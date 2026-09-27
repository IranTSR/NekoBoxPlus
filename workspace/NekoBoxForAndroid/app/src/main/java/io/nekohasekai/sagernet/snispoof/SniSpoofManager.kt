package io.nekohasekai.sagernet.snispoof

import android.content.Context
import android.os.Build
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.isIpAddress
import io.nekohasekai.sagernet.ktx.isIpAddressV6
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest

/**
 * Root sidecar manager for SNI spoofing, mirroring the PattNG integration.
 *
 * The bundled arm64 `sni_spoofing_arm64` binary is extracted to the app's private dir,
 * SHA-256 verified, then launched detached as root (`su -c "nohup ... &"`). It listens on
 * a loopback port and forwards to the real server with a fake SNI, so on-path DPI sees
 * the decoy while the real TLS session (SNI/credentials) is untouched.
 *
 * Lifecycle: [startForRun] runs before the core config is built (the config rewrite in
 * ConfigBuilder reads [loopbackPortFor]); [stop] kills the daemon on every stop path.
 *
 * Blocking calls: start/stop perform bounded blocking work (root probe, daemon spawn,
 * listen poll) and must run on Dispatchers.IO.
 */
object SniSpoofManager {

    const val TAG = "SniSpoof"

    /** Bundled asset name (arm64 only). */
    const val ASSET_ARM64 = "sni_spoofing_arm64"

    /** SHA-256 of the bundled asset; a mismatch forces re-extraction. */
    const val ASSET_SHA256 = "cc7fbcd57afaacbc18bf016421981c96f7e18ddae229fc236c167ca847c4e1b7"

    const val RUNTIME_DIR = "sni_spoof"
    const val BIN_NAME = "sni-spoofing"
    const val PID_FILE = "sni-spoofing.pid"

    const val DEFAULT_PORT = 40443
    const val DEFAULT_UTLS = "chrome"
    const val DEFAULT_INJECTOR = "active"

    /** User-facing failure; the message is shown as-is. */
    class SniSpoofException(message: String) : Exception(message)

    data class Session(val profileId: Long, val port: Int, val pid: Int)

    @Volatile
    private var session: Session? = null

    /** Per-profile SNI spoofing knobs, extracted from whichever bean type backs the profile. */
    private data class SniSpoofSettings(
        val enabled: Boolean,
        val connect: String?,
        val fakeSni: String?,
        val utls: String?,
        val injector: String?,
        val serverAddress: String?,
        val serverPort: Int?,
    )

    private fun ProxyEntity.sniSpoofSettings(): SniSpoofSettings? {
        return when (val bean = requireBean()) {
            is StandardV2RayBean -> SniSpoofSettings(
                bean.sniSpoofEnabled == true,
                bean.sniSpoofConnect,
                bean.sniSpoofFakeSni,
                bean.sniSpoofUtls,
                bean.sniSpoofInjector,
                bean.serverAddress,
                bean.serverPort,
            )
            is ShadowsocksBean -> SniSpoofSettings(
                bean.sniSpoofEnabled == true,
                bean.sniSpoofConnect,
                bean.sniSpoofFakeSni,
                bean.sniSpoofUtls,
                bean.sniSpoofInjector,
                bean.serverAddress,
                bean.serverPort,
            )
            is SOCKSBean -> SniSpoofSettings(
                bean.sniSpoofEnabled == true,
                bean.sniSpoofConnect,
                bean.sniSpoofFakeSni,
                bean.sniSpoofUtls,
                bean.sniSpoofInjector,
                bean.serverAddress,
                bean.serverPort,
            )
            else -> null
        }
    }

    /** TCP protocols the sidecar can front. It is a TCP proxy: UDP protocols are out. */
    fun isSupportedType(type: Int): Boolean = type in setOf(
        ProxyEntity.TYPE_VMESS, // covers VLESS (VMessBean with alterId == -1)
        ProxyEntity.TYPE_TROJAN,
        ProxyEntity.TYPE_SS,
        ProxyEntity.TYPE_SOCKS,
        ProxyEntity.TYPE_HTTP,
    )

    fun isEnabledFor(entity: ProxyEntity): Boolean {
        val settings = entity.sniSpoofSettings() ?: return false
        return settings.enabled && isSupportedType(entity.type)
    }

    /**
     * Starts the sidecar for a run, or reuses the live session when the same profile is
     * already served (e.g. a core reload after a network handover).
     *
     * This performs bounded blocking work (one root probe, one daemon spawn, a short
     * listen poll) and must be called before the core config is built.
     *
     * @return the loopback port the core must dial.
     * @throws SniSpoofException with a user-facing message when the sidecar cannot start.
     */
    @Throws(SniSpoofException::class)
    fun startForRun(context: Context, entity: ProxyEntity): Int {
        currentSession().let { current ->
            if (current != null && current.profileId == entity.id && isPidAlive(current.pid)) {
                Logs.i("$TAG: reusing live session on port ${current.port}")
                return current.port
            }
        }
        stop()

        val settings = entity.sniSpoofSettings()
        if (settings == null || !isEnabledFor(entity)) {
            throw SniSpoofException("SNI spoofing is not enabled for this profile")
        }
        if (!isArm64()) throw SniSpoofException("SNI spoofing needs an arm64 device")
        val server = settings.serverAddress.orEmpty()
        val serverPort = settings.serverPort ?: 0
        if (server.isBlank() || serverPort <= 0) {
            throw SniSpoofException("SNI spoofing: the server address is empty")
        }
        if (isIpv6Literal(server)) {
            throw SniSpoofException("SNI spoofing is IPv4-only")
        }
        val target = connectTarget(settings)
        if (!isValidConnectTarget(target)) {
            throw SniSpoofException("Spoof IP:port must look like host:port, e.g. 1.2.3.4:443")
        }
        if (isConnectTargetIp(target) && settings.fakeSni?.trim().isNullOrBlank()) {
            throw SniSpoofException("A decoy SNI is required when the server address is an IP")
        }
        if (!RootManager.isRootAvailable()) {
            throw SniSpoofException("SNI spoofing needs root access")
        }
        val bin = ensureBinary(context) ?: throw SniSpoofException("SNI spoofing: the sidecar binary is missing")
        val port = pickPort()
        val pid = launchDaemon(context, bin, settings, port)
            ?: throw SniSpoofException("SNI spoofing: the sidecar failed to start")
        if (!awaitListening(port, 5_000)) {
            killPid(pid)
            throw SniSpoofException("SNI spoofing: the sidecar did not start listening")
        }
        session = Session(entity.id, port, pid)
        Logs.i("$TAG: sidecar running, pid=$pid port=$port")
        return port
    }

    /**
     * The loopback port the generated core config must dial for [entity], or null when no
     * live session serves exactly this profile. Called from the outbound builder.
     */
    fun loopbackPortFor(entity: ProxyEntity): Int? {
        val s = currentSession() ?: return null
        return if (s.profileId == entity.id) s.port else null
    }

    /**
     * Stops the sidecar. Safe to call repeatedly and with no session.
     *
     * Fast and bounded (SIGTERM + a short wait): this runs on the service's stop path.
     * Anything that survives is reaped from the PID file on the next start.
     */
    fun stop() {
        val s = currentSession()
        session = null
        if (s != null) {
            killPid(s.pid, waitMs = 1_000)
            Logs.i("$TAG: sidecar stopped")
        }
    }

    internal fun currentSession(): Session? = session

    // ---------------------------------------------------------- binary

    private fun isArm64(): Boolean =
        Build.SUPPORTED_ABIS.any { it.equals("arm64-v8a", ignoreCase = true) }

    private fun isIpv6Literal(host: String): Boolean = try {
        host.isIpAddressV6()
    } catch (_: Exception) {
        host.contains(":")
    }

    /**
     * Extracts the bundled arm64 binary to the app's private dir (once, verified by SHA-256)
     * and makes it executable.
     */
    private fun ensureBinary(context: Context): File? {
        return try {
            val dir = File(context.filesDir, RUNTIME_DIR).apply { mkdirs() }
            val bin = File(dir, BIN_NAME)
            if (!bin.isFile || sha256Hex(bin) != ASSET_SHA256) {
                context.assets.open(ASSET_ARM64).use { input ->
                    bin.outputStream().use { output -> input.copyTo(output) }
                }
                Logs.i("$TAG: sidecar binary extracted")
            }
            bin.setExecutable(true, true)
            if (bin.canExecute()) bin else null
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            Logs.e("$TAG: binary setup failed", e)
            null
        }
    }

    private fun sha256Hex(file: File): String? {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(8192)
                var n = input.read(buf)
                while (n > 0) {
                    digest.update(buf, 0, n)
                    n = input.read(buf)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Logs.w("$TAG: sha256 failed: ${e.message}")
            null
        }
    }

    // ---------------------------------------------------------- daemon

    private fun pickPort(): Int =
        if (isPortFree(DEFAULT_PORT)) DEFAULT_PORT
        else findRandomFreePort()

    private fun isPortFree(port: Int): Boolean {
        return try {
            Socket(LOCALHOST, port).close()
            false
        } catch (_: Exception) {
            true
        }
    }

    private fun findRandomFreePort(): Int {
        return try {
            ServerSocket(0).use { it.localPort }
        } catch (_: Exception) {
            DEFAULT_PORT
        }
    }

    /**
     * Resolves the sidecar's -connect upstream.
     *
     * The optional per-profile override (IP:port or host:port) wins; otherwise the
     * profile's own server address and port are used, matching the CLI's `-connect`.
     */
    internal fun connectTarget(settings: SniSpoofSettings): String {
        val override = settings.connect?.trim().orEmpty()
        if (override.isNotEmpty()) return override
        return "${settings.serverAddress}:${settings.serverPort}"
    }

    /**
     * True when the -connect target's host part is a literal IP address.
     * The sidecar then requires an explicit -fake-sni decoy.
     */
    internal fun isConnectTargetIp(target: String): Boolean {
        return isIpLiteral(connectHost(target))
    }

    private fun isIpLiteral(host: String): Boolean = try {
        host.isIpAddress()
    } catch (_: Exception) {
        host.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+\$"))
    }

    /**
     * True when the target looks like host:port with a valid port number.
     * IPv6 hosts must use brackets, e.g. [::1]:443.
     */
    internal fun isValidConnectTarget(target: String): Boolean {
        val t = target.trim()
        if (t.isEmpty()) return false
        val host: String
        val portStr: String
        if (t.startsWith("[")) {
            host = t.substringAfter("[").substringBefore("]")
            val rest = t.substringAfter("]", "")
            if (!rest.startsWith(":")) return false
            portStr = rest.drop(1)
        } else {
            val idx = t.lastIndexOf(":")
            if (idx <= 0) return false
            host = t.substring(0, idx)
            portStr = t.substring(idx + 1)
        }
        if (host.isEmpty() || portStr.isEmpty()) return false
        val port = portStr.toIntOrNull() ?: return false
        return port in 1..65535
    }

    private fun connectHost(target: String): String {
        val t = target.trim()
        return if (t.startsWith("[")) t.substringAfter("[").substringBefore("]")
        else t.substringBefore(":")
    }

    /**
     * Builds the exact argv for the sidecar.
     */
    internal fun buildArgs(settings: SniSpoofSettings, port: Int): List<String> {
        val args = mutableListOf(
            "-listen", "$LOCALHOST:$port",
            "-connect", connectTarget(settings),
        )
        settings.fakeSni?.takeIf { it.isNotBlank() }?.let {
            args += listOf("-fake-sni", it.trim())
        }
        args += listOf("-utls", normalizeUtls(settings.utls))
        args += listOf("-injector", normalizeInjector(settings.injector))
        return args
    }

    internal fun normalizeUtls(value: String?): String {
        val v = value?.trim().orEmpty()
        return if (v.isEmpty()) DEFAULT_UTLS else v
    }

    internal fun normalizeInjector(value: String?): String {
        return when (value?.trim()?.lowercase()) {
            "passive" -> "passive"
            else -> DEFAULT_INJECTOR
        }
    }

    private fun shQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /**
     * Spawns the daemon detached via su (nohup + &), records its PID, and returns it.
     */
    private fun launchDaemon(context: Context, bin: File, settings: SniSpoofSettings, port: Int): Int? {
        return try {
            val dir = File(context.filesDir, RUNTIME_DIR)
            val pidFile = File(dir, PID_FILE)
            // A previous process death can orphan the daemon (it is detached via nohup); reap it
            // before spawning so its port and netfilter rules never leak into this run.
            reapStalePidFile(pidFile, BIN_NAME)
            if (pidFile.exists()) pidFile.delete()
            // A previous run can orphan the daemon outside the PID file's reach
            // (app process death, a failed stop). Sweep by exact process name so a
            // stale sidecar never survives next to the new one; pkill exits 1 when
            // nothing matches, which is fine.
            RootProcessRunner.run(
                listOf("su", "-c", "pkill -x ${shQuote(BIN_NAME)}"),
                5_000
            )

            val argv = buildArgs(settings, port).joinToString(" ") { shQuote(it) }
            val script = buildString {
                appendLine("BIN=${shQuote(bin.absolutePath)}")
                appendLine("PIDFILE=${shQuote(pidFile.absolutePath)}")
                appendLine("nohup \"\$BIN\" $argv >/dev/null 2>&1 &")
                appendLine("echo \$! > \"\$PIDFILE\"")
            }
            val scriptFile = File(dir, "start_sni_spoof.sh").apply {
                writeText(script)
                setExecutable(true, true)
            }
            val result = RootProcessRunner.run(
                listOf("su", "-c", "sh ${shQuote(scriptFile.absolutePath)}"),
                15_000
            )
            if (result.code != 0) {
                Logs.e("$TAG: daemon spawn failed: ${result.output.trim()}")
                return null
            }
            val pid = pidFile.takeIf { it.isFile }?.readText()?.trim()?.toIntOrNull()
            if (pid == null || pid <= 0) {
                Logs.e("$TAG: no PID recorded")
                return null
            }
            pid
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            Logs.e("$TAG: daemon spawn threw", e)
            null
        }
    }

    private fun awaitListening(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        while (System.nanoTime() < deadline) {
            try {
                Socket(LOCALHOST, port).close()
                return true
            } catch (_: Exception) {
                // not up yet
            }
            try {
                Thread.sleep(200)
            } catch (ie: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
        return false
    }

    private fun isPidAlive(pid: Int): Boolean {
        val r = RootProcessRunner.run(listOf("su", "-c", "kill -0 $pid"), 5_000)
        return r.code == 0
    }

    /**
     * SIGTERM first: the sidecar removes its iptables/nfqueue rules on graceful shutdown.
     * SIGKILL only when it refuses to die within [waitMs] (its netfilter rules may leak then,
     * and the next start reaps the survivor from the PID file).
     */
    private fun killPid(pid: Int, waitMs: Long = 3_000) {
        try {
            RootProcessRunner.run(listOf("su", "-c", "kill $pid"), 5_000)
            val deadline = System.nanoTime() + waitMs * 1_000_000L
            while (System.nanoTime() < deadline) {
                if (!isPidAlive(pid)) return
                try {
                    Thread.sleep(200)
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
            if (isPidAlive(pid)) {
                Logs.w("$TAG: pid $pid ignored SIGTERM, SIGKILLing")
                RootProcessRunner.run(listOf("su", "-c", "kill -9 $pid"), 5_000)
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            Logs.e("$TAG: kill failed", e)
        }
    }

    /**
     * Kills a daemon orphaned by a previous process death. The PID is only trusted when
     * /proc/<pid>/cmdline still names our binary, so a recycled PID can never hit an
     * unrelated process.
     */
    private fun reapStalePidFile(pidFile: File, binName: String) {
        val pid = pidFile.takeIf { it.isFile }?.readText()?.trim()?.toIntOrNull() ?: return
        if (pid <= 0 || !isPidAlive(pid)) return
        val cmdline = RootProcessRunner.run(
            listOf("su", "-c", "cat /proc/$pid/cmdline"), 5_000
        ).output
        if (!cmdline.contains(binName)) {
            Logs.w("$TAG: pid file holds foreign pid $pid, ignoring")
            return
        }
        Logs.w("$TAG: reaping orphaned sidecar pid $pid")
        killPid(pid)
    }
}
