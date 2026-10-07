package io.nekohasekai.sagernet.bg

import android.content.Context
import android.os.ParcelFileDescriptor
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.fmt.bepass.BepassBean
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.readableMessage
import libcore.Libcore
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Native bepass engine instance.
 *
 * Owns the Android TUN directly; sing-box is never started while a bepass
 * profile is active. The blocking libcore calls run on a dedicated worker
 * thread so [launch] returns promptly.
 *
 * Contract assumed from the agreed libcore API (note: gobind lowercases the
 * first letter of Go function names when generating Java, so the Kotlin
 * call sites use lowercase-initial names):
 * - [Libcore.bepassStartClient] blocks until the client is up and ready
 *   (or fails), returning false on failure.
 * - [Libcore.bepassStartTun] attaches the TUN fd and pumps packets until
 *   [Libcore.bepassStopTun] is called.
 */
class BepassInstance(
    val profile: ProxyEntity,
    private val service: BaseService.Interface,
) : AbstractInstance {

    companion object {
        const val TUN_MTU = 1500

        /** Local SOCKS endpoint the bepass client listens on; the TUN dials it. */
        const val LOCAL_SOCKS = "127.0.0.1:10821"
    }

    private val bean: BepassBean = (profile.requireBean() as BepassBean).apply {
        initializeDefaultValues()
    }

    private val tornDown = AtomicBoolean(false)

    @Volatile
    private var tun: ParcelFileDescriptor? = null

    @Volatile
    private var tunFd: Int = -1

    /**
     * True once the fd was handed to the Go pump: Go's BepassStopTun closes
     * it, so Kotlin must not close it again (double-close could close an
     * unrelated recycled fd).
     */
    @Volatile
    private var tunOwnedByGo = false

    @Volatile
    private var worker: Thread? = null

    override fun launch() {
        val vpn = service as? VpnService
            ?: error("bepass requires VPN service mode")
        val pfd = vpn.startBepassTun()
        tun = pfd
        // Hand the raw fd to the Go side; we re-adopt it to close on teardown.
        tunFd = pfd.detachFd()
        Logs.d("bepass TUN fd=$tunFd")
        val configJson = buildConfigJson()
        worker = thread(name = "bepass-client", isDaemon = true) {
            runBepass(configJson)
        }
    }

    private fun runBepass(configJson: String) {
        try {
            if (!Libcore.bepassStartClient(configJson)) {
                fail(R.string.bepass_start_failed)
                return
            }
            Logs.d("bepass client started, attaching TUN")
            if (!Libcore.bepassStartTun(tunFd.toLong(), TUN_MTU.toLong(), LOCAL_SOCKS)) {
                fail(R.string.bepass_start_failed)
                return
            }
            // Pump is running and Go owns the fd from here on.
            tunOwnedByGo = true
            // BepassStartTun returns once BepassStopTun() is called: normal shutdown.
            Logs.d("bepass TUN loop ended")
        } catch (e: Throwable) {
            if (!tornDown.get()) {
                Logs.w(e)
                fail(e.readableMessage)
            }
        }
    }

    /**
     * Builds the bepass config JSON: starts from the Go side's defaults and
     * overrides every known key with the profile's settings. Key names follow
     * the documented bepass config format (PascalCase).
     */
    private fun buildConfigJson(): String {
        val root = try {
            JSONObject(Libcore.bepassDefaultConfig())
        } catch (e: Exception) {
            Logs.w(e)
            JSONObject()
        }
        root.put("TLSHeaderLength", bean.tlsHeaderLength)
        root.put("TLSPaddingEnabled", bean.tlsPaddingEnabled)
        root.put(
            "TLSPaddingSize",
            JSONArray().put(bean.tlsPaddingSizeMin).put(bean.tlsPaddingSizeMax),
        )
        root.put(
            "ChunksLengthBeforeSni",
            JSONArray().put(bean.chunksBeforeSniMin).put(bean.chunksBeforeSniMax),
        )
        root.put(
            "SniChunksLength",
            JSONArray().put(bean.sniChunksMin).put(bean.sniChunksMax),
        )
        root.put(
            "ChunksLengthAfterSni",
            JSONArray().put(bean.chunksAfterSniMin).put(bean.chunksAfterSniMax),
        )
        root.put(
            "DelayBetweenChunks",
            JSONArray().put(bean.delayBetweenChunksMin).put(bean.delayBetweenChunksMax),
        )
        root.put("DnsCacheTTL", bean.dnsCacheTtl)
        root.put("DnsRequestTimeout", bean.dnsRequestTimeout)
        root.put("RemoteDNSAddr", bean.remoteDnsAddr)
        root.put("EnableDNSFragmentation", bean.enableDnsFragmentation)
        root.put("EnableLowLevelSockets", bean.enableLowLevelSockets)
        root.put("WorkerEnabled", bean.workerEnabled)
        root.put("WorkerAddress", bean.workerAddress)
        root.put("WorkerIPPortAddress", bean.workerIpPortAddress)
        root.put("WorkerDNSOnly", bean.workerDnsOnly)
        root.put("BindAddress", LOCAL_SOCKS)
        return root.toString()
    }

    private fun fail(messageRes: Int) {
        val message = (service as? Context)?.getString(messageRes) ?: "bepass"
        fail(message)
    }

    private fun fail(message: String) {
        if (!tornDown.compareAndSet(false, true)) return
        Logs.w("bepass engine failed: $message")
        runCatching { Libcore.bepassStopTun() }.onFailure { Logs.w(it) }
        runCatching { Libcore.bepassStopClient() }.onFailure { Logs.w(it) }
        closeTunFd()
        runCatching {
            service.stopRunner(false, message)
        }.onFailure { Logs.w(it) }
    }

    private fun closeTunFd() {
        val fd = tunFd
        tunFd = -1
        tun = null
        // Skip when Go owns the fd: BepassStopTun already closed it.
        if (fd >= 0 && !tunOwnedByGo) {
            runCatching {
                ParcelFileDescriptor.adoptFd(fd).close()
            }.onFailure { Logs.w(it) }
        }
    }

    override fun close() {
        if (!tornDown.compareAndSet(false, true)) return
        runCatching { Libcore.bepassStopTun() }.onFailure { Logs.w(it) }
        runCatching { Libcore.bepassStopClient() }.onFailure { Logs.w(it) }
        try {
            worker?.join(5_000L)
        } catch (e: InterruptedException) {
            Logs.w(e)
        } finally {
            worker = null
        }
        closeTunFd()
        Logs.d("bepass instance closed")
    }
}
