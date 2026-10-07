// Package libcore — bepass native protocol bindings.
//
// bepass (github.com/bepass-org/bepass) is a TLS ClientHello-fragmentation
// DPI-bypass engine. It is compiled INTO this libcore AAR (single Go runtime);
// a separate bepass AAR must never be built alongside it — two Go runtimes
// collide on the JNI go.Seq namespace and the VPN will not start.
//
// Architecture when a bepass profile is active (sing-box is NOT started):
//
//	Kotlin (VpnService TUN, fd) -> BepassStartTun -> tun2socks LWIP pump
//	                            -> SOCKS5 127.0.0.1:10821 -> BepassStartClient
//	                            -> fragmented TLS dials (socket-protected)
//
// Socket protection: bepass's dialer (dialer/tcp.go TCPDial) routes every
// outbound TCP connection through protect.NewClientDialer() when
// EnableLowLevelSockets is true on android. protect/protect_linux.go (which
// IS compiled for android — Go satisfies the linux build tag on android)
// overrides softwind's netproxy.SoMark/SoMarkControl to pass the socket fd
// over a Unix-domain socket at the relative path "protect_path" instead of
// using SO_MARK. libcore's InitCore chdir's into <cache>/../no_backup, so
// that relative path resolves to the exact socket libcore's own protect
// server listens on (protect.go, started via acquireProtect below), whose
// callback ends in VpnService.protect(fd) on the Kotlin side.
// No bepass fork and no custom dialer hook are needed — the stock bepass
// protect path plugs straight into libcore's existing one.
//
// Caveats (upstream bepass behavior, not worked around here):
//   - server.Run reads the GLOBAL config.G; bepass's own mobile StartClient
//     unmarshals JSON into a throwaway local, silently discarding it. We
//     populate config.G explicitly in BepassStartClient.
//   - BepassStartClient BLOCKS (socks5 ListenAndServe); call from a worker thread.
//   - In fragment mode (WorkerEnabled=false) bepass registers no SOCKS5 UDP
//     ASSOCIATE handler; the default handler dials UDP with plain net.Dial —
//     unprotected and unfragmented. UDP through the bepass core is therefore
//     not DPI-bypassed in this mode (upstream limitation).
//   - The DNSCrypt branch (RemoteDNSAddr not starting with https://) also
//     dials unprotected; the default config uses DoH (https://) to avoid it.
package libcore

import (
	"encoding/json"
	"log"
	"net"
	"sync"

	bepassmobile "github.com/bepass-org/bepass/cmd/mobile"
	bepassconfig "github.com/bepass-org/bepass/config"
	bepassresolve "github.com/bepass-org/bepass/resolve"
	bepassserver "github.com/bepass-org/bepass/server"
)

// bepassDefaultSocks is the loopback SOCKS5 the bepass core listens on and
// the address Kotlin passes to BepassStartTun.
const bepassDefaultSocks = "127.0.0.1:10821"

var (
	bepassClientMu      sync.Mutex
	bepassClientRunning bool
	bepassTunMu         sync.Mutex
	bepassTunRunning    bool
)

// BepassDefaultConfig returns bepass's stock defaults (from its config.json)
// adapted for Android, as JSON. Kotlin starts from this and overrides fields
// per profile before calling BepassStartClient.
//
// Differences from upstream config.json, all deliberate:
//   - BindAddress "127.0.0.1:10821" (upstream "0.0.0.0:8085"): loopback only.
//   - EnableLowLevelSockets true (upstream false): REQUIRED on Android so
//     outbound sockets are passed through protect_path and bypass the TUN.
//   - WorkerEnabled false (upstream true with a placeholder worker URL):
//     direct TLS-fragment mode; worker mode needs a real WorkerAddress.
func BepassDefaultConfig() string {
	cfg := bepassconfig.Config{
		TLSHeaderLength:        5,
		TLSPaddingEnabled:      false,
		TLSPaddingSize:         [2]int{40, 80},
		DnsCacheTTL:            3000000,
		DnsRequestTimeout:      10,
		RemoteDNSAddr:          "https://yarp.lefolgoc.net/dns-query",
		BindAddress:            bepassDefaultSocks,
		ChunksLengthBeforeSni:  [2]int{2000, 2000},
		SniChunksLength:        [2]int{5, 10},
		ChunksLengthAfterSni:   [2]int{2000, 2000},
		DelayBetweenChunks:     [2]int{10, 20},
		WorkerAddress:          "",
		WorkerIPPortAddress:    "",
		WorkerEnabled:          false,
		WorkerDNSOnly:          false,
		EnableLowLevelSockets:  true,
		EnableDNSFragmentation: false,
		Hosts: []bepassresolve.Hosts{
			{Domain: "yarp.lefolgoc.net", IP: "5.39.88.20"},
		},
		UDPBindAddress:     "0.0.0.0",
		UDPReadTimeout:     120,
		UDPWriteTimeout:    120,
		UDPLinkIdleTimeout: 120,
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Println("bepass: marshal default config:", err)
		return "{}"
	}
	return string(out)
}

// BepassStartClient parses configJSON into bepass's global config and runs the
// bepass core: a SOCKS5 (+HTTP) listener on BindAddress (default
// 127.0.0.1:10821) whose outbound TLS connections are fragmented for DPI
// bypass.
//
// THIS CALL BLOCKS until BepassStopClient is called or the listener fails —
// Kotlin must invoke it on a background thread. Returns false if the config
// JSON is invalid or the core exits with an error.
func BepassStartClient(configJSON string) bool {
	var cfg bepassconfig.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		log.Println("bepass: invalid config JSON:", err)
		return false
	}
	// NOTE: bepass's server package reads the GLOBAL config.G, and bepass's
	// own mobile StartClient unmarshals into a throwaway local — so the JSON
	// would be silently ignored. Populate the global explicitly.
	*bepassconfig.G = cfg

	// Keep libcore's protect server up for the client's whole lifetime so
	// bepass's protect_path fd-passing has a listener (refcounted; safe to
	// nest with sing-box's own usage).
	acquireProtect()
	defer releaseProtect()

	bepassClientMu.Lock()
	bepassClientRunning = true
	bepassClientMu.Unlock()
	defer func() {
		bepassClientMu.Lock()
		bepassClientRunning = false
		bepassClientMu.Unlock()
	}()

	if err := bepassserver.Run(false); err != nil {
		log.Println("bepass: core exited with error:", err)
		return false
	}
	return true
}

// BepassStopClient shuts down the bepass core started by BepassStartClient,
// unblocking it. Safe to call when the client is not running.
func BepassStopClient() (ok bool) {
	bepassClientMu.Lock()
	running := bepassClientRunning
	bepassClientMu.Unlock()
	if !running {
		return true
	}
	defer func() {
		if r := recover(); r != nil {
			log.Println("bepass: stop client recovered from panic:", r)
			ok = false
		}
	}()
	if err := bepassserver.ShutDown(); err != nil {
		log.Println("bepass: stop client:", err)
		return false
	}
	return true
}

// BepassStartTun starts bepass's tun2socks LWIP pump on an already-opened
// Android TUN fd, forwarding device traffic through the SOCKS5 at socksAddr
// (normally "127.0.0.1:10821", served by BepassStartClient). It returns
// immediately; the pump runs in the background. IPv6 is disabled (the app
// targets IPv4-only networks). Returns false on invalid arguments.
//
// Ownership note: the pump closes the fd on BepassStopTun — Kotlin must pass
// a detached fd (ParcelFileDescriptor.detachFd()) and must not close it
// again itself.
func BepassStartTun(tunFd int, mtu int, socksAddr string) bool {
	if tunFd < 0 {
		log.Println("bepass: invalid tun fd")
		return false
	}
	// bepass's mobile Start calls log.Fatalf (kills the process) on a bad
	// proxy address — validate here and fail gracefully instead.
	if _, err := net.ResolveTCPAddr("tcp", socksAddr); err != nil {
		log.Println("bepass: invalid socks address:", err)
		return false
	}
	if mtu <= 0 {
		mtu = 1500
	}
	// FakeIPRange stays empty: bepass Fatalf's on an unparsable CIDR, and we
	// do not use its fake-DNS path.
	if rc := bepassmobile.Start(&bepassmobile.StartOptions{
		TunFd:        tunFd,
		Socks5Server: socksAddr,
		FakeIPRange:  "",
		MTU:          mtu,
		EnableIPv6:   false,
		AllowLan:     false,
	}); rc != 0 {
		log.Println("bepass: tun pump failed to start")
		return false
	}
	bepassTunMu.Lock()
	bepassTunRunning = true
	bepassTunMu.Unlock()
	return true
}

// BepassStopTun stops the tun2socks pump started by BepassStartTun and closes
// the TUN fd on the Go side (see ownership note on BepassStartTun). Safe to
// call when the pump is not running.
func BepassStopTun() {
	bepassTunMu.Lock()
	running := bepassTunRunning
	bepassTunRunning = false
	bepassTunMu.Unlock()
	if !running {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Println("bepass: stop tun recovered from panic:", r)
		}
	}()
	bepassmobile.Stop()
}
