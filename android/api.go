//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

/*
#cgo LDFLAGS: -llog
#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

// Implemented in jni.c. c_has_vpn_service/c_protect_socket are called from Go;
// wgNotifySocketProtected is implemented in Go and called from jni.c.
extern int c_has_vpn_service(void);
extern int c_protect_socket(int fd);
extern void wgNotifySocketProtected(int handle);
*/
import "C"

import (
	"bufio"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/proxy"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type AndroidLogger struct {
	level C.int
	tag   string
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	cTag := C.CString(l.tag)
	cMsg := C.CString(msg)
	C.__android_log_write(l.level, cTag, cMsg)
	C.free(unsafe.Pointer(cTag))
	C.free(unsafe.Pointer(cMsg))
}

type TunnelHandle struct {
	device *device.Device
	bind   *conn.EvasionBind
}

type Socks5Handle struct {
	server *proxy.SOCKS5Server
	device *device.Device
	bind   *conn.EvasionBind
}

var (
	tunnelMu         sync.Mutex
	tunnelHandles    = make(map[int32]TunnelHandle)
	nextTunnelHandle int32

	socksMu         sync.Mutex
	socksHandles    = make(map[int32]*Socks5Handle)
	nextSocksHandle int32
)

func init() {
	// Wire VpnService.protect(fd) into the socket creation path. This runs
	// before bind() and before the first datagram is sent, eliminating the
	// routing loop caused by the 0.0.0.0/0 -> tun0 route.
	conn.SetSocketProtector(func(fd int) error {
		if C.c_protect_socket(C.int(fd)) != 0 {
			return fmt.Errorf("VpnService.protect(%d) failed", fd)
		}
		return nil
	})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for range signals {
			n := runtime.Stack(buf, true)
			if n == len(buf) {
				n--
			}
			buf[n] = 0
			cTag := C.CString("TravonetWG/Stacktrace")
			cMsg := C.CString(string(buf[:n]))
			C.__android_log_write(C.ANDROID_LOG_ERROR, cTag, cMsg)
			C.free(unsafe.Pointer(cTag))
			C.free(unsafe.Pointer(cMsg))
		}
	}()
}

// amneziaWGKeys are UAPI keys produced by AmneziaWG configs that the vanilla
// WireGuard UAPI parser rejects. They must be dropped (or mapped) before
// device.IpcSet sees them.
var amneziaWGKeys = map[string]bool{
	"jc": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

// parseSettings parses incoming configuration (either standard WG .conf or UAPI)
// and extracts evasion options without breaking the WireGuard UAPI parser.
func parseSettings(settings string, logger *device.Logger) (cleanUapi string, evasionCfg conn.EvasionConfig, pka int, endpoint string, mtu int, err error) {
	evasionCfg = conn.DefaultEvasionConfig()
	evasionCfg.LogFunc = logger.Verbosef
	mtu = 1280

	lower := strings.ToLower(settings)
	if strings.Contains(lower, "[interface]") {
		parsed, parseErr := conf.ParseConfigString(settings)
		if parseErr != nil {
			return "", evasionCfg, 0, "", 0, fmt.Errorf("failed to parse WireGuard .conf: %w", parseErr)
		}
		if parsed.Strategy != "" {
			evasionCfg.Strategy = parsed.Strategy
		}
		if parsed.FakeTTL != 0 {
			evasionCfg.FakeTTL = parsed.FakeTTL
		}
		if parsed.NormalTTL > 0 {
			evasionCfg.NormalTTL = parsed.NormalTTL
		}
		if parsed.PreJunkSize > 0 {
			evasionCfg.PreJunkSize = parsed.PreJunkSize
		}
		if parsed.MTU > 0 {
			mtu = parsed.MTU
		}

		uapi, genErr := parsed.ToUAPI()
		if genErr != nil {
			return "", evasionCfg, 0, "", 0, fmt.Errorf("failed to generate UAPI: %w", genErr)
		}
		return uapi, evasionCfg, parsed.PersistentKeepalive, parsed.Endpoint, mtu, nil
	}

	// UAPI format - filter custom evasion parameters and AmneziaWG keys.
	var uapiLines []string
	inPeerSection := false
	keepaliveSeen := false
	scanner := bufio.NewScanner(strings.NewReader(settings))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		if amneziaWGKeys[key] {
			continue
		}

		switch key {
		case "strategy":
			evasionCfg.Strategy = val
			continue
		case "fake_ttl", "fakettl":
			if strings.EqualFold(val, "auto") {
				evasionCfg.FakeTTL = -1
			} else if v, convErr := strconv.Atoi(val); convErr == nil {
				evasionCfg.FakeTTL = v
			}
			continue
		case "normal_ttl", "normalttl":
			if v, convErr := strconv.Atoi(val); convErr == nil && v > 0 {
				evasionCfg.NormalTTL = v
			}
			continue
		case "pre_junk", "prejunk", "prejunksize":
			if v, convErr := strconv.Atoi(val); convErr == nil {
				evasionCfg.PreJunkSize = v
			}
			continue
		case "jmin":
			// AmneziaWG: jmin maps to PreJunkSize when PreJunk is unset.
			if v, convErr := strconv.Atoi(val); convErr == nil && evasionCfg.PreJunkSize == 0 {
				evasionCfg.PreJunkSize = v
			}
			continue
		case "no_evasion", "disable_evasion":
			if strings.EqualFold(val, "true") || val == "1" {
				evasionCfg.Enabled = false
			}
			continue
		case "mtu":
			if v, convErr := strconv.Atoi(val); convErr == nil && v > 0 {
				mtu = v
			}
			continue
		case "endpoint":
			endpoint = val
			uapiLines = append(uapiLines, "endpoint="+conf.ResolveEndpointHostPort(val))
			continue
		case "public_key":
			inPeerSection = true
		case "persistent_keepalive_interval", "persistentkeepalive":
			if v, convErr := strconv.Atoi(val); convErr == nil {
				pka = v
				keepaliveSeen = true
			}
			continue
		}

		uapiLines = append(uapiLines, line)
	}

	// Automatic PersistentKeepalive optimization for Android mobile networks.
	if inPeerSection {
		if conf.IsPort500Endpoint(endpoint) {
			if pka == 0 || pka > 10 {
				pka = 5
			}
		} else if pka == 0 {
			pka = 15
		}
		if pka > 0 {
			uapiLines = append(uapiLines, fmt.Sprintf("persistent_keepalive_interval=%d", pka))
		}
	} else if !keepaliveSeen {
		pka = 0
	}

	cleanUapi = strings.Join(uapiLines, "\n") + "\n"
	return cleanUapi, evasionCfg, pka, endpoint, mtu, nil
}

// resolveAutoFakeTTL runs the kernel-assisted TTL probe when FakeTTL=auto.
func resolveAutoFakeTTL(evasionCfg *conn.EvasionConfig, endpoint string, logger *device.Logger) {
	if evasionCfg.FakeTTL >= 0 || endpoint == "" {
		return
	}
	hops, recommended, probeErr := conn.MeasureTargetTTL(endpoint)
	if recommended <= 0 {
		recommended = 5
	}
	evasionCfg.FakeTTL = recommended
	if probeErr != nil {
		logger.Verbosef("AutoTTL probe failed (%v), using safe FakeTTL=%d", probeErr, recommended)
	} else {
		logger.Verbosef("AutoTTL: measured %d hops, using FakeTTL=%d", hops, recommended)
	}
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string) int32 {
	tag := "TravonetWG/" + interfaceName
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, pka, endpoint, mtu, err := parseSettings(settings, logger)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}
	resolveAutoFakeTTL(&evasionCfg, endpoint, logger)

	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	if actualMTU, mtuErr := tunDev.MTU(); mtuErr == nil && actualMTU > 0 {
		mtu = actualMTU
	}

	logger.Verbosef("Attaching to interface %v (strategy=%s, fake_ttl=%d, keepalive=%ds, mtu=%d)",
		name, evasionCfg.Strategy, evasionCfg.FakeTTL, pka, mtu)

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)
	dev.SetMTU(mtu)

	// Legacy embedders (unmodified WireGuard/AmneziaWG clients) call
	// wgGetSocketV4() + vpnService.protect(fd) only after wgTurnOn returns.
	// Arm the barrier so the first handshake cannot race the routing loop.
	if C.c_has_vpn_service() == 0 {
		evasionBind.RequireLegacySocketProtect()
	}

	// Bring the device up first: this opens and protects the UDP sockets before
	// any peer (and therefore any handshake) exists.
	if err = dev.Up(); err != nil {
		logger.Errorf("Unable to bring up device: %v", err)
		dev.Close()
		return -1
	}

	if err = dev.IpcSet(cleanUapi); err != nil {
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	logger.Verbosef("TravonetWG device started")

	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	for attempts := 0; attempts < math.MaxInt32; attempts++ {
		nextTunnelHandle++
		if nextTunnelHandle <= 0 {
			nextTunnelHandle = 1
		}
		if _, exists := tunnelHandles[nextTunnelHandle]; !exists {
			tunnelHandles[nextTunnelHandle] = TunnelHandle{device: dev, bind: evasionBind}
			return nextTunnelHandle
		}
	}
	logger.Errorf("Unable to find empty handle")
	dev.Close()
	return -1
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		tunnelMu.Unlock()
		return
	}
	delete(tunnelHandles, tunnelHandle)
	tunnelMu.Unlock()

	handle.device.Close()
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	// Give the Java thread time to finish vpnService.protect(fd), then release
	// the legacy protection barrier so a waiting handshake can proceed.
	if handle.bind != nil {
		go func() {
			time.Sleep(50 * time.Millisecond)
			handle.bind.NotifySocketProtected()
		}()
	}
	return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	if handle.bind != nil {
		go func() {
			time.Sleep(50 * time.Millisecond)
			handle.bind.NotifySocketProtected()
		}()
	}
	return int32(fd)
}

//export wgNotifySocketProtected
func wgNotifySocketProtected(tunnelHandle int32) {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if ok && handle.bind != nil {
		handle.bind.NotifySocketProtected()
	}
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgVersion
func wgVersion() *C.char {
	return C.CString("TravonetWG-1.11 (wireguard-go)")
}

//export wgStartSocks5
func wgStartSocks5(listenAddr string, settings string) int32 {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	tag := "TravonetWG/SOCKS5"
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, pka, endpoint, mtu, err := parseSettings(settings, logger)
	if err != nil {
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}
	resolveAutoFakeTTL(&evasionCfg, endpoint, logger)

	var localIPs []netip.Addr
	var dnsIPs []netip.Addr
	var socksAuth string
	if parsed, parseErr := conf.ParseConfigString(settings); parseErr == nil {
		if parsed.SocksAuth != "" {
			socksAuth = parsed.SocksAuth
		}
		for _, a := range parsed.Addresses {
			addrStr := a
			if idx := strings.Index(addrStr, "/"); idx > 0 {
				addrStr = addrStr[:idx]
			}
			if ip, ipErr := netip.ParseAddr(addrStr); ipErr == nil {
				localIPs = append(localIPs, ip)
			}
		}
		for _, d := range parsed.DNS {
			if ip, ipErr := netip.ParseAddr(d); ipErr == nil {
				dnsIPs = append(dnsIPs, ip)
			}
		}
		if parsed.MTU > 0 {
			mtu = parsed.MTU
		}
	}
	if len(localIPs) == 0 {
		localIPs = []netip.Addr{netip.MustParseAddr("172.16.0.2")}
	}
	if len(dnsIPs) == 0 {
		dnsIPs = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
	if err != nil {
		logger.Errorf("CreateNetTUN: %v", err)
		return -1
	}

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)
	dev.SetMTU(mtu)

	// Open sockets before configuring peers, mirroring the VpnService path.
	if err := dev.Up(); err != nil {
		logger.Errorf("dev.Up: %v", err)
		dev.Close()
		return -1
	}
	if err := dev.IpcSet(cleanUapi); err != nil {
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	socksServer := proxy.NewSOCKS5Server(listenAddr, tnet.DialContext)
	socksServer.Debug = true
	if socksAuth != "" {
		if user, pass, ok := strings.Cut(socksAuth, ":"); ok {
			socksServer.SetAuth(user, pass)
			logger.Verbosef("SOCKS5 authentication enabled for user '%s'", user)
		} else {
			logger.Errorf("Invalid SocksAuth format: %s (expected USER:PASS)", socksAuth)
		}
	}

	go func() {
		if err := socksServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
			logger.Errorf("SOCKS5 server: %v", err)
		}
	}()

	logger.Verbosef("SOCKS5 proxy listening on %s (WireGuard peer connected, keepalive: %ds)", listenAddr, pka)

	socksMu.Lock()
	defer socksMu.Unlock()
	for attempts := 0; attempts < math.MaxInt32; attempts++ {
		nextSocksHandle++
		if nextSocksHandle <= 0 {
			nextSocksHandle = 1
		}
		if _, exists := socksHandles[nextSocksHandle]; !exists {
			socksHandles[nextSocksHandle] = &Socks5Handle{
				server: socksServer,
				device: dev,
				bind:   evasionBind,
			}
			return nextSocksHandle
		}
	}
	_ = socksServer.Close()
	dev.Close()
	return -1
}

//export wgStopSocks5
func wgStopSocks5(socksHandle int32) {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	if !ok {
		socksMu.Unlock()
		return
	}
	delete(socksHandles, socksHandle)
	socksMu.Unlock()

	_ = handle.server.Close()
	handle.device.Close()
}

//export wgGetSocks5SocketV4
func wgGetSocks5SocketV4(socksHandle int32) int32 {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	socksMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetSocks5SocketV6
func wgGetSocks5SocketV6(socksHandle int32) int32 {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	socksMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

func main() {}
