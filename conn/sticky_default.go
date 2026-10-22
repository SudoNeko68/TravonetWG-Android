//go:build !linux || android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net/netip"

// Sticky sockets (IP_PKTINFO/ {get,set}srcControl) are deliberately disabled on
// Android. The Linux implementation pairs that with device/sticky_linux.go,
// which tracks address changes through an rtnetlink multicast subscription; on
// a non-rooted device SELinux denies the required CAP_NET_ADMIN for that
// subscription, so enabling the feature would fail at runtime instead of
// degrading gracefully. Without it WireGuard simply re-resolves the source
// address whenever the endpoint is reset (new handshake, bind update or port
// rotation via device.RotatePort), which is sufficient for mobile networks.

func (e *StdNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *StdNetEndpoint) SrcIfidx() int32 {
	return 0
}

func (e *StdNetEndpoint) SrcToString() string {
	return ""
}

// TODO: macOS, FreeBSD and other BSDs likely do support the sticky sockets
// {get,set}srcControl feature set, but use alternatively named flags and need
// ports and require testing.

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
}

// stickyControlSize returns the recommended buffer size for pooling sticky
// offloading control data.
const stickyControlSize = 0

const StdNetSupportsStickySockets = false
