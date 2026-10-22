/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"fmt"
	"net"
	"strconv"
)

// androidFallbackFakeTTL is the safe FakeTTL used on Android when the route
// distance cannot be probed. It must stay small enough that the fake packet
// never reaches the real WireGuard server.
const androidFallbackFakeTTL = 5

// MeasureTargetTTL measures the network distance (hops) to the target endpoint
// and calculates the optimal FakeTTL for DPI early-termination desync.
//
// On Android the distance is measured without root through IP_RECVERR /
// MSG_ERRQUEUE, so no traceroute binary or CAP_NET_RAW is required.
func MeasureTargetTTL(endpoint string) (totalHops int, recommendedFakeTTL int, err error) {
	host := endpoint
	port := 51820
	if h, p, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
		host = h
		if parsedPort, convErr := strconv.Atoi(p); convErr == nil && parsedPort > 0 {
			port = parsedPort
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		ips, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(ips) == 0 {
			return 0, androidFallbackFakeTTL, fmt.Errorf("failed to resolve endpoint %s: %v", host, lookupErr)
		}
		for _, candidate := range ips {
			if candidate.To4() != nil {
				ip = candidate
				break
			}
		}
		if ip == nil {
			return 0, androidFallbackFakeTTL, fmt.Errorf("no IPv4 address found for %s", host)
		}
	}

	if hops, probeErr := measureTTLViaErrQueue(ip, port); probeErr == nil && hops > 0 {
		return hops, recommendFakeTTL(hops), nil
	} else if probeErr != nil {
		return 0, androidFallbackFakeTTL, fmt.Errorf("kernel TTL probe unavailable: %w", probeErr)
	}

	return 0, androidFallbackFakeTTL, fmt.Errorf("kernel TTL probe returned no hops")
}

// recommendFakeTTL derives a safe fake TTL from the measured hop count. The
// fake packet must traverse the domestic DPI (TSPU) but expire before reaching
// the foreign server. The Android-safe window is 3..7.
func recommendFakeTTL(totalHops int) int {
	recommended := totalHops - 4
	if recommended < 3 {
		recommended = 3
	}
	if recommended > 7 {
		recommended = 7
	}
	return recommended
}
