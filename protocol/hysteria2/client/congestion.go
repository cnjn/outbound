package client

import "fmt"

// Congestion controller names used by the hysteria2 client. They match the
// shared cc_override allowlist in protocol/tuic/common, restricted to the
// controllers this client can actually install.
const (
	ccBBR    = "bbr"
	ccBrutal = "brutal"
	ccBbr3   = "bbr3"
)

// defaultCongestionController mirrors
// protocol/tuic/common.DefaultCongestionController: the controller installed
// when a link carries no explicit cc_override. This package keeps its own
// allowlist copy, so the default is mirrored here as well.
//
// The default is bbr3 again now that its low-RTT pacing-cwnd deadlock is
// fixed (see the bbr3 sender): on a loopback/veth lab bbr3 measured
// 3.80-3.97 Gbps p1 and 3.97 Gbps p4 against bbr's 3.74 and brutal's 3.62,
// and on the shaped-path regime bbr3 already measured better than bbr (see
// protocol/tuic/common/congestion.go). cc_override=bbr remains available.
const defaultCongestionController = ccBbr3

// ValidateCongestionOverride reports whether override can be installed by this
// client before any connection is attempted. An empty value is always valid and
// means "no client override" (server-driven selection). cubic and new_reno are
// in the shared link allowlist but have no hysteria2 implementation, so they are
// rejected here instead of being silently downgraded to BBR.
func ValidateCongestionOverride(override string) error {
	switch override {
	case "", ccBBR, ccBrutal, ccBbr3:
		return nil
	case "cubic", "new_reno":
		return fmt.Errorf("cc_override %q is not supported by hysteria2", override)
	default:
		return fmt.Errorf("unsupported cc_override %q: hysteria2 supports bbr, brutal, bbr3", override)
	}
}

// resolveCongestion decides which congestion controller the client installs
// after a successful handshake. It is a pure function so the whole decision
// table is unit-testable without a QUIC connection.
//
// override is the normalized (lowercased, trimmed) cc_override value. An empty
// override chooses between the two measured regimes:
//
//   - rxAuto: the server asked for bandwidth detection, so a fixed-rate sender
//     would ignore that request; use defaultCongestionController and keep a
//     declared clientTx as its access-link ceiling (a hint caps, it is never a
//     target, so it cannot distort the detection the server asked for).
//   - otherwise min(serverRx, clientTx) is the rate the link declared. When it
//     is positive, install Brutal at exactly that rate: on a bottlenecked path
//     (4 MB/s shaper, 256 KB queue, 40 ms one-way, 12 MiB, n=5) the fixed-rate
//     sender delivered 3.82 MiB/s at a 19.9 ms p95, against 3.31 MiB/s at
//     61.0 ms for the probing default and 2.99 MiB/s at 63.8 ms with ~17x the
//     packet loss for the BBR this table used to fall back to. When it is zero
//     no rate is known, and the probing default measured better than that BBR.
//
// A non-empty override keeps its own semantics:
//
//   - bbr forces BBR and reports no target;
//   - brutal runs the same min(serverRx, clientTx) computation and keeps the
//     historical BBR fallback when no bandwidth is known;
//   - cubic, new_reno, and anything else return an error, because a silent
//     downgrade would hide a typo.
//
// The returned tx is the target handed to the installer (brutal target or bbr3
// hint); it is zero when no target applies.
func resolveCongestion(override string, rxAuto bool, serverRx, clientTx uint64) (string, uint64, error) {
	if err := ValidateCongestionOverride(override); err != nil {
		return "", 0, err
	}
	if override == "" {
		if rxAuto {
			return defaultCongestionController, clientTx, nil
		}
		if name, tx := brutalTarget(serverRx, clientTx); name == ccBrutal {
			return name, tx, nil
		}
		return defaultCongestionController, 0, nil
	}
	switch override {
	case ccBbr3:
		return ccBbr3, clientTx, nil
	case ccBrutal:
		name, tx := brutalTarget(serverRx, clientTx)
		return name, tx, nil
	default: // ccBBR
		return ccBBR, 0, nil
	}
}

// brutalTarget is the historical min(serverRx, clientTx) computation: a
// positive target selects Brutal, otherwise BBR.
func brutalTarget(serverRx, clientTx uint64) (string, uint64) {
	tx := serverRx
	if tx == 0 || tx > clientTx {
		tx = clientTx
	}
	if tx > 0 {
		return ccBrutal, tx
	}
	return ccBBR, 0
}
