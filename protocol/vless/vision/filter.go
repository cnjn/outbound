package vision

import (
	"bytes"
	"encoding/binary"
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHandshakeStart = []byte{0x16, 0x03}
	tlsServerHandshakeStart = []byte{0x16, 0x03, 0x03}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	tls13CipherSuiteMap = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	tlsHandshakeTypeClientHello byte = 0x01
	tlsHandshakeTypeServerHello byte = 0x02
)

func (vc *Conn) FilterTLS(buffer []byte) (index int) {
	vc.filterMu.Lock()
	defer vc.filterMu.Unlock()
	return vc.filterTLSLocked(buffer)
}

// stopFilteringLocked marks the sniffer as done. Called from the write path
// once it has decided TLS filtering is no longer needed (non-TLS traffic or
// direct mode engaged). Acquires filterMu so the state is consistent with
// any concurrent FilterTLS invocation from the read path.
func (vc *Conn) stopFilteringLocked() {
	vc.filterMu.Lock()
	vc.packetsToFilter = 0
	vc.filterMu.Unlock()
}

// filterSnapshot returns a point-in-time copy of the sniffing state for the
// write path to make padding decisions on. Callers must not hold filterMu.
type filterSnapshot struct {
	packetsToFilter int
	isTLS           bool
	isTLS12orAbove  bool
	enableXTLS      bool
}

// filterSnapshot returns a consistent snapshot of the fields the write path
// reads after calling FilterTLS. Taking the snapshot under filterMu closes
// the TOCTOU window between FilterTLS updating the state machine and the
// write path reading it to pick a padding command.
func (vc *Conn) filterSnapshot() filterSnapshot {
	vc.filterMu.Lock()
	defer vc.filterMu.Unlock()
	return filterSnapshot{
		packetsToFilter: vc.packetsToFilter,
		isTLS:           vc.isTLS,
		isTLS12orAbove:  vc.isTLS12orAbove,
		enableXTLS:      vc.enableXTLS,
	}
}

// isCompleteAppDataRecords reports whether b consists solely of one or more
// complete TLS ApplicationData (0x17 0x03 0x03) records. Invariant: Vision must
// never switch to Direct mode in the middle of a record.
func isCompleteAppDataRecords(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for len(b) > 0 {
		if len(b) < 5 || !bytes.Equal(b[:3], tlsApplicationDataStart) {
			return false
		}
		recordLen := int(binary.BigEndian.Uint16(b[3:5]))
		if recordLen == 0 || len(b)-5 < recordLen {
			return false
		}
		b = b[5+recordLen:]
	}
	return true
}

func (vc *Conn) filterTLSLocked(buffer []byte) (index int) {
	if vc.packetsToFilter <= 0 {
		return 0
	}
	lenP := len(buffer)
	vc.packetsToFilter--
	if index = bytes.Index(buffer, tlsServerHandshakeStart); index != -1 {
		if lenP > index+5 {
			if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
				vc.isTLS = true
				if buffer[5] == tlsHandshakeTypeServerHello {
					//logrus.Infof("isTLS12orAbove")
					vc.remainingServerHello = binary.BigEndian.Uint16(buffer[index+3:]) + 5
					vc.isTLS12orAbove = true
					if lenP-index >= 79 && vc.remainingServerHello >= 79 {
						// RFC 8446 4.1.2: legacy_session_id is opaque<0..32>.
						// The pre-fix code indexed the cipher suite without
						// validating that length, so an oversized field read
						// past the end of the buffer (panic on a hostile
						// ServerHello). A length outside the RFC range skips
						// cipher discovery: vc.cipher stays 0, XTLS stays
						// false, and the connection falls back to plain VLESS
						// relaying - the fail-safe direction.
						sessionIDLen := int(buffer[index+43])
						cipherOff := index + 44 + sessionIDLen
						if sessionIDLen <= 32 && cipherOff+2 <= lenP {
							vc.cipher = binary.BigEndian.Uint16(buffer[cipherOff:])
						}
					}
				}
			}
		}
	} else if index = bytes.Index(buffer, tlsClientHandshakeStart); index != -1 {
		if lenP > index+5 && buffer[index+5] == tlsHandshakeTypeClientHello {
			vc.isTLS = true
		}
	}

	if vc.remainingServerHello > 0 {
		end := int(vc.remainingServerHello)
		i := index
		if i < 0 {
			i = 0
		}
		if i+end > lenP {
			end = lenP
			vc.remainingServerHello -= uint16(end - i)
		} else {
			vc.remainingServerHello -= uint16(end)
			end += i
		}
		if bytes.Contains(buffer[i:end], tls13SupportedVersions) {
			// TLS 1.3 Client Hello
			cs, ok := tls13CipherSuiteMap[vc.cipher]
			if ok && cs != "TLS_AES_128_CCM_8_SHA256" {
				vc.enableXTLS = true
			}
			// logrus.Infof("XTLS Vision found TLS 1.3, packetLength=%d， CipherSuite=%s", lenP, cs)
			vc.packetsToFilter = 0
			return
		} else if vc.remainingServerHello <= 0 {
			// logrus.Infof("XTLS Vision found TLS 1.2, packetLength=%d", lenP)
			vc.packetsToFilter = 0
			return
		}
		// logrus.Infof("XTLS Vision found inconclusive server hello, packetLength=%d, remainingServerHelloBytes=%d", lenP, vc.remainingServerHello)
	}
	// if vc.packetsToFilter <= 0 {
	// 	logrus.Infof("XTLS Vision stop filtering")
	// }
	return
}
