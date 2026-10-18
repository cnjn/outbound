// Modified from https://github.com/Reality/Xray-core/blob/fbc56b88da2808e3181add4935c143e319772c93/transport/internet/reality/reality.go

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/logger"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

// Reality protocol version bytes embedded in the ClientHello session ID.
const (
	realityVersionX byte = 1
	realityVersionY byte = 8
	realityVersionZ byte = 10
)

// realityHelloAttempts bounds how many ClientHellos the dialer generates before
// it gives up on a fingerprint. A fingerprint only authenticates when its hello
// carries a TLS 1.3 key share, and uTLS's randomized parrots (fp=random,
// fp=randomized) offer one in only about 40% of handshakes: measured over 3000
// builds each with the pinned uTLS revision, HelloRandomized,
// HelloRandomizedALPN and HelloRandomizedNoALPN landed at 37.7%-41.5%, while
// Chrome, Firefox, Safari and iOS landed at 100%.
//
// A rebuild happens before anything is sent, costs about 0.035ms, and reuses
// the same underlay, so it is free compared with the dial itself. Three attempts
// left the randomized fingerprints failing 0.6^3 = 22% of the time; sixteen
// bring that to 0.03%. Fingerprints that never carry a key share (for example
// Android 11's OkHttp parrot or the pre-TLS1.3 360 parrots) still fail after a
// bounded number of local rebuilds with an error that names the fingerprint.
const realityHelloAttempts = 16

// realityBothShapesBackoff is how long a REALITY server that rejected both
// ClientHello shapes (post-quantum free and hybrid) is dialled with a single
// attempt before the second shape is probed again.
const realityBothShapesBackoff = 5 * time.Minute

// realitySealAuth seals the REALITY authentication payload into the ClientHello
// session ID and copies the ciphertext back into the raw ClientHello.
//
// REALITY always authenticates with AES-GCM keyed by the 32-byte REALITY auth
// key (AES-256-GCM): Xray (crypto.NewAesGcm) and sing-box through
// metacubex-utls both open the payload with AES-GCM no matter which cipher
// suites the ClientHello offers. Deriving the AEAD from the
// offered suites is therefore wrong: an earlier revision preferred
// ChaCha20-Poly1305 whenever the first recognized suite was not AES-GCM, which
// randomized fingerprints (fp=random, fp=randomized) hit on a fraction of
// dials. The server then cannot open the payload, falls back to the handshake
// target and the client reports "REALITY: processed invalid connection".
func realitySealAuth(hello *utls.PubClientHelloMsg, authKey []byte) error {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return fmt.Errorf("REALITY: build AES block: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("REALITY: build AES-GCM: %w", err)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	return nil
}

type RealityUConn struct {
	*utls.UConn
	ServerName string
	AuthKey    []byte
	Verified   bool
}

// AlreadyReadBuffered marks RealityUConn as having a TLS record buffer so
// protocol dialers do not wrap it again with BufferedReaderConn.
func (c *RealityUConn) AlreadyReadBuffered() {}

var (
	realityPeerCertificatesFieldOnce sync.Once
	realityPeerCertificatesField     reflect.StructField
	realityPeerCertificatesFieldErr  error
)

func realityPeerCertificatesFieldInfo() (reflect.StructField, error) {
	realityPeerCertificatesFieldOnce.Do(func() {
		field, ok := reflect.TypeOf((*utls.Conn)(nil)).Elem().FieldByName("peerCertificates")
		if !ok {
			realityPeerCertificatesFieldErr = errors.New("REALITY: utls.Conn peerCertificates field unavailable")
			return
		}
		if field.Type != reflect.TypeOf([]*x509.Certificate{}) {
			realityPeerCertificatesFieldErr = fmt.Errorf(
				"REALITY: unexpected utls.Conn peerCertificates type: %v",
				field.Type,
			)
			return
		}
		realityPeerCertificatesField = field
	})
	return realityPeerCertificatesField, realityPeerCertificatesFieldErr
}

func realityPeerCertificates(conn *utls.Conn) ([]*x509.Certificate, error) {
	if conn == nil {
		return nil, errors.New("REALITY: nil uTLS connection")
	}
	field, err := realityPeerCertificatesFieldInfo()
	if err != nil {
		return nil, err
	}
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(conn), field.Offset))
	if len(certs) == 0 {
		return nil, errors.New("REALITY: missing peer certificates")
	}
	return certs, nil
}

func (c *RealityUConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c == nil || c.UConn == nil {
		return errors.New("REALITY: nil uTLS connection")
	}
	certs, err := realityPeerCertificates(c.Conn)
	if err != nil {
		return err
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type Reality struct {
	infoWriter io.Writer

	nextDialer  netproxy.Dialer
	serverName  string
	fingerprint *utls.ClientHelloID
	shortId     [8]byte
	publicKey   *ecdh.PublicKey
	spiderX     string
	spiderY     []int64

	// pqHybrid remembers whether this server authenticated with the
	// fingerprint's original ClientHello, which keeps the post-quantum
	// X25519MLKEM768 key share. Newest REALITY servers require that share and
	// answer as the real website when it is missing, while post-quantum aware
	// servers of the previous generation negotiate the hybrid group and then
	// derive a different REALITY authentication key, so both shapes exist in
	// the wild. The default shape is the pre-post-quantum one (see
	// dropHybridKeyShare); a failed handshake retries the other shape once.
	pqHybrid atomic.Bool
	// pqRetryAfter suppresses that second shape probe until this UNIX time once
	// both shapes failed, so a dead or blocked server is not dialled twice on
	// every single connection.
	pqRetryAfter atomic.Int64
}

// dropHybridKeyShare removes the post-quantum X25519MLKEM768 group from the
// ClientHello: both its key share entry and its supported_groups entry.
//
// REALITY encrypts its authentication payload into the ClientHello before the
// server chooses a key share, so the client has to keep the negotiated group
// deterministic: the payload is sealed with the classic X25519 key share, while
// a server that negotiates the hybrid X25519MLKEM768 group derives a different
// authentication key and treats the client as a probe. Post-quantum capable
// servers prefer that group as soon as the client advertises it (Go 1.24
// curvePreferences, Chrome 131+ parrots), which makes "chrome" fingerprints
// fail against them with "REALITY: processed invalid connection".
//
// Removing only the supported_groups entry is not enough: servers that validate
// key shares against the advertised groups reject the hello with
// "tls: illegal parameter". Removing both yields the pre-PQ Chrome hello shape
// that Xray's pinned uTLS fingerprints produce.
func dropHybridKeyShare(uConn *utls.UConn) {
	changed := false
	for _, ext := range uConn.Extensions {
		switch e := ext.(type) {
		case *utls.KeyShareExtension:
			kept := e.KeyShares[:0]
			for _, share := range e.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					changed = true
					continue
				}
				kept = append(kept, share)
			}
			e.KeyShares = kept
		case *utls.SupportedCurvesExtension:
			kept := e.Curves[:0]
			for _, curve := range e.Curves {
				if curve == utls.X25519MLKEM768 {
					changed = true
					continue
				}
				kept = append(kept, curve)
			}
			e.Curves = kept
		}
	}
	if !changed {
		return
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		logger.Logger.WithError(err).Warn("REALITY: failed to rebuild ClientHello without X25519MLKEM768")
	}
}

// realityECDHEKey returns the TLS 1.3 ECDHE private key used by REALITY.
// Newer uTLS versions populate KeyShareKeys and may leave the deprecated
// EcdheKey field unset, so keep compatibility with both layouts.
func realityECDHEKey(state *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if state == nil {
		return nil
	}
	if keyShareKeys := state.State13.KeyShareKeys; keyShareKeys != nil {
		if keyShareKeys.Ecdhe != nil {
			return keyShareKeys.Ecdhe
		}
		if keyShareKeys.MlkemEcdhe != nil {
			return keyShareKeys.MlkemEcdhe
		}
	}
	return state.State13.EcdheKey // nolint:staticcheck
}

func (x *Reality) UnwrapDialer() netproxy.Dialer {
	return x.nextDialer
}

func NewReality(s string, d netproxy.Dialer) (*Reality, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewReality: %w", err)
	}

	x := &Reality{
		nextDialer: d,
	}

	query := u.Query()
	x.serverName = query.Get("sni")
	_, err = hex.Decode(x.shortId[:], []byte(query.Get("sid")))
	if err != nil {
		return nil, fmt.Errorf("invalid reality sid")
	}
	_publicKey := query.Get("pbk")
	const x25519ScalarSize = 32
	var publicKey [x25519ScalarSize]byte
	_, err = base64.RawURLEncoding.Decode(publicKey[:], []byte(_publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid reality pbk")
	}
	x.publicKey, err = ecdh.X25519().NewPublicKey(publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("REALITY: publicKey == nil: %w", err)
	}
	x.spiderX, _ = url.QueryUnescape(query.Get("spx"))
	_fingerprint := query.Get("fp")

	if x.serverName == "" {
		x.serverName = u.Hostname()
	} else if strings.ToLower(x.serverName) == "nosni" { // If ServerName is set to "nosni", we set it empty.
		x.serverName = ""
	}

	x.fingerprint, err = nameToUtlsClientHelloID(_fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	if x.spiderX == "" {
		x.spiderX = "/"
	}
	if x.spiderX[0] != '/' {
		return nil, fmt.Errorf(`invalid "spiderX": %v`, x.spiderX)
	}
	x.spiderY = make([]int64, 10)
	// spiderX comes from the subscription link (?spx=), so it is attacker- and
	// typo-controllable. url.Parse returns a nil *URL on error, and the very
	// next line dereferences it: a malformed value must be rejected here, at
	// configuration load / hot-reload time, instead of panicking the process.
	tmpU, err := url.Parse(x.spiderX)
	if err != nil {
		return nil, fmt.Errorf("REALITY: invalid spiderX %q: %w", x.spiderX, err)
	}
	q := tmpU.Query()
	parse := func(param string, index int) {
		if q.Get(param) != "" {
			s := strings.Split(q.Get(param), "-")
			if len(s) == 1 {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
			} else {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
			}
		}
		q.Del(param)
	}
	parse("p", 0) // padding
	parse("c", 2) // concurrency
	parse("t", 4) // times
	parse("i", 6) // interval
	parse("r", 8) // return
	// The five parameters above are REALITY's own spider schedule and are
	// consumed by the parse calls, so they must not survive into x.spiderX:
	// that value is concatenated onto "https://"+serverName to build the
	// cover-traffic GET (paths[x.spiderX] below), and upstream Xray strips
	// them for exactly that reason (config.SpiderX = u.String() with u parsed
	// from spiderX in infra/conf/transport_security.go). The stripped query
	// therefore belongs to the spiderX URL, not to the outer link in u.
	tmpU.RawQuery = q.Encode()
	x.spiderX = tmpU.String()
	// x.infoWriter = logger.Logger.WriterLevel(logrus.TraceLevel)
	// logrus.Printf("%#v", x)
	return x, nil
}

func (x *Reality) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		// logrus.Printf("%#v, %T, %v", x.nextDialer, magicNetwork.Network, addr)
		c, err := x.nextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[REALITY]: dial to %s: %w", addr, err)
		}
		retry := 1
		retryHybrid := false
		hybridHello := x.pqHybrid.Load()
	retryHandshake:
		uConn := &RealityUConn{}
		utlsConfig := &utls.Config{
			VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
			ServerName:             x.serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			KeyLogWriter:           x.infoWriter,
		}
		uConn.ServerName = utlsConfig.ServerName
		uConn.UConn = utls.UClient(&netproxy.FakeNetConn{
			Conn:  c,
			LAddr: nil,
			RAddr: nil,
		}, utlsConfig, *x.fingerprint)
		{
			err = uConn.BuildHandshakeState()
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			if !hybridHello {
				dropHybridKeyShare(uConn.UConn)
			}
			hello := uConn.HandshakeState.Hello
			hello.SessionId = make([]byte, 32)
			copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
			hello.SessionId[0] = realityVersionX
			hello.SessionId[1] = realityVersionY
			hello.SessionId[2] = realityVersionZ
			hello.SessionId[3] = 0 // reserved
			binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
			copy(hello.SessionId[8:], x.shortId[:])
			// if config.Show {
			// logrus.Printf("REALITY hello.SessionId[:16]: %v\n", hello.SessionId[:16])
			// }
			ecdheKey := realityECDHEKey(&uConn.HandshakeState)
			if ecdheKey == nil {
				// logrus.Println("wtf", retry, addr)
				if retry >= realityHelloAttempts {
					_ = c.Close()
					return nil, fmt.Errorf("REALITY: fingerprint %s %s does not provide a usable TLS 1.3 key share", x.fingerprint.Client, x.fingerprint.Version)
				}
				// retryHandshake sits after the dial: the retry re-wraps
				// the same live underlay below, so it must stay open.
				// Only the terminal exit above owns the close.
				retry++
				goto retryHandshake // rebuild the hello with a fresh key share
			}
			// logrus.Println("OH YEAH", retry)
			uConn.AuthKey, _ = ecdheKey.ECDH(x.publicKey)
			if uConn.AuthKey == nil {
				_ = c.Close()
				return nil, errors.New("REALITY: SharedKey == nil")
			}
			if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
				_ = c.Close()
				return nil, err
			}
			if err := realitySealAuth(hello, uConn.AuthKey); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		// logrus.Println("00")
		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, err
		}
		// if config.Show {
		// 	newError(fmt.Sprintf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)).WriteToLog(session.ExportIDToError(ctx))
		// }
		// logrus.Println("11", uConn.Verified)
		if !uConn.Verified {
			// The server answered as the real website instead of proving
			// itself, which means it rejected the REALITY authentication
			// payload. Retry once with the other ClientHello shape, because the
			// shape is what differs between server generations, then give up and
			// act as cover traffic.
			if !retryHybrid && (hybridHello || time.Now().Unix() >= x.pqRetryAfter.Load()) {
				retryHybrid = true
				hybridHello = !hybridHello
				_ = c.Close()
				if next, dialErr := x.nextDialer.DialContext(ctx, network, addr); dialErr == nil {
					c = next
					goto retryHandshake
				}
			}
			x.pqRetryAfter.Store(time.Now().Add(realityBothShapesBackoff).Unix())
			// Trigger spider. This goroutine lives as long as the process and
			// nothing else owns it, so an unhandled panic here would take the
			// whole process down; contain it and report it instead.
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Logger.WithFields(map[string]any{
							"server_name": uConn.ServerName,
							"panic":       fmt.Sprint(r),
							"stack":       string(debug.Stack()),
						}).Error("REALITY: panic in spider goroutine")
					}
				}()
				client := &http.Client{
					Transport: &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
							return uConn, nil
						},
					},
				}
				prefix := []byte("https://" + uConn.ServerName)
				paths, firstPath := spiderPathsFor(uConn.ServerName, x.spiderX)
				firstURL := string(prefix) + firstPath
				get := func(first bool) {
					// The !first requests each run on their own goroutine and
					// outlive the handshake, so a panic here would take the
					// whole process down; contain it and report it instead.
					defer func() {
						if r := recover(); r != nil {
							logger.Logger.WithFields(map[string]any{
								"server_name": uConn.ServerName,
								"panic":       fmt.Sprint(r),
								"stack":       string(debug.Stack()),
							}).Error("REALITY: panic in spider request")
						}
					}()
					var (
						req  *http.Request
						resp *http.Response
						err  error
						body []byte
					)
					var target string
					if first {
						target = firstURL
					} else {
						target = string(prefix) + spiderNextPath(paths)
					}
					// The harvested paths are peer-controlled (href values
					// scraped from the backdrop), so an unbuildable request
					// URL is a real outcome. A nil request here would panic
					// on the next line, in a goroutine that outlives the
					// handshake.
					if req, err = http.NewRequest("GET", target, nil); err != nil {
						return
					}
					req.Header.Set("User-Agent", x.fingerprint.Client) // TODO: User-Agent map
					// if first && config.Show {
					// 	newError(fmt.Sprintf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())).WriteToLog(session.ExportIDToError(ctx))
					// }
					// logrus.Printf("session %#v", uConn.HandshakeState.Session)
					times := 1
					if !first {
						times = int(randBetween(x.spiderY[4], x.spiderY[5]))
					}
					for j := 0; j < times; j++ {
						if !first && j == 0 {
							req.Header.Set("Referer", firstURL)
						}
						req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(randBetween(x.spiderY[0], x.spiderY[1])))})
						// Bound each request: the spider shares the process
						// lifetime, and a backdrop that accepts and stalls
						// would otherwise park this goroutine (and the uConn
						// it holds) forever.
						reqCtx, cancelReq := context.WithTimeout(context.Background(), spiderRequestTimeout)
						if resp, err = client.Do(req.WithContext(reqCtx)); err != nil {
							cancelReq()
							break
						}
						req.Header.Set("Referer", req.URL.String())
						if body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20)); err != nil {
							_ = resp.Body.Close()
							cancelReq()
							break
						}
						_ = resp.Body.Close()
						cancelReq()
						req.URL.Path = spiderHarvest(uConn.ServerName, paths, prefix, body)
						// if config.Show {
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())).WriteToLog(session.ExportIDToError(ctx))
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))).WriteToLog(session.ExportIDToError(ctx))
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))).WriteToLog(session.ExportIDToError(ctx))
						// }
						if !first {
							time.Sleep(time.Duration(randBetween(x.spiderY[6], x.spiderY[7])) * time.Millisecond) // interval
						}
					}
				}
				get(true)
				concurrency := int(randBetween(x.spiderY[2], x.spiderY[3]))
				for i := 0; i < concurrency; i++ {
					go get(false)
				}
				// Do not close the connection
			}()
			time.Sleep(time.Duration(randBetween(x.spiderY[8], x.spiderY[9])) * time.Millisecond) // return
			return nil, errors.New("REALITY: processed invalid connection")
		}
		x.pqHybrid.Store(hybridHello)
		x.pqRetryAfter.Store(0)
		return uConn, nil

	case "udp":
		return nil, fmt.Errorf("%w: Reality+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}

}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]bool
	// bytes is the retained href bytes per serverName. maxSpiderPaths bounds the
	// entry count but not the entry sizes: each key is an href harvested from a
	// body read with a 1 MiB limit, so the entry cap alone leaves room for
	// 4096 * 1 MiB of peer-fed keys per serverName, kept for the process
	// lifetime.
	bytes map[string]int
}

const (
	// spiderRequestTimeout bounds each spider backdrop request: the spider
	// goroutines share the process lifetime and are never cancelled, so an
	// unbounded request would park them (and the uConn they hold) forever.
	spiderRequestTimeout = 30 * time.Second
	// maxSpiderPaths bounds the harvested-path set per serverName; the peer
	// controls how many hrefs it can feed the harvester.
	maxSpiderPaths = 4096
	// maxSpiderBytes bounds the harvested-path bytes per serverName. A real
	// backdrop's paths sit well below it -- reaching it would take 4096 entries
	// of 256 bytes each -- so it only binds on the overlength keys that
	// maxSpiderPaths alone cannot bound.
	maxSpiderBytes = 1 << 20
)

// spiderPathRetained decides whether one harvested href joins the set. It is a
// named function so the bound is testable without a live REALITY handshake.
func spiderPathRetained(paths map[string]bool, retainedBytes int, key []byte) bool {
	return !bytes.Contains(key, dot) &&
		len(paths) < maxSpiderPaths &&
		retainedBytes+len(key) <= maxSpiderBytes
}

func getPathLocked(paths map[string]bool) string {
	stopAt := int(randBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

// spiderPathsFor returns serverName's harvested path set, creating it and
// seeding it with spiderX on first use, together with the first request path.
// The maps lock is taken and released inside, by defer: the recover that
// contains a panic in the spider goroutines sits outside this critical section,
// so an unlock skipped by a panic would outlive the recovered panic and wedge
// every later spider access.
func spiderPathsFor(serverName, spiderX string) (map[string]bool, string) {
	maps.Lock()
	defer maps.Unlock()
	if maps.maps == nil || maps.bytes == nil {
		maps.maps = make(map[string]map[string]bool)
		maps.bytes = make(map[string]int)
	}
	paths := maps.maps[serverName]
	if paths == nil {
		paths = make(map[string]bool)
		paths[spiderX] = true
		maps.maps[serverName] = paths
		maps.bytes[serverName] = len(spiderX)
	}
	return paths, getPathLocked(paths)
}

// spiderNextPath returns the next request path from the path set. The harvest
// goroutines write that map, so getPathLocked reads it under the maps lock, and
// the unlock is deferred for the panic-safety reason above.
func spiderNextPath(paths map[string]bool) string {
	maps.Lock()
	defer maps.Unlock()
	return getPathLocked(paths)
}

// spiderHarvest merges the hrefs of one backdrop body into the path set and
// returns the next request path. The merge and the path pick run under the maps
// lock, which is released by defer for the panic-safety reason above.
func spiderHarvest(serverName string, paths map[string]bool, prefix, body []byte) string {
	maps.Lock()
	defer maps.Unlock()
	for _, m := range href.FindAllSubmatch(body, -1) {
		m[1] = bytes.TrimPrefix(m[1], prefix)
		if spiderPathRetained(paths, maps.bytes[serverName], m[1]) {
			paths[string(m[1])] = true
			maps.bytes[serverName] += len(m[1])
		}
	}
	return getPathLocked(paths)
}

func randBetween(left int64, right int64) int64 {
	if left >= right {
		return left
	}
	bigInt, err := rand.Int(rand.Reader, big.NewInt(right-left))
	if err != nil || bigInt == nil {
		// Entropy failure must not panic on a nil big.Int; fall back to the
		// lower bound.
		return left
	}
	return left + bigInt.Int64()
}
