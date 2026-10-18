package netproxy

// ReadBufferer is an optional capability for wrapped conns: it reports how
// many plaintext bytes are already buffered in userspace such that the next
// Read returns at least one byte without waiting for the network.
//
// Copy loops above the transport stack use it to decide whether another
// read completes immediately (write batching) without arming deadlines or
// issuing speculative reads, either of which can permanently poison
// record-framed streams such as TLS.
//
// Implementations report their own layer's buffered bytes plus everything
// visible through their underlying conn (they hold the reference and can
// delegate directly). The generic walker ReadBuffered stops at the first
// implementation hit, which is therefore expected to be the outermost conn.
type ReadBufferer interface {
	ReadBuffered() int
}

const readBufferedMaxDepth = 8

// ReadBuffered reports how many plaintext bytes are immediately readable
// from userspace buffers on conn (zero when unknown). It is observational
// only: no reads are issued and no stream state is modified.
func ReadBuffered(conn any) int {
	for depth := 0; depth < readBufferedMaxDepth; depth++ {
		switch c := conn.(type) {
		case nil:
			return 0
		case ReadBufferer:
			return c.ReadBuffered()
		case UnderlyingConnProvider:
			conn = c.UnderlyingConn()
		default:
			return 0
		}
	}
	return 0
}
