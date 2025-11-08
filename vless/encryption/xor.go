package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"time"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"

	"lukechampine.com/blake3"
)

func NewCTR(key, iv []byte) cipher.Stream {
	subkey := make([]byte, 32)
	blake3.DeriveKey(subkey, Challenge, key) // avoids using key directly
	block, _ := aes.NewCipher(subkey)
	return cipher.NewCTR(block, iv)
	// chacha20.NewUnauthenticatedCipher()
}

// XorMode represents the XOR encryption mode for obfuscation
type XorMode byte

const (
	XorModeNative XorMode = 0 // No XOR obfuscation
	XorModeXorPub XorMode = 1 // XOR obfuscation for public key/ciphertext only
	XorModeRandom XorMode = 2 // Full XOR obfuscation for all traffic
)

var (
	_ net.Conn             = (*XorConn)(nil)
	_ N.ReaderWithUpstream = (*XorConn)(nil)
	_ N.WriterWithUpstream = (*XorConn)(nil)
)

type XorConn struct {
	conn      net.Conn
	ctr       cipher.Stream
	peerCTR   cipher.Stream
	outSkip   int
	outHeader []byte
	inSkip    int
	inHeader  []byte
}

func NewXorConn(conn net.Conn, ctr, peerCTR cipher.Stream, outSkip, inSkip int) *XorConn {
	return &XorConn{
		conn:      conn,
		ctr:       ctr,
		peerCTR:   peerCTR,
		outSkip:   outSkip,
		outHeader: make([]byte, 0, HeaderLength), // important
		inSkip:    inSkip,
		inHeader:  make([]byte, 0, HeaderLength), // important
	}
}

func (c *XorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for p := b; ; {
		if len(p) <= c.outSkip {
			c.outSkip -= len(p)
			break
		}
		p = p[c.outSkip:]
		c.outSkip = 0
		need := HeaderLength - len(c.outHeader)
		if len(p) < need {
			c.outHeader = append(c.outHeader, p...)
			c.ctr.XORKeyStream(p, p)
			break
		}
		c.outSkip, _ = decodeHeader(append(c.outHeader, p[:need]...))
		c.outHeader = c.outHeader[:0]
		c.ctr.XORKeyStream(p[:need], p[:need])
		p = p[need:]
	}
	if _, err := c.conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *XorConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.conn.Read(b)
	for p := b[:n]; ; {
		if len(p) <= c.inSkip {
			c.inSkip -= len(p)
			break
		}
		p = p[c.inSkip:]
		c.inSkip = 0
		need := HeaderLength - len(c.inHeader)
		if len(p) < need {
			c.peerCTR.XORKeyStream(p, p)
			c.inHeader = append(c.inHeader, p...)
			break
		}
		c.peerCTR.XORKeyStream(p[:need], p[:need])
		c.inSkip, _ = decodeHeader(append(c.inHeader, p[:need]...))
		c.inHeader = c.inHeader[:0]
		p = p[need:]
	}
	return n, err
}

func (c *XorConn) Close() error {
	return common.Close(c.conn)
}

func (c *XorConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *XorConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *XorConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *XorConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *XorConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *XorConn) WriterReplaceable() bool {
	return false
}

func (c *XorConn) ReaderReplaceable() bool {
	return false
}

func (c *XorConn) Upstream() any {
	return c.conn
}
