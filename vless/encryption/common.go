package encryption

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
	"lukechampine.com/blake3"
)

const (
	// Magic header bytes (TLS 1.3 disguise)
	MagicHeaderByte0 = 23
	MagicHeaderByte1 = 3
	MagicHeaderByte2 = 3

	// Protocol field lengths
	HeaderLength        = 5  // Magic header length
	IVLength            = 16 // Initialization Vector length
	NonceLength         = 12 // AEAD nonce length
	TicketLength        = 16
	AEADTagLength       = 16          // AEAD authentication tag length
	Hash256Length       = 32          // BLAKE3 hash length
	EncryptedLengthSize = 18          // 2-byte length + 16-byte tag
	XrayBufferSize      = 8192        // Xray buffer size
	MinPacketLength     = 17          // Minimum packet length (1 byte data + 16 byte tag)
	MaxPacketLength     = 16384 + 256 // TLS 1.3 max record: 16384 + 256 = 16640 (RFC 8446 §5.2)
	MinPaddingLength    = 35          // Minimum first padding length (18+17)
	MaxTotalPadding     = 65553       // Maximum total padding length (18+65535)

	Challenge = "VLESS"

	X25519KeySize = 32
)

var (
	// Keep in sync with crypto/tls/cipher_suites.go.
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	hasGCMAsmARM64 = (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64")
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH
	hasGCMAsmPPC64 = runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

	HasAESGCMHardwareSupport = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X || hasGCMAsmPPC64
)

type overrideAesKey struct{}

func OverrideUseAes(ctx context.Context, useAes bool) context.Context {
	return context.WithValue(ctx, overrideAesKey{}, useAes)
}

func useAesFromContext(ctx context.Context) bool {
	value := ctx.Value(overrideAesKey{})
	if value == nil {
		return HasAESGCMHardwareSupport
	}
	return value.(bool)
}

var (
	_ net.Conn             = (*CommonConn)(nil)
	_ N.ExtendedConn       = (*CommonConn)(nil)
	_ N.FrontHeadroom      = (*CommonConn)(nil)
	_ N.RearHeadroom       = (*CommonConn)(nil)
	_ N.ReaderWithMTU      = (*CommonConn)(nil)
	_ N.WriterWithMTU      = (*CommonConn)(nil)
	_ N.ReaderWithUpstream = (*CommonConn)(nil)
	_ N.WriterWithUpstream = (*CommonConn)(nil)
)

type CommonConn struct {
	conn        net.Conn
	useAES      bool
	client      *Client
	unitedKey   []byte
	preWrite    []byte
	aead        *AEAD
	peerAEAD    *AEAD
	peerPadding []byte
	peerHeader  [HeaderLength]byte

	// These two field are required by vision's reflect, DO NOT CHANGE
	rawInput bytes.Buffer // Read buffer
	input    bytes.Reader // Last read cache
}

func NewCommonConn(conn net.Conn, useAES bool) *CommonConn {
	return &CommonConn{
		conn:   conn,
		useAES: useAES,
	}
}

func (c *CommonConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > XrayBufferSize {
			b = b[:XrayBufferSize] // for avoiding another copy() in peer's Read()
		}
		n += len(b)
		headerAndData := buf.NewSize(len(c.preWrite) + HeaderLength + len(b) + c.aead.Overhead())
		preWrite := c.preWrite
		if preWrite != nil {
			common.Must1(headerAndData.Write(preWrite))
			c.preWrite = nil
		}
		encodeHeader(headerAndData.Extend(HeaderLength), len(b)+c.aead.Overhead())
		nonceGotMax := false
		if bytes.Equal(c.aead.Nonce[:], maxNonce) {
			nonceGotMax = true
		}
		c.aead.Seal(headerAndData.Index(len(preWrite)+HeaderLength), nil, b, headerAndData.Range(len(preWrite), len(preWrite)+HeaderLength))
		headerAndData.Truncate(headerAndData.Cap())
		if nonceGotMax {
			c.aead = NewAEAD(headerAndData.Bytes(), c.unitedKey, c.useAES)
		}
		_, err := c.conn.Write(headerAndData.Bytes())
		headerAndData.Release()
		if err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// WriteBuffer implements N.ExtendedWriter.
//
// When the buffer carries the headroom advertised by FrontHeadroom() and
// RearHeadroom(), the record is framed and sealed in place, saving the
// allocation and the copy of the whole payload that Write() has to do.
func (c *CommonConn) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	if dataLen == 0 {
		buffer.Release()
		return nil
	}
	overhead := c.aead.Overhead()
	if dataLen > XrayBufferSize || // needs to be fragmented
		c.preWrite != nil || // client's 0-RTT, needs more front headroom than advertised
		buffer.Start() < HeaderLength ||
		buffer.FreeLen() < overhead {
		defer buffer.Release()
		return common.Error(c.Write(buffer.Bytes()))
	}
	defer buffer.Release()
	header := buffer.ExtendHeader(HeaderLength)
	encodeHeader(header, dataLen+overhead)
	nonceGotMax := bytes.Equal(c.aead.Nonce[:], maxNonce)
	c.aead.Seal(buffer.Index(HeaderLength), nil, buffer.From(HeaderLength), header)
	buffer.Extend(overhead)
	if nonceGotMax {
		c.aead = NewAEAD(buffer.Bytes(), c.unitedKey, c.useAES)
	}
	return common.Error(c.conn.Write(buffer.Bytes()))
}

func (c *CommonConn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	err = c.readPrologue()
	if err != nil {
		return
	}
	if c.input.Len() > 0 {
		n, err = c.input.Read(b)
		return
	}
	return c.readChunk(b)
}

// ReadBuffer implements N.ExtendedReader.
//
// The record is read into the free space of the buffer and opened in place
// when it fits, avoiding the staging copy through rawInput.
func (c *CommonConn) ReadBuffer(buffer *buf.Buffer) error {
	if buffer.FreeLen() == 0 {
		return io.ErrShortBuffer
	}
	err := c.readPrologue()
	if err != nil {
		return err
	}
	var n int
	if c.input.Len() > 0 {
		n, err = c.input.Read(buffer.FreeBytes())
	} else {
		n, err = c.readChunk(buffer.FreeBytes())
	}
	if err != nil {
		return err
	}
	buffer.Truncate(buffer.Len() + n)
	return nil
}

// readPrologue reads the parts of the server response that precede the first
// record: the server random of a 0-RTT connection and the 1-RTT padding.
func (c *CommonConn) readPrologue() error {
	if c.peerAEAD == nil { // client's 0-RTT
		serverRandom := make([]byte, IVLength)
		_, err := io.ReadFull(c.conn, serverRandom)
		if err != nil {
			return err
		}
		c.peerAEAD = NewAEAD(serverRandom, c.unitedKey, c.useAES)
		if xorConn, isXorConn := c.conn.(*XorConn); isXorConn {
			xorConn.peerCTR = NewCTR(c.unitedKey, serverRandom)
		}
	}
	if c.peerPadding != nil { // client's 1-RTT
		_, err := io.ReadFull(c.conn, c.peerPadding)
		if err != nil {
			return err
		}
		_, err = c.peerAEAD.Open(c.peerPadding[:0], nil, c.peerPadding, nil)
		if err != nil {
			return err
		}
		c.peerPadding = nil
	}
	return nil
}

// readChunk reads one record, writes as much plaintext as fits into b and
// caches the remainder in input.
func (c *CommonConn) readChunk(b []byte) (n int, err error) {
	peerHeader := c.peerHeader[:]
	_, err = io.ReadFull(c.conn, peerHeader)
	if err != nil {
		return
	}
	l, err := decodeHeader(peerHeader) // l: 17~17000
	if err != nil {
		if c.client != nil && E.IsMulti(err, ErrInvalidHeader) { // client's 0-RTT
			c.client.ticketAccess.Lock()
			if bytes.HasPrefix(c.unitedKey, c.client.pfsKey) {
				c.client.expireAt = c.client.timeFunc() // expired
			}
			c.client.ticketAccess.Unlock()
			return 0, E.Extend(err, "new handshake needed")
		}
		return
	}
	c.client = nil
	var peerData []byte
	if len(b) >= l {
		peerData = b[:l] // avoids the copy through rawInput, opened in place below
	} else {
		if c.rawInput.Cap() < l {
			c.rawInput.Grow(l) // we are always reading
		}
		peerData = c.rawInput.Bytes()[:l]
	}
	_, err = io.ReadFull(c.conn, peerData)
	if err != nil {
		return
	}
	dst := peerData[:l-AEADTagLength]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	var newAEAD *AEAD
	if bytes.Equal(c.peerAEAD.Nonce[:], maxNonce) {
		newAEAD = NewAEAD(append(bytes.Clone(peerHeader), peerData...), c.unitedKey, c.useAES)
	}
	_, err = c.peerAEAD.Open(dst[:0], nil, peerData, peerHeader)
	if newAEAD != nil {
		c.peerAEAD = newAEAD
	}
	if err != nil {
		return 0, E.Cause(err, "CommonConn: open dst")
	}
	if len(dst) > len(b) {
		c.input.Reset(dst[copy(b, dst):])
		dst = b // for len(dst)
	}
	n = len(dst)
	return
}

func (c *CommonConn) Close() error {
	return common.Close(c.conn)
}

func (c *CommonConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *CommonConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *CommonConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *CommonConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *CommonConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// FrontHeadroom is the length of the record header prepended by WriteBuffer.
func (c *CommonConn) FrontHeadroom() int {
	return HeaderLength
}

// RearHeadroom is the length of the AEAD tag appended by WriteBuffer.
func (c *CommonConn) RearHeadroom() int {
	return AEADTagLength
}

// WriterMTU keeps the payload of a buffer within the size of a single record,
// so that WriteBuffer never has to fall back to the fragmenting Write().
func (c *CommonConn) WriterMTU() int {
	return XrayBufferSize
}

// ReaderMTU is the largest payload a peer record can carry.
func (c *CommonConn) ReaderMTU() int {
	return MaxPacketLength - AEADTagLength
}

func (c *CommonConn) WriterReplaceable() bool {
	return false
}

func (c *CommonConn) ReaderReplaceable() bool {
	return false
}

func (c *CommonConn) Upstream() any {
	return c.conn
}

var _ cipher.AEAD = (*AEAD)(nil)

type AEAD struct {
	aead  cipher.AEAD
	Nonce [NonceLength]byte
}

func NewAEAD(ctx, key []byte, useAES bool) *AEAD {
	subkey := make([]byte, 32)
	blake3.DeriveKey(subkey, string(ctx), key)
	var aead cipher.AEAD
	if useAES {
		block, _ := aes.NewCipher(subkey)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(subkey)
	}
	return &AEAD{aead: aead}
}

func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if nonce == nil {
		nonce = increaseNonce(a.Nonce[:])
	}
	return a.aead.Seal(dst, nonce, plaintext, additionalData)
}

func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if nonce == nil {
		nonce = increaseNonce(a.Nonce[:])
	}
	return a.aead.Open(dst, nonce, ciphertext, additionalData)
}

func (a *AEAD) NonceSize() int {
	return a.aead.NonceSize()
}

func (a *AEAD) Overhead() int {
	return a.aead.Overhead()
}

func increaseNonce(nonce []byte) []byte {
	for i := 0; i < NonceLength; i++ {
		nonce[NonceLength-1-i]++
		if nonce[NonceLength-1-i] != 0 {
			break
		}
	}
	return nonce
}

var maxNonce = bytes.Repeat([]byte{0xFF}, NonceLength)

func encodeHeader(header []byte, length int) {
	header[0] = MagicHeaderByte0
	header[1] = MagicHeaderByte1
	header[2] = MagicHeaderByte2
	binary.BigEndian.PutUint16(header[3:], uint16(length))
}

var ErrInvalidHeader = E.New("invalid header")

func decodeHeader(header []byte) (length int, err error) {
	length = int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != MagicHeaderByte0 || header[1] != MagicHeaderByte1 || header[2] != MagicHeaderByte2 {
		err = ErrInvalidHeader
		return
	}
	if length < MinPacketLength || length > MaxPacketLength {
		err = E.Extend(ErrInvalidHeader, fmt.Sprint(header[:HeaderLength])) // DO NOT CHANGE: relied by client's Read()
	}
	return
}

func parsePadding(padding []string) (paddingLens, paddingGaps [][3]int, err error) {
	if len(padding) == 0 {
		return
	}
	maxLen := 0
	for i, segment := range padding {
		parts := strings.Split(segment, "-")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			err = E.New("invalid padding length/gap parameter: " + segment)
			return
		}
		parsedValues := [3]int{}
		if parsedValues[0], err = strconv.Atoi(parts[0]); err != nil {
			return
		}
		if parsedValues[1], err = strconv.Atoi(parts[1]); err != nil {
			return
		}
		if parsedValues[2], err = strconv.Atoi(parts[2]); err != nil {
			return
		}
		if i == 0 && (parsedValues[0] < 100 || parsedValues[1] < MinPaddingLength || parsedValues[2] < MinPaddingLength) {
			err = E.New("first padding length must not be smaller than 35")
			return
		}
		if i%2 == 0 {
			paddingLens = append(paddingLens, parsedValues)
			maxLen += max(parsedValues[1], parsedValues[2])
		} else {
			paddingGaps = append(paddingGaps, parsedValues)
		}
	}
	if maxLen > MaxTotalPadding {
		err = E.New("total padding length must not be larger than 65553")
		return
	}
	return
}

func createPadding(paddingLens, paddingGaps [][3]int) (length int, lens []int, gaps []time.Duration) {
	if len(paddingLens) == 0 {
		paddingLens = [][3]int{{100, 111, 1111}, {50, 0, 3333}}
		paddingGaps = [][3]int{{75, 0, 111}}
	}
	for _, y := range paddingLens {
		l := 0
		if y[0] >= int(randBetween(0, 100)) {
			l = int(randBetween(int64(y[1]), int64(y[2])))
		}
		lens = append(lens, l)
		length += l
	}
	for _, y := range paddingGaps {
		g := 0
		if y[0] >= int(randBetween(0, 100)) {
			g = int(randBetween(int64(y[1]), int64(y[2])))
		}
		gaps = append(gaps, time.Duration(g)*time.Millisecond)
	}
	return
}

func randBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if to < from {
		from, to = to, from
	}
	return from + rand.Int64N(to-from)
}
