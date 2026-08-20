package packetaddr

import (
	"encoding/binary"
	"io"
	"math"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const streamPacketLengthSize = 2

var (
	_ N.NetPacketConn    = (*StreamPacketConn)(nil)
	_ N.PacketReadWaiter = (*StreamPacketConn)(nil)
)

type StreamPacketConn struct {
	net.Conn
	bindAddr        M.Socksaddr
	writer          N.VectorisedWriter
	readWaitOptions N.ReadWaitOptions
}

func NewStreamConn(conn net.Conn, bindAddr M.Socksaddr) *StreamPacketConn {
	streamConn := &StreamPacketConn{
		Conn:     conn,
		bindAddr: bindAddr,
	}
	streamConn.writer, _ = bufio.CreateVectorisedWriter(N.UnwrapWriter(conn))
	return streamConn
}

func (c *StreamPacketConn) RemoteAddr() net.Addr {
	return c.bindAddr
}

func (c *StreamPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *StreamPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.bindAddr)
}

func (c *StreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	length, err := readStreamPacketLength(c.Conn)
	if err != nil {
		return
	}
	var destination M.Socksaddr
	destination, err = AddressSerializer.ReadAddrPort(c.Conn)
	if err != nil {
		return
	}
	destinationLen := AddressSerializer.AddrPortLen(destination)
	if destinationLen > int(length) {
		err = ErrInvalidSegment
		return
	}
	payloadLen := int(length) - destinationLen
	if payloadLen > len(p) {
		n, err = io.ReadFull(c.Conn, p)
		if err != nil {
			return
		}
		_, err = bufio.Copy(io.Discard, io.LimitReader(c.Conn, int64(payloadLen-len(p))))
		if err != nil {
			return
		}
	} else {
		n, err = io.ReadFull(c.Conn, p[:payloadLen])
		if err != nil {
			return
		}
	}
	destination = destination.Unwrap()
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	return
}

func (c *StreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = c.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err == nil {
		n = len(p)
	}
	return
}

func (c *StreamPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	length, err := readStreamPacketLength(c.Conn)
	if err != nil {
		return
	}
	_, err = buffer.ReadFullFrom(c.Conn, int(length))
	if err != nil {
		return
	}
	return decodeStreamPacketAddress(buffer, length)
}

func (c *StreamPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if destination.IsFqdn() {
		return E.Extend(ErrFqdnUnsupported, destination.Fqdn)
	}
	addrLen := AddressSerializer.AddrPortLen(destination)
	if addrLen+buffer.Len() > math.MaxUint16 {
		return ErrSegmentTooLarge
	}
	headerLen := streamPacketLengthSize + addrLen
	if c.writer == nil {
		headerLen += buffer.Len()
	}
	headerBufferLen := headerLen
	if c.writer == nil {
		headerBufferLen += buffer.Len()
	}
	header := buf.NewSize(headerBufferLen)
	defer header.Release()
	binary.BigEndian.PutUint16(header.Extend(streamPacketLengthSize), uint16(addrLen+buffer.Len()))
	err := AddressSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	if c.writer == nil {
		common.Must1(header.Write(buffer.Bytes()))
		err = common.Error(c.Conn.Write(header.Bytes()))
		return err
	}
	return c.writer.WriteVectorised([]*buf.Buffer{header, buffer})
}

func (c *StreamPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *StreamPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	length, err := readStreamPacketLength(c.Conn)
	if err != nil {
		return
	}
	buffer = c.readWaitOptions.NewPacketBuffer()
	_, err = buffer.ReadFullFrom(c.Conn, int(length))
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	destination, err = decodeStreamPacketAddress(buffer, length)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	c.readWaitOptions.PostReturn(buffer)
	return
}

func decodeStreamPacketAddress(buffer *buf.Buffer, length uint16) (M.Socksaddr, error) {
	destination, err := AddressSerializer.ReadAddrPort(buffer)
	if err != nil {
		return M.Socksaddr{}, ErrInvalidSegment
	}
	if AddressSerializer.AddrPortLen(destination) > int(length) {
		return M.Socksaddr{}, ErrInvalidSegment
	}
	return destination.Unwrap(), nil
}

func readStreamPacketLength(reader io.Reader) (uint16, error) {
	var lengthBuffer [streamPacketLengthSize]byte
	_, err := io.ReadFull(reader, lengthBuffer[:])
	if err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lengthBuffer[:])
	if length == 0 {
		return 0, ErrEmptySegment
	}
	return length, nil
}

func (c *StreamPacketConn) FrontHeadroom() int {
	return streamPacketLengthSize + M.MaxIPSocksaddrLength
}

func (c *StreamPacketConn) ReaderOverhead() int {
	return M.MaxIPSocksaddrLength
}

func (c *StreamPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *StreamPacketConn) Upstream() any {
	return c.Conn
}
