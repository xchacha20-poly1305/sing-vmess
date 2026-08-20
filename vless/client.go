package vless

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless/encryption"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type Client struct {
	key    [16]byte
	flow   string
	logger logger.Logger

	encryption *encryption.Client
}

func NewClient(ctx context.Context, userId string, flow string, encryptionOptions string, logger logger.Logger) (*Client, error) {
	user, err := uuid.FromString(userId)
	if err != nil {
		user = uuid.NewV5(uuid.Nil, userId)
	}
	switch flow {
	case "", "xtls-rprx-vision":
	default:
		return nil, E.New("unsupported flow: " + flow)
	}
	var encryptionClient *encryption.Client
	switch encryptionOptions {
	case "", "none":
	default:
		xorMode, seconds, nfsPKeysBytes, paddings, err := encryption.ParseEncryption(encryptionOptions)
		if err != nil {
			return nil, err
		}
		encryptionClient, err = encryption.NewClient(ctx, nfsPKeysBytes, xorMode, seconds, paddings)
		if err != nil {
			return nil, err
		}
		var aeadType string
		if encryption.HasAESGCMHardwareSupport {
			aeadType = "aes"
		} else {
			aeadType = "chacha20"
		}
		logger.Info("Using encryption client with AEAD: ", aeadType)
	}
	return &Client{user, flow, logger, encryptionClient}, nil
}

func (c *Client) prepareConn(conn net.Conn, tlsConn net.Conn) (net.Conn, error) {
	if c.flow == FlowVision {
		protocolConn, err := NewVisionConn(conn, tlsConn, c.key, c.logger)
		if err != nil {
			return nil, E.Cause(err, "initialize vision")
		}
		conn = protocolConn
	}
	return conn, nil
}

func (c *Client) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	tlsConn := conn
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	remoteConn := NewConn(conn, c.key, vmess.CommandTCP, destination, c.flow)
	protocolConn, err := c.prepareConn(remoteConn, tlsConn)
	if err != nil {
		return nil, err
	}
	return protocolConn, common.Error(remoteConn.Write(nil))
}

func (c *Client) DialEarlyConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	tlsConn := conn
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	return c.prepareConn(NewConn(conn, c.key, vmess.CommandTCP, destination, c.flow), tlsConn)
}

func (c *Client) DialPacketConn(conn net.Conn, destination M.Socksaddr) (*PacketConn, error) {
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	serverConn := &PacketConn{Conn: conn, key: c.key, destination: destination, flow: c.flow}
	return serverConn, common.Error(serverConn.Write(nil))
}

func (c *Client) DialEarlyPacketConn(conn net.Conn, destination M.Socksaddr) (*PacketConn, error) {
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	return &PacketConn{Conn: conn, key: c.key, destination: destination, flow: c.flow}, nil
}

func (c *Client) DialStreamPacketAddrConn(conn net.Conn, destination M.Socksaddr) (*packetaddr.StreamPacketConn, error) {
	if destination.IsFqdn() {
		return nil, E.Extend(packetaddr.ErrFqdnUnsupported, destination.Fqdn)
	}
	streamConn, err := c.DialConn(conn, M.Socksaddr{Fqdn: packetaddr.StreamPacketMagicAddress})
	if err != nil {
		return nil, err
	}
	return packetaddr.NewStreamConn(streamConn, destination), nil
}

func (c *Client) DialEarlyStreamPacketAddrConn(conn net.Conn, destination M.Socksaddr) (*packetaddr.StreamPacketConn, error) {
	if destination.IsFqdn() {
		return nil, E.Extend(packetaddr.ErrFqdnUnsupported, destination.Fqdn)
	}
	streamConn, err := c.DialEarlyConn(conn, M.Socksaddr{Fqdn: packetaddr.StreamPacketMagicAddress})
	if err != nil {
		return nil, err
	}
	return packetaddr.NewStreamConn(streamConn, destination), nil
}

func (c *Client) DialXUDPPacketConn(conn net.Conn, destination M.Socksaddr) (vmess.PacketConn, error) {
	tlsConn := conn
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	remoteConn := NewConn(conn, c.key, vmess.CommandTCP, destination, c.flow)
	protocolConn, err := c.prepareConn(remoteConn, tlsConn)
	if err != nil {
		return nil, err
	}
	return vmess.NewXUDPConn(protocolConn, destination), common.Error(remoteConn.Write(nil))
}

func (c *Client) DialEarlyXUDPPacketConn(conn net.Conn, destination M.Socksaddr) (vmess.PacketConn, error) {
	tlsConn := conn
	if c.encryption != nil {
		var err error
		conn, err = c.encryption.Handshake(conn)
		if err != nil {
			return nil, err
		}
	}
	remoteConn := NewConn(conn, c.key, vmess.CommandMux, destination, c.flow)
	protocolConn, err := c.prepareConn(remoteConn, tlsConn)
	if err != nil {
		return nil, err
	}
	return vmess.NewXUDPConn(protocolConn, destination), common.Error(remoteConn.Write(nil))
}

var (
	_ N.EarlyReader = (*Conn)(nil)
	_ N.EarlyWriter = (*Conn)(nil)
)

type Conn struct {
	N.ExtendedConn
	request        Request
	requestWritten bool
	responseRead   bool
}

func NewConn(conn net.Conn, uuid [16]byte, command byte, destination M.Socksaddr, flow string) *Conn {
	return &Conn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		request: Request{
			UUID:        uuid,
			Command:     command,
			Destination: destination,
			Flow:        flow,
		},
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.responseRead {
		err = ReadResponse(c.ExtendedConn)
		if err != nil {
			return
		}
		c.responseRead = true
	}
	return c.ExtendedConn.Read(b)
}

func (c *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !c.responseRead {
		err := ReadResponse(c.ExtendedConn)
		if err != nil {
			return err
		}
		c.responseRead = true
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		err = WriteRequest(c.ExtendedConn, c.request, b)
		if err == nil {
			n = len(b)
		}
		c.requestWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.requestWritten {
		err := EncodeRequest(c.request, buf.With(buffer.ExtendHeader(RequestLen(c.request))))
		if err != nil {
			return err
		}
		c.requestWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *Conn) ReaderReplaceable() bool {
	return c.responseRead
}

func (c *Conn) WriterReplaceable() bool {
	return c.requestWritten
}

func (c *Conn) NeedHandshakeForRead() bool {
	return !c.responseRead
}

func (c *Conn) NeedHandshakeForWrite() bool {
	return !c.requestWritten
}

func (c *Conn) FrontHeadroom() int {
	if c.requestWritten {
		return 0
	}
	return RequestLen(c.request)
}

func (c *Conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}

type PacketConn struct {
	net.Conn
	access         sync.Mutex
	key            [16]byte
	destination    M.Socksaddr
	flow           string
	requestWritten bool
	responseRead   bool
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	if !c.responseRead {
		err = ReadResponse(c.Conn)
		if err != nil {
			return
		}
		c.responseRead = true
	}
	var length uint16
	err = binary.Read(c.Conn, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if len(b) < int(length) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, b[:length])
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		c.access.Lock()
		if c.requestWritten {
			c.access.Unlock()
		} else {
			err = WritePacketRequest(c.Conn, Request{c.key, vmess.CommandUDP, c.destination, c.flow}, nil)
			if err == nil {
				n = len(b)
			}
			c.requestWritten = true
			c.access.Unlock()
		}
	}
	err = binary.Write(c.Conn, binary.BigEndian, uint16(len(b)))
	if err != nil {
		return
	}
	return c.Conn.Write(b)
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(dataLen))
	if !c.requestWritten {
		c.access.Lock()
		if c.requestWritten {
			c.access.Unlock()
		} else {
			err := WritePacketRequest(c.Conn, Request{c.key, vmess.CommandUDP, c.destination, c.flow}, buffer.Bytes())
			c.requestWritten = true
			c.access.Unlock()
			return err
		}
	}
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *PacketConn) FrontHeadroom() int {
	return 2
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.Conn
}
