package encryption

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"

	"lukechampine.com/blake3"
)

const (
	// PFS key exchange related lengths
	PfsKeyExchangeLength = EncryptedLengthSize + mlkem.EncapsulationKeySize768 + X25519KeySize + AEADTagLength // 18 + 1184 + 32 + 16
	PfsKeySize           = Hash256Length + Hash256Length                                                       // ML-KEM-768 shared key + X25519 shared key
	PfsPublicKeyLength   = mlkem.EncapsulationKeySize768 + X25519KeySize                                       // 1184 + 32

	EncryptedPfsPublicKeyLength = mlkem.CiphertextSize768 + X25519KeySize + AEADTagLength // 1088 + 32 + 16
	EncryptedTicketLength       = Hash256Length                                           // 32
)

type Client struct {
	useAes        bool
	nfsPKeys      []any
	nfsPKeysBytes [][]byte
	hash32s       [][Hash256Length]byte
	relaysLength  int
	xorMode       XorMode
	seconds       uint32
	paddingLens   [][3]int
	paddingGaps   [][3]int

	ticketAccess sync.RWMutex
	timeFunc     func() time.Time
	expireAt     time.Time
	pfsKey       []byte
	ticket       []byte
}

func NewClient(ctx context.Context, nfsPKeysBytes [][]byte, xorMode XorMode, seconds uint32, paddings []string) (client *Client, err error) {
	if len(nfsPKeysBytes) == 0 {
		return nil, E.New("empty nfsPKeysBytes")
	}
	client = &Client{
		useAes:        useAesFromContext(ctx),
		nfsPKeys:      make([]any, len(nfsPKeysBytes)),
		nfsPKeysBytes: nfsPKeysBytes,
		hash32s:       make([][Hash256Length]byte, len(nfsPKeysBytes)),
		xorMode:       xorMode,
		seconds:       seconds,
		timeFunc:      ntp.TimeFuncFromContext(ctx),
	}
	if client.timeFunc == nil {
		client.timeFunc = time.Now
	}
	for i, keysByte := range nfsPKeysBytes {
		switch len(keysByte) {
		case X25519KeySize:
			if client.nfsPKeys[i], err = ecdh.X25519().NewPublicKey(keysByte); err != nil {
				return
			}
			client.relaysLength += X25519KeySize + Hash256Length
		case mlkem.EncapsulationKeySize768:
			if client.nfsPKeys[i], err = mlkem.NewEncapsulationKey768(keysByte); err != nil {
				return
			}
			client.relaysLength += mlkem.CiphertextSize768 + Hash256Length
		default:
			return nil, E.New("invalid nfsPKeysBytes size ", len(keysByte), " of ", i)
		}
		client.hash32s[i] = blake3.Sum256(keysByte)
	}
	client.relaysLength -= Hash256Length
	client.paddingLens, client.paddingGaps, err = parsePadding(paddings)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ParseEncryption(raw string) (xorMode XorMode, seconds uint32, nfsPKeysBytes [][]byte, paddings []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 4 {
		err = E.New("invalid encryption parts: ", len(parts))
		return
	}

	encryptionType := parts[0]
	if encryptionType != "mlkem768x25519plus" {
		err = E.New("unknown encryption type: ", encryptionType)
		return
	}

	rawXorMode := parts[1]
	switch rawXorMode {
	case "native":
		xorMode = XorModeNative
	case "xorpub":
		xorMode = XorModeXorPub
	case "random":
		xorMode = XorModeRandom
	default:
		err = E.New("unknown encryption mode: ", rawXorMode)
		return
	}

	rttPart := parts[2]
	switch rttPart {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		err = E.New("unknown rtt: ", rttPart)
		return
	}

	keyParts := parts[3:]
	for i, key := range keyParts {
		if len(key) < 20 {
			paddings = append(paddings, key)
			continue
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			err = E.New("decode base64 of key ", i, ": ", key)
			return
		}
		switch len(decoded) {
		case X25519KeySize:
		case mlkem.EncapsulationKeySize768:
		default:
			err = E.New("invalid key length ", len(decoded), " of ", i)
			return
		}
		nfsPKeysBytes = append(nfsPKeysBytes, decoded)
	}

	return
}

func (c *Client) Handshake(conn net.Conn) (commonConn *CommonConn, err error) {
	commonConn = NewCommonConn(conn, c.useAes)

	ivAndRelaysLength := IVLength + c.relaysLength
	paddingLength, paddingLens, paddingGaps := createPadding(c.paddingLens, c.paddingGaps)
	clientHello := buf.NewSize(ivAndRelaysLength + PfsKeyExchangeLength + paddingLength)
	defer clientHello.Release()

	iv := clientHello.WriteRandom(IVLength)
	relays := clientHello.Extend(c.relaysLength)
	pfsKeyExchange := clientHello.Extend(PfsKeyExchangeLength)
	padding := clientHello.Extend(paddingLength)
	var nfsKey []byte
	var lastCTR cipher.Stream
	for i, key := range c.nfsPKeys {
		var index int
		switch key.(type) {
		case *ecdh.PublicKey:
			x25519Key := key.(*ecdh.PublicKey)
			privateKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			copy(relays, privateKey.PublicKey().Bytes())
			nfsKey, err = privateKey.ECDH(x25519Key)
			if err != nil {
				return nil, err
			}
			index = X25519KeySize
		case *mlkem.EncapsulationKey768:
			mlkemKey := key.(*mlkem.EncapsulationKey768)
			var ciphertext []byte
			nfsKey, ciphertext = mlkemKey.Encapsulate()
			copy(relays, ciphertext)
			index = mlkem.CiphertextSize768
		default:
			panic("invalid key type")
		}
		if c.xorMode != XorModeNative { // this xor can (others can't) be recovered by client's config, revealing an X25519 public key / ML-KEM-768 ciphertext, that's why "native" values
			NewCTR(c.nfsPKeysBytes[i], iv).XORKeyStream(relays, relays[:index]) // make X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:Hash256Length]) // make this relay irreplaceable
		}
		if i == len(c.nfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], c.hash32s[i+1][:])
		relays = relays[index+Hash256Length:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey, commonConn.useAES)

	if c.seconds > 0 {
		c.ticketAccess.RLock()
		if c.timeFunc().Before(c.expireAt) {
			commonConn.client = c
			commonConn.unitedKey = append(c.pfsKey, nfsKey...) // different unitedKey for each connection
			nfsAEAD.Seal(clientHello.To(ivAndRelaysLength), nil, binary.BigEndian.AppendUint16(nil, EncryptedTicketLength), nil)
			nfsAEAD.Seal(clientHello.To(ivAndRelaysLength+EncryptedLengthSize), nil, c.ticket, nil)
			c.ticketAccess.RUnlock()
			commonConn.preWrite = bytes.Clone(clientHello.To(ivAndRelaysLength + EncryptedLengthSize + EncryptedTicketLength))
			commonConn.aead = NewAEAD(clientHello.Range(ivAndRelaysLength+EncryptedLengthSize, ivAndRelaysLength+EncryptedLengthSize+EncryptedTicketLength), commonConn.unitedKey, commonConn.useAES)
			if c.xorMode == XorModeRandom {
				commonConn.conn = NewXorConn(conn, NewCTR(commonConn.unitedKey, iv), nil, len(commonConn.preWrite), IVLength)
			}
			return commonConn, nil
		}
		c.ticketAccess.RUnlock()
	}

	nfsAEAD.Seal(pfsKeyExchange[:0], nil, binary.BigEndian.AppendUint16(nil, uint16(PfsKeyExchangeLength-EncryptedLengthSize)), nil)
	mlkem768DKey, _ := mlkem.GenerateKey768()
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsAEAD.Seal(pfsKeyExchange[:EncryptedLengthSize], nil, pfsPublicKey, nil)

	nfsAEAD.Seal(padding[:0], nil, binary.BigEndian.AppendUint16(nil, uint16(paddingLength-EncryptedLengthSize)), nil)
	nfsAEAD.Seal(padding[:EncryptedLengthSize], nil, padding[EncryptedLengthSize:paddingLength-AEADTagLength], nil)

	clientHelloBytes := clientHello.Bytes()
	paddingLens[0] += ivAndRelaysLength + PfsKeyExchangeLength
	for i, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if l > 0 {
			_, err = conn.Write(clientHelloBytes[:l])
			if err != nil {
				return nil, err
			}
			clientHelloBytes = clientHelloBytes[l:]
		}
		if len(paddingGaps) > i {
			time.Sleep(paddingGaps[i])
		}
	}

	encryptedPfsPublicKey := buf.NewSize(EncryptedPfsPublicKeyLength)
	defer encryptedPfsPublicKey.Release()
	_, err = encryptedPfsPublicKey.ReadFullFrom(conn, encryptedPfsPublicKey.Cap())
	if err != nil {
		return nil, err
	}
	_, err = nfsAEAD.Open(encryptedPfsPublicKey.Index(0), maxNonce, encryptedPfsPublicKey.Bytes(), nil)
	if err != nil {
		return nil, E.Cause(err, "open encryptedPfsPublicKey")
	}
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey.To(mlkem.CiphertextSize768))
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey.Range(mlkem.CiphertextSize768, mlkem.CiphertextSize768+X25519KeySize))
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := append(mlkem768Key, x25519Key...)
	commonConn.unitedKey = append(pfsKey, nfsKey...)
	commonConn.aead = NewAEAD(pfsPublicKey, commonConn.unitedKey, commonConn.useAES)
	commonConn.peerAEAD = NewAEAD(encryptedPfsPublicKey.To(mlkem.CiphertextSize768+X25519KeySize), commonConn.unitedKey, commonConn.useAES)

	encryptedTicket := make([]byte, EncryptedTicketLength)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	if _, err := commonConn.peerAEAD.Open(encryptedTicket[:0], nil, encryptedTicket, nil); err != nil {
		return nil, err
	}
	seconds := binary.BigEndian.Uint16(encryptedTicket)

	if c.seconds > 0 && seconds > 0 {
		c.ticketAccess.Lock()
		c.expireAt = c.timeFunc().Add(time.Duration(seconds) * time.Second)
		c.pfsKey = pfsKey
		c.ticket = encryptedTicket[:IVLength]
		c.ticketAccess.Unlock()
	}

	encryptedLength := make([]byte, EncryptedLengthSize)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := commonConn.peerAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(encryptedLength[:2])
	commonConn.peerPadding = make([]byte, length) // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern

	if c.xorMode == XorModeRandom {
		commonConn.conn = NewXorConn(conn, NewCTR(commonConn.unitedKey, iv), NewCTR(commonConn.unitedKey, encryptedTicket[:IVLength]), 0, int(length))
	}
	return commonConn, nil
}
