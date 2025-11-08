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
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"

	"lukechampine.com/blake3"
)

type ServiceSession struct {
	pfsKey  []byte
	nfsKeys sync.Map
}

type Service struct {
	ctx    context.Context
	closed chan struct{}

	nfsSKeys      []any
	nfsPKeysBytes [][]byte
	hash32s       [][Hash256Length]byte
	relaysLength  int
	xorMode       XorMode
	secondsFrom   int64
	secondsTo     int64
	paddingLens   [][3]int
	paddingGaps   [][3]int

	sessionAccess sync.RWMutex
	timeFunc      func() time.Time
	lasts         map[int64][TicketLength]byte
	tickets       [][TicketLength]byte
	sessions      map[[TicketLength]byte]*ServiceSession
}

func NewService(ctx context.Context, nfsSKeysBytes [][]byte, xorMode XorMode, secondsFrom, secondsTo int64, padding []string) (*Service, error) {
	if len(nfsSKeysBytes) == 0 {
		return nil, E.New("nfsSKeysBytes must not be empty")
	}
	service := &Service{
		ctx:           ctx,
		nfsSKeys:      make([]any, len(nfsSKeysBytes)),
		nfsPKeysBytes: make([][]byte, len(nfsSKeysBytes)),
		hash32s:       make([][Hash256Length]byte, len(nfsSKeysBytes)),
		xorMode:       xorMode,
		secondsFrom:   secondsFrom,
		secondsTo:     secondsTo,
		timeFunc:      ntp.TimeFuncFromContext(ctx),
	}
	if service.timeFunc == nil {
		service.timeFunc = time.Now
	}
	for i, keyBytes := range nfsSKeysBytes {
		switch len(keyBytes) {
		case X25519KeySize:
			key, err := ecdh.X25519().NewPrivateKey(keyBytes)
			if err != nil {
				return nil, E.Cause(err, "initialize x25519 private key of ", i)
			}
			service.nfsSKeys[i] = key
			service.nfsPKeysBytes[i] = key.PublicKey().Bytes()
			service.relaysLength += X25519KeySize + Hash256Length
		case mlkem.SeedSize:
			key, err := mlkem.NewDecapsulationKey768(keyBytes)
			if err != nil {
				return nil, E.Cause(err, "initialize mlkem decapsulation key of ", i)
			}
			service.nfsSKeys[i] = key
			service.nfsPKeysBytes[i] = key.EncapsulationKey().Bytes()
			service.relaysLength += mlkem.CiphertextSize768 + Hash256Length
		default:
			return nil, E.New("invalid key size: ", len(keyBytes))
		}
		service.hash32s[i] = blake3.Sum256(service.nfsPKeysBytes[i])
	}
	service.relaysLength -= Hash256Length
	var err error
	service.paddingLens, service.paddingGaps, err = parsePadding(padding)
	if err != nil {
		return nil, err
	}
	return service, nil
}

func ParseDecryption(raw string) (xorMode XorMode, secondsFrom, secondsTo int64, nfsKeyBytes [][]byte, paddings []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 4 {
		err = E.New("malformed decryption")
		return
	}

	decryptionType := parts[0]
	if decryptionType != "mlkem768x25519plus" {
		err = E.New("unknown decryption type: ", decryptionType)
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
		err = E.New("unknown xor mode: ", rawXorMode)
		return
	}

	rawTimes := parts[2]
	timeParts := strings.SplitN(strings.TrimSuffix(rawTimes, "s"), "-", 2)
	rawFrom := timeParts[0]
	from, err := strconv.Atoi(rawFrom)
	if err != nil {
		err = E.Cause(err, "parse seconds from: ", rawFrom)
		return
	}
	secondsFrom = int64(from)
	if len(timeParts) == 2 {
		rawTo := timeParts[1]
		var to int
		to, err = strconv.Atoi(timeParts[1])
		if err != nil {
			err = E.Cause(err, "parse seconds to: ", rawTo)
			return
		}
		secondsTo = int64(to)
	}

	paddingParts := parts[3:]
	for i, rawPadding := range paddingParts {
		if len(rawPadding) < 20 {
			paddings = append(paddings, rawPadding)
			continue
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(rawPadding)
		if err != nil {
			err = E.Cause(err, "base64 decode ", i, ": ", rawPadding)
			return
		}
		switch len(decoded) {
		case X25519KeySize:
		case mlkem.SeedSize:
		default:
			err = E.New("invalid key size ", len(decoded), " of ", i)
			return
		}
		nfsKeyBytes = append(nfsKeyBytes, decoded)
	}

	return
}

func (s *Service) Start() error {
	if s.allow0Rtt() {
		go s.loopCleanLegacySessions()
	}
	return nil
}

func (s *Service) loopCleanLegacySessions() {
	s.closed = make(chan struct{})
	s.lasts = make(map[int64][TicketLength]byte)
	s.tickets = make([][TicketLength]byte, 0, 1024)
	s.sessions = make(map[[TicketLength]byte]*ServiceSession)

	const CLeanDuration = 1 * time.Minute
	timer := time.NewTimer(CLeanDuration)
	for {
		timer.Reset(CLeanDuration)
		select {
		case <-s.ctx.Done():
			return
		case <-s.closed:
			return
		case <-timer.C:
		}
		s.sessionAccess.Lock()
		minute := s.timeFunc().Unix() / 60
		last := s.lasts[minute]
		delete(s.lasts, minute)
		delete(s.lasts, minute-1) // for insurance
		if !common.IsEmpty(last) {
			for i, ticker := range s.tickets {
				delete(s.sessions, ticker)
				if ticker == last {
					s.tickets = s.tickets[i+1:]
					break
				}
			}
		}
		s.sessionAccess.Unlock()
	}
}

func (s *Service) allow0Rtt() bool {
	return s.secondsFrom > 0 || s.secondsTo > 0
}

func (s *Service) Close() error {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if s.closed != nil {
		close(s.closed)
	}
	return nil
}

func (s *Service) Handshake(conn net.Conn, fallback *[]byte) (*CommonConn, error) {
	commonConn := NewCommonConn(conn, true)

	ivAndRelays := buf.NewSize(IVLength + s.relaysLength)
	defer ivAndRelays.Release()
	_, err := ivAndRelays.ReadFullFrom(conn, ivAndRelays.Cap())
	if err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, ivAndRelays.Bytes()...)
	}
	iv := ivAndRelays.To(IVLength)
	relays := ivAndRelays.From(IVLength)
	var (
		nfsKey  []byte
		lastCTR cipher.Stream
	)
	for i, key := range s.nfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:EncryptedTicketLength]) // recover this relay
		}
		var index int
		switch key.(type) {
		case *ecdh.PrivateKey:
			index = X25519KeySize
		case *mlkem.DecapsulationKey768:
			index = mlkem.CiphertextSize768
		default:
			panic("unexcepted key type")
		}
		if s.xorMode != XorModeNative {
			NewCTR(s.nfsPKeysBytes[i], iv).XORKeyStream(relays, relays[:index]) // we don't use buggy elligator2, because we have PSK :)
		}
		switch key.(type) {
		case *ecdh.PrivateKey:
			publicKey, err := ecdh.X25519().NewPublicKey(relays[:index])
			if err != nil {
				return nil, E.Cause(err, "initialize x25519 public key of ", i)
			}
			if publicKey.Bytes()[31] > 127 { // we just don't want the observer can change even one bit without breaking the connection, though it has nothing to do with security
				return nil, E.New("x25519 key ", i, ": the highest bit of the last byte of the peer-sent X25519 public key is not 0")
			}
			x25519Key := key.(*ecdh.PrivateKey)
			nfsKey, err = x25519Key.ECDH(publicKey)
			if err != nil {
				return nil, E.Cause(err, "create nfs key from x25519 public key of ", i)
			}
		case *mlkem.DecapsulationKey768:
			mlkemKey := key.(*mlkem.DecapsulationKey768)
			nfsKey, err = mlkemKey.Decapsulate(relays[:index])
			if err != nil {
				return nil, E.Cause(err, "create nfs key from mlkem public key of ", i)
			}
		default:
			panic("unexcepted key type")
		}
		if i == len(s.nfsSKeys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:Hash256Length])
		if !bytes.Equal(relays[:Hash256Length], s.hash32s[i+1][:]) {
			return nil, E.New("unexpected hash 32: ", fmt.Sprint(relays[:Hash256Length]))
		}
		relays = relays[Hash256Length:]
	}
	nfsAead := NewAEAD(iv, nfsKey, commonConn.useAES)

	encryptedLength := make([]byte, 2+nfsAead.Overhead())
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, encryptedLength...)
	}
	decryptedLength := make([]byte, 2)
	if _, err0 := nfsAead.Open(decryptedLength[:0], nil, encryptedLength, nil); err0 != nil {
		commonConn.useAES = !commonConn.useAES
		nfsAead = NewAEAD(iv, nfsKey, commonConn.useAES)
		if _, err1 := nfsAead.Open(decryptedLength[:0], nil, encryptedLength, nil); err1 != nil {
			return nil, E.Cause(E.Errors(err0, err1), "try decrypt length with aes and chacha20")
		}
	}
	if fallback != nil {
		*fallback = nil
	}
	length := binary.BigEndian.Uint16(decryptedLength)

	if length == EncryptedTicketLength {
		if !s.allow0Rtt() {
			return nil, E.New("0-rtt is forbidden")
		}
		encryptedTicket := make([]byte, EncryptedTicketLength)
		_, err = io.ReadFull(conn, encryptedTicket)
		if err != nil {
			return nil, err
		}
		ticket, err := nfsAead.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, E.Cause(err, "open encrypted ticket")
		}
		s.sessionAccess.Lock()
		session := s.sessions[[TicketLength]byte(ticket)]
		s.sessionAccess.Unlock()
		if session == nil {
			noises := buf.NewSize(int(randBetween(1279, 2279))) // matches 1-RTT's server hello length for "random", though it is not important, just for example
			defer noises.Release()
			// Prevent valid header
			header := noises.To(HeaderLength)
			var err error
			for err == nil {
				rand.Read(header)
				_, err = decodeHeader(header)
			}
			noises.Truncate(HeaderLength)
			noises.ReadFullFrom(rand.Reader, noises.FreeLen())
			_, _ = conn.Write(noises.Bytes()) // make client do new handshake
			return nil, E.New("expired ticket")
		}
		if _, loaded := session.nfsKeys.LoadOrStore([EncryptedTicketLength]byte(nfsKey), true); loaded { // prevents bad client also
			return nil, E.New("replay detected!")
		}
		commonConn.unitedKey = append(session.pfsKey, nfsKey...) // the same nfsKey links the upload & download (prevents server -> client's another request)
		commonConn.preWrite = make([]byte, TicketLength)
		rand.Read(commonConn.preWrite) // always trust yourself, not the client (also prevents being parsed as TLS thus causing false interruption for "native" and "xorpub")
		commonConn.aead = NewAEAD(commonConn.preWrite, commonConn.unitedKey, commonConn.useAES)
		commonConn.peerAEAD = NewAEAD(encryptedTicket, commonConn.unitedKey, commonConn.useAES) // unchangeable ctx (prevents server -> server), and different ctx length for upload / download (prevents client -> client)
		if s.xorMode == XorModeRandom {
			commonConn.conn = NewXorConn(conn, NewCTR(commonConn.unitedKey, commonConn.preWrite), NewCTR(commonConn.unitedKey, iv), 16, 0) // it doesn't matter if the attacker sends client's iv back to the client
		}
		return commonConn, nil
	}

	if length < EncryptedPfsPublicKeyLength { // client may send more public keys in the future's version
		return nil, io.ErrUnexpectedEOF
	}
	encryptedPfsPublicKey := buf.NewSize(int(length))
	defer encryptedPfsPublicKey.Release()
	_, err = encryptedPfsPublicKey.ReadFullFrom(conn, encryptedPfsPublicKey.FreeLen())
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedPfsPublicKey.Index(0), nil, encryptedPfsPublicKey.Bytes(), nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted public key")
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey.To(mlkem.EncapsulationKeySize768))
	if err != nil {
		return nil, E.Cause(err, "create mlkem768 key from encryptedPfsPublicKey")
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519Key, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey.Range(mlkem.EncapsulationKeySize768, mlkem.EncapsulationKeySize768+X25519KeySize))
	if err != nil {
		return nil, E.Cause(err, "create x25519 public key from encryptedPfsPublicKey")
	}
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	x25519Key, err := x25519SKey.ECDH(peerX25519Key)
	if err != nil {
		return nil, E.Cause(err, "x25519 ecdh")
	}
	pfsKey := append(mlkem768Key, x25519Key...)
	pfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	commonConn.unitedKey = append(pfsKey, nfsKey...)
	commonConn.aead = NewAEAD(pfsPublicKey, commonConn.unitedKey, commonConn.useAES)
	commonConn.peerAEAD = NewAEAD(encryptedPfsPublicKey.To(mlkem.EncapsulationKeySize768+EncryptedTicketLength), commonConn.unitedKey, commonConn.useAES)

	ticket := [TicketLength]byte{}
	rand.Read(ticket[:])
	var seconds int64
	if s.secondsTo == 0 {
		seconds = s.secondsFrom * randBetween(50, 100) / 100
	} else {
		seconds = randBetween(s.secondsFrom, s.secondsTo)
	}
	binary.BigEndian.PutUint16(ticket[:], uint16(seconds))
	if seconds > 0 {
		s.sessionAccess.Lock()
		s.lasts[(s.timeFunc().Unix()+max(s.secondsFrom, s.secondsTo))/60+2] = ticket
		s.tickets = append(s.tickets, ticket)
		s.sessions[ticket] = &ServiceSession{pfsKey: pfsKey}
		s.sessionAccess.Unlock()
	}

	paddingLength, paddingLens, paddingGaps := createPadding(s.paddingLens, s.paddingGaps)
	serverHello := buf.NewSize(EncryptedPfsPublicKeyLength + EncryptedTicketLength + paddingLength)
	defer serverHello.Release()
	nfsAead.Seal(serverHello.Index(0), maxNonce, pfsPublicKey, nil)
	commonConn.aead.Seal(serverHello.Index(EncryptedPfsPublicKeyLength), nil, ticket[:], nil)
	const paddingIndex = EncryptedPfsPublicKeyLength + EncryptedTicketLength
	commonConn.aead.Seal(serverHello.Index(paddingIndex), nil, binary.BigEndian.AppendUint16(nil, uint16(paddingLength-18)), nil)
	commonConn.aead.Seal(serverHello.Index(paddingIndex+EncryptedLengthSize), nil, serverHello.Range(paddingIndex+18, paddingIndex+paddingLength-16), nil)
	serverHello.Truncate(serverHello.Cap())

	paddingLens[0] += paddingIndex
	for i, paddingLen := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if paddingLen > 0 {
			_, err = conn.Write(serverHello.To(paddingLen))
			if err != nil {
				return nil, E.Cause(err, "write padding ", i)
			}
			serverHello.Advance(paddingLen)
		}
		if len(paddingGaps) > i {
			time.Sleep(paddingGaps[i])
		}
	}

	// important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedLength[:0], nil, encryptedLength, nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted length")
	}
	encryptedPadding := buf.NewSize(int(binary.BigEndian.Uint16(encryptedLength)))
	defer encryptedPadding.Release()
	_, err = encryptedPadding.ReadFullFrom(conn, encryptedPadding.Cap())
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedPadding.Index(0), nil, encryptedPadding.Bytes(), nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted padding")
	}

	if s.xorMode == XorModeRandom {
		commonConn.conn = NewXorConn(conn, NewCTR(commonConn.unitedKey, ticket[:]), NewCTR(commonConn.unitedKey, iv), 0, 0)
	}

	return commonConn, nil
}
