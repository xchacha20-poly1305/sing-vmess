package packetaddr

import (
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	SeqPacketMagicAddress    = "sp.packet-addr.v2fly.arpa"
	StreamPacketMagicAddress = "st.packet-addr.v2fly.arpa"
)

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x02, M.AddressFamilyIPv6),
)

var (
	ErrFqdnUnsupported = E.New("packetaddr: fqdn unsupported")
	ErrEmptySegment    = E.New("packetaddr: empty stream segment")
	ErrSegmentTooLarge = E.New("packetaddr: stream segment too large")
	ErrInvalidSegment  = E.New("packetaddr: invalid stream segment")
)
