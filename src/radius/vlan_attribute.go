/*
Copyright © 2024 Keytos alan@keytos.io

Tunnel attributes carry an RFC 2868 tag so that several tunnels in one
packet can be grouped. The tag is the first value octet. Tags 0x01
through 0x1F select a tunnel, and 0x00 means the tag is unused.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Type      |    Length     |      Tag      |     Value ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Tunnel-Type and Tunnel-Medium-Type are a tag plus a 24-bit enum.
Tunnel-Private-Group-ID is a tag plus a string. When the tag is unused
and the string's first byte is greater than 0x1F, RFC 2868 takes that
byte as the start of the string, so an untagged group id is the string
alone.

Egress-VLANID and Egress-VLAN-Name use a different indication, from
RFC 4675: 0x31 for a tagged VLAN and 0x32 for an untagged one.
Egress-VLANID is four octets, the indication followed by a 12-bit pad
of zero and a 12-bit VLAN id:

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Tag Indic.   |        Pad            |       VLANID          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	// RFC 2868: a tag of 0x00 is unused, and 0x01 through 0x1F name a tunnel.
	maxTunnelTag = 31

	// RFC 4675 writes the indication as an ASCII digit, not as an integer.
	egressVLANTagged   = 0x31
	egressVLANUntagged = 0x32
)

// splitOptionalTunnelTag separates a leading RFC 2868 tag from a CLI value.
// The tag is a decimal integer from 0 to 31 followed by a colon, as in
// "1:20". A value with no such prefix is untagged.
func splitOptionalTunnelTag(v string) (tag byte, rest string, tagged bool, err error) {
	colon := strings.IndexByte(v, ':')
	if colon <= 0 {
		return 0, v, false, nil
	}
	n, convErr := strconv.ParseUint(v[:colon], 10, 8)
	if convErr != nil || n > maxTunnelTag {
		return 0, v, false, nil
	}
	rest = v[colon+1:]
	if rest == "" {
		return 0, "", false, fmt.Errorf("missing value after tunnel tag %d", n)
	}
	return byte(n), rest, true, nil
}

func serializeTunnelEnumAttribute(t AttributeType, v string) (*Attribute, error) {
	tag, rest, _, err := splitOptionalTunnelTag(v)
	if err != nil {
		return nil, err
	}
	a := newEmptyAttribute(t, 4)
	if err := ParseAttributeEnumData(a.Value, t, rest); err != nil {
		return nil, err
	}
	// The enum occupies the low 24 bits. A value that spills into the tag
	// octet is not a legal RFC 2868 tunnel type or medium type.
	if a.Value[0] != 0 {
		return nil, fmt.Errorf("%s value does not fit in 24 bits: %s", t.String(), rest)
	}
	a.Value[0] = tag
	return a, nil
}

func serializeTunnelPrivateGroupId(v string) (*Attribute, error) {
	tag, rest, tagged, err := splitOptionalTunnelTag(v)
	if err != nil {
		return nil, err
	}
	if !tagged {
		return newAttribute(AttributeTypeTunnelPrivateGroupId, []byte(v)), nil
	}
	b := make([]byte, 1+len(rest))
	b[0] = tag
	copy(b[1:], rest)
	return newAttribute(AttributeTypeTunnelPrivateGroupId, b), nil
}

// splitEgressIndication separates an RFC 4675 indication from a CLI value.
// "tagged:" and "untagged:" select the indication. Any other value is left
// unchanged so an Egress-VLAN-Name written without a prefix keeps its
// previous encoding.
func splitEgressIndication(v string) (tag byte, rest string, indicated bool, err error) {
	switch {
	case strings.HasPrefix(v, "tagged:"):
		rest = strings.TrimPrefix(v, "tagged:")
		tag = egressVLANTagged
	case strings.HasPrefix(v, "untagged:"):
		rest = strings.TrimPrefix(v, "untagged:")
		tag = egressVLANUntagged
	default:
		return 0, v, false, nil
	}
	if rest == "" {
		return 0, "", false, fmt.Errorf("missing VLAN after the tag indication in %q", v)
	}
	return tag, rest, true, nil
}

func serializeEgressVlanId(v string) (*Attribute, error) {
	tag, rest, indicated, err := splitEgressIndication(v)
	if err != nil {
		return nil, err
	}
	if !indicated {
		return nil, fmt.Errorf("invalid Egress-VLANID %q: want tagged:<vlan> or untagged:<vlan>", v)
	}
	n, err := strconv.ParseUint(rest, 10, 12)
	if err != nil {
		return nil, fmt.Errorf("invalid Egress-VLANID %q: %w", v, err)
	}
	a := newEmptyAttribute(AttributeTypeEgressVlanId, 4)
	a.Value[0] = tag
	// The VLAN id is the low 12 bits. The 12 bits above it are the pad and
	// stay zero, which a value that fits in 12 bits guarantees.
	binary.BigEndian.PutUint16(a.Value[2:], uint16(n))
	return a, nil
}

func serializeEgressVlanName(v string) (*Attribute, error) {
	tag, name, indicated, err := splitEgressIndication(v)
	if err != nil {
		return nil, err
	}
	if !indicated {
		return newAttribute(AttributeTypeEgressVlanName, []byte(v)), nil
	}
	b := make([]byte, 1+len(name))
	b[0] = tag
	copy(b[1:], name)
	return newAttribute(AttributeTypeEgressVlanName, b), nil
}
