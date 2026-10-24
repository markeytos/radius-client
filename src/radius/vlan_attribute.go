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

func serializeTunnelEnumAttribute(k AttributeKey, v string) (*Attribute, error) {
	if err := tunnelTagInRange(k); err != nil {
		return nil, err
	}
	// Checked on the full parsed number, before it is narrowed to the 24-bit
	// enum. A value such as 2^32+13 would otherwise wrap to Virtual LAN.
	if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0xFFFFFF {
		return nil, fmt.Errorf("%s value %s does not fit in 24 bits; set the tag on the name, for example %s#1:<value>", k.Type.String(), v, k.Type.String())
	}
	a := newEmptyAttribute(k.Type, 4)
	if err := ParseAttributeEnumData(a.Value, k.Type, v); err != nil {
		return nil, err
	}
	if a.Value[0] != 0 {
		return nil, fmt.Errorf("%s value %s does not fit in 24 bits; set the tag on the name, for example %s#1:Virtual LAN", k.Type.String(), v, k.Type.String())
	}
	if k.HasTunnelTag {
		a.Value[0] = k.TunnelTag
	}
	return a, nil
}

func serializeTunnelPrivateGroupId(k AttributeKey, v string) (*Attribute, error) {
	if err := tunnelTagInRange(k); err != nil {
		return nil, err
	}
	if !k.HasTunnelTag {
		return newAttribute(AttributeTypeTunnelPrivateGroupId, []byte(v)), nil
	}
	return newTaggedStringAttribute(AttributeTypeTunnelPrivateGroupId, k.TunnelTag, v)
}

// splitEgressIndication separates an RFC 4675 indication from a CLI value.
// "tagged:" and "untagged:" select the indication. Any other value is left
// unchanged so an Egress-VLAN-Name written without a prefix keeps its
// previous encoding.
func splitEgressIndication(v string) (tag byte, rest string, indicated bool, err error) {
	var found bool
	if rest, found = strings.CutPrefix(v, "tagged:"); found {
		tag = egressVLANTagged
	} else if rest, found = strings.CutPrefix(v, "untagged:"); found {
		tag = egressVLANUntagged
	} else {
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
	return newTaggedStringAttribute(AttributeTypeEgressVlanName, tag, name)
}

func tunnelTagInRange(k AttributeKey) error {
	if k.HasTunnelTag && k.TunnelTag > maxTunnelTag {
		return fmt.Errorf("invalid tunnel tag %d", k.TunnelTag)
	}
	return nil
}

// newTaggedStringAttribute prefixes a one-byte tag. The tag counts toward the
// 253-byte attribute limit, so a value that was legal on its own can become
// too long once the tag is added. That is an error, same as a vendor attribute
// that does not fit, rather than a panic from newAttribute.
func newTaggedStringAttribute(t AttributeType, tag byte, rest string) (*Attribute, error) {
	n := 1 + len(rest)
	if n > maxAttributeLen {
		return nil, fmt.Errorf("value of %s too big: %d bytes", t.String(), n)
	}
	return newAttribute(t, append([]byte{tag}, rest...)), nil
}
