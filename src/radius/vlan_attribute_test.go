/*
Copyright © 2024 Keytos alan@keytos.io

Test RFC 2868 tunnel tags and RFC 4675 egress VLAN attributes.
*/
package radius

import (
	"bytes"
	"strings"
	"testing"
)

func mustSerializeOne(t *testing.T, key AttributeKey, value string) *Attribute {
	t.Helper()
	attrs, err := serializeAttributeMap(AttributeMap{key: {value}})
	if err != nil {
		t.Fatalf("could not serialize %s: %v", value, err)
	}
	if len(attrs) != 1 {
		t.Fatalf("expected one attribute for %s, got %d", value, len(attrs))
	}
	return attrs[0]
}

func TestTunnelAttributesCarryOptionalTags(t *testing.T) {
	tunnelType := AttributeKey{Type: AttributeTypeTunnelType}
	taggedType := AttributeKey{Type: AttributeTypeTunnelType, TunnelTag: 1, HasTunnelTag: true}
	taggedMedium := AttributeKey{Type: AttributeTypeTunnelMediumType, TunnelTag: 1, HasTunnelTag: true}
	groupID := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId}
	taggedGroup := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId, TunnelTag: 1, HasTunnelTag: true}
	zeroGroup := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId, TunnelTag: 0, HasTunnelTag: true}

	tests := []struct {
		name  string
		key   AttributeKey
		value string
		want  []byte
	}{
		// VLAN is tunnel type 13. An omitted tag is the zero tag octet.
		{"untagged tunnel type", tunnelType, "Virtual LAN", []byte{0x00, 0x00, 0x00, 0x0d}},
		{"tagged tunnel type", taggedType, "Virtual LAN", []byte{0x01, 0x00, 0x00, 0x0d}},
		// 802 is tunnel medium type 6.
		{"tagged tunnel medium", taggedMedium, "802", []byte{0x01, 0x00, 0x00, 0x06}},
		// '2' is 0x32, which is past 0x1F, so the string is untagged on its own.
		{"untagged group id", groupID, "20", []byte("20")},
		{"tagged group id", taggedGroup, "20", []byte{0x01, '2', '0'}},
		{"explicit zero tag on group id", zeroGroup, "20", []byte{0x00, '2', '0'}},
		// A colon in the value is part of the value. The tag lives on the name.
		{"group id with a colon", groupID, "10:20", []byte("10:20")},
		{"group id that looks like a tag", groupID, "5:guest", []byte("5:guest")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mustSerializeOne(t, test.key, test.value)
			if got.Type != test.key.Type {
				t.Fatalf("attribute type %s, want %s", got.Type, test.key.Type)
			}
			if !bytes.Equal(got.Value, test.want) {
				t.Fatalf("value %q encoded to %x, want %x", test.value, got.Value, test.want)
			}
		})
	}
}

func TestInvalidTunnelAndEgressValues(t *testing.T) {
	tunnelType := AttributeKey{Type: AttributeTypeTunnelType}
	tunnelMedium := AttributeKey{Type: AttributeTypeTunnelMediumType}
	groupID := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId, TunnelTag: 1, HasTunnelTag: true}
	vlanName := AttributeKey{Type: AttributeTypeEgressVlanName}

	tests := []struct {
		name  string
		key   AttributeKey
		value string
	}{
		{"unknown tunnel type", tunnelType, "NotATunnelType"},
		{"tunnel type above 24 bits", tunnelType, "16777229"},
		{"tunnel type that would wrap", tunnelType, "4294967309"},
		{"unknown tunnel medium", tunnelMedium, "NotAMedium"},
		{"group id too long once tagged", groupID, strings.Repeat("a", maxAttributeLen)},
		{"empty untagged vlan name", vlanName, "untagged:"},
		{"vlan name too long once tagged", vlanName, "tagged:" + strings.Repeat("a", maxAttributeLen)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := serializeAttributeMap(AttributeMap{test.key: {test.value}})
			if err == nil {
				t.Fatalf("expected an error for %s value %q", test.key.Type, test.value)
			}
		})
	}
}

func TestOversizedTunnelEnumNamesTheTagSyntax(t *testing.T) {
	key := AttributeKey{Type: AttributeTypeTunnelType}
	_, err := serializeAttributeMap(AttributeMap{key: {"16777229"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Tunnel-Type#1:<value>") {
		t.Fatalf("error did not point at the tag syntax: %v", err)
	}
}

func TestTaggedStringAtTheLengthLimit(t *testing.T) {
	key := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId, TunnelTag: 1, HasTunnelTag: true}
	got := mustSerializeOne(t, key, strings.Repeat("a", maxAttributeLen-1))
	if len(got.Value) != maxAttributeLen {
		t.Fatalf("tagged value length %d, want %d", len(got.Value), maxAttributeLen)
	}
}

func TestEgressVLANAttributes(t *testing.T) {
	vlanID := AttributeKey{Type: AttributeTypeEgressVlanId}
	vlanName := AttributeKey{Type: AttributeTypeEgressVlanName}

	tests := []struct {
		name  string
		key   AttributeKey
		value string
		want  []byte
	}{
		{"tagged vlan id", vlanID, "tagged:100", []byte{0x31, 0x00, 0x00, 0x64}},
		{"untagged vlan id", vlanID, "untagged:100", []byte{0x32, 0x00, 0x00, 0x64}},
		{"last legal vlan id", vlanID, "tagged:4095", []byte{0x31, 0x00, 0x0f, 0xff}},
		// A name with no prefix stays a raw string. RFC 4675 calls that legacy.
		{"raw vlan name", vlanName, "Engineering", []byte("Engineering")},
		{"tagged vlan name", vlanName, "tagged:Engineering", append([]byte{0x31}, []byte("Engineering")...)},
		{"untagged vlan name", vlanName, "untagged:Engineering", append([]byte{0x32}, []byte("Engineering")...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mustSerializeOne(t, test.key, test.value)
			if !bytes.Equal(got.Value, test.want) {
				t.Fatalf("value %q encoded to %x, want %x", test.value, got.Value, test.want)
			}
		})
	}
}

func TestInvalidEgressVLANID(t *testing.T) {
	key := AttributeKey{Type: AttributeTypeEgressVlanId}
	for _, value := range []string{"100", "tagged:", "tagged:4096", "vlan:100"} {
		if _, err := serializeAttributeMap(AttributeMap{key: {value}}); err == nil {
			t.Fatalf("expected an error for Egress-VLANID %s", value)
		}
	}
}

// The check a session runs: a tag-1 group id matches only a reply that
// carries that tag, which is how a NAS is told the VLAN.
func TestTaggedGroupIDMatchesOnlyTheTaggedReply(t *testing.T) {
	taggedKey := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId, TunnelTag: 1, HasTunnelTag: true}
	taggedReply := &Datagram{Attributes: Attributes{
		{Type: AttributeTypeTunnelPrivateGroupId, Value: []byte{0x01, '2', '0'}},
	}}

	expected, err := serializeAttributeMap(AttributeMap{taggedKey: {"20"}})
	if err != nil {
		t.Fatalf("could not serialize tagged group id: %v", err)
	}
	s := &session{recvAttributes: expected, lastReadDatagram: taggedReply}
	if err := s.lastReadDatagramHasExpectedAttributes(); err != nil {
		t.Fatalf("tag 1 group id 20 was not matched: %v", err)
	}

	untagged := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId}
	plain, err := serializeAttributeMap(AttributeMap{untagged: {"20"}})
	if err != nil {
		t.Fatalf("could not serialize untagged group id: %v", err)
	}
	s.recvAttributes = plain
	if err := s.lastReadDatagramHasExpectedAttributes(); err == nil {
		t.Fatal("untagged group id 20 matched a reply that carries tag 1")
	}
}
