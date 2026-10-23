/*
Copyright © 2024 Keytos alan@keytos.io

Test RFC 2868 tunnel tags and RFC 4675 egress VLAN attributes.
*/
package radius

import (
	"bytes"
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
	tunnelMedium := AttributeKey{Type: AttributeTypeTunnelMediumType}
	groupID := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId}

	tests := []struct {
		name  string
		key   AttributeKey
		value string
		want  []byte
	}{
		// VLAN is tunnel type 13. An omitted tag is the zero tag octet.
		{"untagged tunnel type", tunnelType, "Virtual LAN", []byte{0x00, 0x00, 0x00, 0x0d}},
		{"explicit zero tag", tunnelType, "0:Virtual LAN", []byte{0x00, 0x00, 0x00, 0x0d}},
		{"tagged tunnel type", tunnelType, "1:Virtual LAN", []byte{0x01, 0x00, 0x00, 0x0d}},
		// 802 is tunnel medium type 6.
		{"tagged tunnel medium", tunnelMedium, "1:802", []byte{0x01, 0x00, 0x00, 0x06}},
		// '2' is 0x32, which is past 0x1F, so the string is untagged on its own.
		{"untagged group id", groupID, "20", []byte("20")},
		{"tagged group id", groupID, "1:20", []byte{0x01, '2', '0'}},
		{"explicit zero tag on group id", groupID, "0:20", []byte{0x00, '2', '0'}},
		// 32 is not a tag, so the colon is part of the group id.
		{"group id that only looks tagged", groupID, "32:20", []byte("32:20")},
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

func TestInvalidTunnelTags(t *testing.T) {
	tunnelType := AttributeKey{Type: AttributeTypeTunnelType}
	groupID := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId}
	for _, value := range []string{"1:", "1:NotATunnelType", "99:Virtual LAN"} {
		key := tunnelType
		if value == "1:" {
			key = groupID
		}
		if _, err := serializeAttributeMap(AttributeMap{key: {value}}); err == nil {
			t.Fatalf("expected an error for %s", value)
		}
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
		// A name with no prefix stays a raw string.
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
	name := AttributeKey{Type: AttributeTypeEgressVlanName}
	if _, err := serializeAttributeMap(AttributeMap{name: {"tagged:"}}); err == nil {
		t.Fatal("expected an error for an empty Egress-VLAN-Name")
	}
}

// The check a session runs: a tag-1 group id matches only a reply that
// carries that tag, which is how a NAS is told the VLAN.
func TestTaggedGroupIDMatchesOnlyTheTaggedReply(t *testing.T) {
	key := AttributeKey{Type: AttributeTypeTunnelPrivateGroupId}
	taggedReply := &Datagram{Attributes: Attributes{
		{Type: AttributeTypeTunnelPrivateGroupId, Value: []byte{0x01, '2', '0'}},
	}}

	expected, err := serializeAttributeMap(AttributeMap{key: {"1:20"}})
	if err != nil {
		t.Fatalf("could not serialize tagged group id: %v", err)
	}
	s := &session{recvAttributes: expected, lastReadDatagram: taggedReply}
	if err := s.lastReadDatagramHasExpectedAttributes(); err != nil {
		t.Fatalf("tag 1 group id 20 was not matched: %v", err)
	}

	untagged, err := serializeAttributeMap(AttributeMap{key: {"20"}})
	if err != nil {
		t.Fatalf("could not serialize untagged group id: %v", err)
	}
	s.recvAttributes = untagged
	if err := s.lastReadDatagramHasExpectedAttributes(); err == nil {
		t.Fatal("untagged group id 20 matched a reply that carries tag 1")
	}
}
