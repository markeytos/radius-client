/*
Copyright © 2026 Keytos alan@keytos.io

Test TEAP TLVs, Crypto-Binding and key derivation
*/
package teap

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

func TestPRF(t *testing.T) {
	// TLS 1.2 P_SHA256 test vector published on the IETF TLS mailing list
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	expected, _ := hex.DecodeString(
		"e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" +
			"6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" +
			"4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" +
			"87347b66")
	out := PRF(sha256.New, secret, "test label", seed, len(expected))
	if !bytes.Equal(out, expected) {
		t.Fatalf("PRF mismatch\nexpected: %x\ngot:      %x", expected, out)
	}
}

func TestParseMessage(t *testing.T) {
	cb := &CryptoBinding{Version: Version, ReceivedVersion: Version, Flags: CryptoBindingFlagsEMSKAndMSK}
	cb.Nonce[0] = 0xaa
	b := MarshalTLVs([]TLV{
		NewStatusTLV(TLVTypeIntermediateResult, StatusSuccess),
		cb.TLV(),
		NewIdentityTypeTLV(IdentityTypeUser),
		NewEAPPayloadTLV([]byte{1, 2, 0, 5, 1}),
		{Type: TLVTypeIdentityHint, Value: []byte("ignored")},
	})
	m, err := ParseMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.IntermediateResult != StatusSuccess || m.Result != 0 {
		t.Fatalf("unexpected results %d, %d", m.IntermediateResult, m.Result)
	}
	if m.IdentityType != IdentityTypeUser {
		t.Fatalf("unexpected identity type %s", m.IdentityType)
	}
	if m.CryptoBinding == nil || !bytes.Equal(m.CryptoBinding.TLV().Value, cb.TLV().Value) {
		t.Fatalf("crypto binding did not round trip: %+v", m.CryptoBinding)
	}
	if !bytes.Equal(m.EAPPayload, []byte{1, 2, 0, 5, 1}) {
		t.Fatalf("unexpected EAP payload %x", m.EAPPayload)
	}
	if m.Err() != nil {
		t.Fatalf("unexpected error %v", m.Err())
	}
}

func TestParseMessageErrors(t *testing.T) {
	tests := map[string][]byte{
		"truncated header":           {0x80, 0x03},
		"truncated value":            {0x80, 0x03, 0x00, 0x04, 0x00, 0x01},
		"unknown mandatory TLV":      MarshalTLVs([]TLV{{Mandatory: true, Type: TLVTypePAC, Value: []byte{0}}}),
		"unknown status":             MarshalTLVs([]TLV{NewStatusTLV(TLVTypeResult, 3)}),
		"short crypto binding":       MarshalTLVs([]TLV{{Mandatory: true, Type: TLVTypeCryptoBinding, Value: make([]byte, 75)}}),
		"invalid identity type size": MarshalTLVs([]TLV{{Mandatory: true, Type: TLVTypeIdentityType, Value: []byte{1}}}),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMessage(b); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	m, err := ParseMessage(MarshalTLVs([]TLV{
		NewStatusTLV(TLVTypeResult, StatusFailure),
		{Mandatory: true, Type: TLVTypeError, Value: []byte{0, 0, 0x07, 0xd1}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if m.Err() == nil {
		t.Fatal("expected failure result to be reported")
	}
}

func TestCryptoBindingResponse(t *testing.T) {
	req := &CryptoBinding{Version: Version, ReceivedVersion: Version, Flags: CryptoBindingFlagsMSK}
	req.Nonce[NonceLen-1] = 0xfe
	resp, err := req.Response(Version)
	if err != nil {
		t.Fatal(err)
	}
	if resp.SubType != CryptoBindingSubTypeResponse || resp.Nonce[NonceLen-1] != 0xff {
		t.Fatalf("unexpected response %+v", resp)
	}

	invalid := map[string]func(cb *CryptoBinding){
		"version":          func(cb *CryptoBinding) { cb.Version = 2 },
		"received version": func(cb *CryptoBinding) { cb.ReceivedVersion = 0 },
		"sub-type":         func(cb *CryptoBinding) { cb.SubType = CryptoBindingSubTypeResponse },
		"flags":            func(cb *CryptoBinding) { cb.Flags = 4 },
		"nonce":            func(cb *CryptoBinding) { cb.Nonce[NonceLen-1] |= 1 },
	}
	for name, f := range invalid {
		t.Run(name, func(t *testing.T) {
			cb := *req
			f(&cb)
			if _, err := cb.Response(Version); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCompoundMACIgnoresMACFields(t *testing.T) {
	ks := &KeySchedule{mac: sha256.New, chains: []*keyChain{{prf: sha256.New, simck: make([]byte, SessionKeySeedLen)}}}
	if err := ks.Next([]byte("inner method MSK")); err != nil {
		t.Fatal(err)
	}
	cb := &CryptoBinding{Version: Version, ReceivedVersion: Version, Flags: CryptoBindingFlagsMSK}
	mac := ks.CompoundMAC(cb, []byte{0, 1, 0, 0}, nil)

	withMACs := *cb
	withMACs.MSKCompoundMAC = mac
	withMACs.EMSKCompoundMAC[0] = 1
	if ks.CompoundMAC(&withMACs, []byte{0, 1, 0, 0}, nil) != mac {
		t.Fatal("Compound MAC depends on the MAC fields")
	}
	if ks.CompoundMAC(cb, nil, nil) == mac {
		t.Fatal("Compound MAC does not cover the outer TLVs")
	}

	// a received TLV is covered as sent, even with its mandatory bit unset
	received := cb.TLV()
	received.Mandatory = false
	received.Value = append([]byte(nil), received.Value...)
	copy(received.Value[len(received.Value)-CompoundMACLen:], mac[:])
	m, err := ParseMessage(received.AppendBinary(nil))
	if err != nil {
		t.Fatal(err)
	}
	if ks.CompoundMAC(m.CryptoBinding, []byte{0, 1, 0, 0}, nil) == mac {
		t.Fatal("Compound MAC of a received TLV ignores its header as sent")
	}
}

func TestHashFollowsCipherSuite(t *testing.T) {
	if prfHash(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)().Size() != 48 ||
		prfHash(tls.TLS_AES_256_GCM_SHA384)().Size() != 48 ||
		prfHash(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)().Size() != 32 {
		t.Fatal("PRF hash does not follow the cipher suite")
	}
	if macHash(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)().Size() != 20 ||
		macHash(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)().Size() != 48 {
		t.Fatal("MAC hash does not follow the cipher suite")
	}
}
