/*
Copyright © 2026 Keytos alan@keytos.io

# Define TEAP Crypto-Binding TLV value (RFC 9930 section 4.2.13)

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|    Reserved   |    Version    |  Received-Ver.| Flags|Sub-Type|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                          Nonce (32)                           ~
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                    EMSK Compound MAC (20)                     ~
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                     MSK Compound MAC (20)                     ~
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
package teap

import (
	"fmt"
)

const (
	Version                  = 1
	NonceLen                 = 32
	CompoundMACLen           = 20
	cryptoBindingLen         = 4 + NonceLen + 2*CompoundMACLen
	cryptoBindingSubTypeMask = 0x0f
)

type CryptoBindingFlags uint8

const (
	CryptoBindingFlagsEMSK       CryptoBindingFlags = 1
	CryptoBindingFlagsMSK        CryptoBindingFlags = 2
	CryptoBindingFlagsEMSKAndMSK CryptoBindingFlags = 3
)

func (f CryptoBindingFlags) HasMSK() bool {
	return f == CryptoBindingFlagsMSK || f == CryptoBindingFlagsEMSKAndMSK
}

type CryptoBindingSubType uint8

const (
	CryptoBindingSubTypeRequest  CryptoBindingSubType = 0
	CryptoBindingSubTypeResponse CryptoBindingSubType = 1
)

type CryptoBinding struct {
	Version         uint8
	ReceivedVersion uint8
	Flags           CryptoBindingFlags
	SubType         CryptoBindingSubType
	Nonce           [NonceLen]byte
	EMSKCompoundMAC [CompoundMACLen]byte
	MSKCompoundMAC  [CompoundMACLen]byte
	// raw is the TLV as received, which the Compound MAC covers as is
	raw []byte
}

func ParseCryptoBinding(b []byte) (*CryptoBinding, error) {
	if len(b) != cryptoBindingLen {
		return nil, fmt.Errorf("teap: invalid Crypto-Binding TLV length %d", len(b))
	}
	cb := &CryptoBinding{
		Version:         b[1],
		ReceivedVersion: b[2],
		Flags:           CryptoBindingFlags(b[3] >> 4),
		SubType:         CryptoBindingSubType(b[3] & cryptoBindingSubTypeMask),
	}
	copy(cb.Nonce[:], b[4:])
	copy(cb.EMSKCompoundMAC[:], b[4+NonceLen:])
	copy(cb.MSKCompoundMAC[:], b[4+NonceLen+CompoundMACLen:])
	return cb, nil
}

func (cb *CryptoBinding) TLV() TLV {
	b := make([]byte, 0, cryptoBindingLen)
	b = append(b, 0, cb.Version, cb.ReceivedVersion, byte(cb.Flags)<<4|byte(cb.SubType))
	b = append(b, cb.Nonce[:]...)
	b = append(b, cb.EMSKCompoundMAC[:]...)
	b = append(b, cb.MSKCompoundMAC[:]...)
	return TLV{Mandatory: true, Type: TLVTypeCryptoBinding, Value: b}
}

// zeroedTLV is the TLV with both Compound MACs zeroed, as covered by them
func (cb *CryptoBinding) zeroedTLV() []byte {
	var b []byte
	if cb.raw != nil {
		b = append(b, cb.raw...)
	} else {
		b = cb.TLV().AppendBinary(nil)
	}
	clear(b[tlvHeaderLen+4+NonceLen:])
	return b
}

// Response builds the peer's reply to a server's binding request, without its
// Compound MACs, after checking the request is one the peer can answer
func (cb *CryptoBinding) Response(receivedVersion uint8) (*CryptoBinding, error) {
	var err error
	switch {
	case cb.Version != Version:
		err = fmt.Errorf("teap: unsupported Crypto-Binding version %d", cb.Version)
	case cb.ReceivedVersion != Version:
		err = fmt.Errorf("teap: Crypto-Binding received version %d does not match the version sent %d", cb.ReceivedVersion, Version)
	case cb.SubType != CryptoBindingSubTypeRequest:
		err = fmt.Errorf("teap: Crypto-Binding sub-type %d is not a binding request", cb.SubType)
	case cb.Flags < CryptoBindingFlagsEMSK || cb.Flags > CryptoBindingFlagsEMSKAndMSK:
		err = fmt.Errorf("teap: invalid Crypto-Binding flags %d", cb.Flags)
	case cb.Nonce[NonceLen-1]&1 != 0:
		err = fmt.Errorf("teap: Crypto-Binding request nonce has its least significant bit set")
	}
	if err != nil {
		return nil, &ProtocolError{Code: ErrorInvalidCryptoBinding, Err: err}
	}
	resp := &CryptoBinding{
		Version:         Version,
		ReceivedVersion: receivedVersion,
		SubType:         CryptoBindingSubTypeResponse,
		Nonce:           cb.Nonce,
	}
	resp.Nonce[NonceLen-1] |= 1
	return resp, nil
}
