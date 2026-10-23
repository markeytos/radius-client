/*
Copyright © 2026 Keytos alan@keytos.io

# Define TEAP TLVs carried inside the TEAP tunnel (RFC 9930)

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|M|R|         TLV Type          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                              Value...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
package teap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TLVType uint16

const (
	TLVTypeAuthorityID           TLVType = 1
	TLVTypeIdentityType          TLVType = 2
	TLVTypeResult                TLVType = 3
	TLVTypeNAK                   TLVType = 4
	TLVTypeError                 TLVType = 5
	TLVTypeChannelBinding        TLVType = 6
	TLVTypeVendorSpecific        TLVType = 7
	TLVTypeRequestAction         TLVType = 8
	TLVTypeEAPPayload            TLVType = 9
	TLVTypeIntermediateResult    TLVType = 10
	TLVTypePAC                   TLVType = 11
	TLVTypeCryptoBinding         TLVType = 12
	TLVTypeBasicPasswordAuthReq  TLVType = 13
	TLVTypeBasicPasswordAuthResp TLVType = 14
	TLVTypePKCS7                 TLVType = 15
	TLVTypePKCS10                TLVType = 16
	TLVTypeTrustedServerRoot     TLVType = 17
	TLVTypeCSRAttributes         TLVType = 18
	TLVTypeIdentityHint          TLVType = 19
)

const (
	tlvHeaderLen     = 4
	tlvFlagMandatory = 0x8000
	tlvTypeMask      = 0x3fff
)

type Status uint16

const (
	StatusSuccess Status = 1
	StatusFailure Status = 2
)

// Error TLV codes, 2000 and above are fatal (RFC 9930 section 4.2.6)
const (
	ErrorInnerMethod           uint32 = 1001
	ErrorFatal                 uint32 = 2000
	ErrorTunnelCompromise      uint32 = 2001
	ErrorUnexpectedTLVs        uint32 = 2002
	ErrorInvalidCryptoBinding  uint32 = 2003
	ErrorMissingMSKCompoundMAC uint32 = 2005
	ErrorMSKCompoundMAC        uint32 = 2006
)

// ProtocolError is an error of the peer reported to the server in an Error TLV
type ProtocolError struct {
	Code uint32
	Err  error
}

func (e *ProtocolError) Error() string {
	return e.Err.Error()
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

type IdentityType uint16

const (
	IdentityTypeUser    IdentityType = 1
	IdentityTypeMachine IdentityType = 2
)

func (it IdentityType) String() string {
	switch it {
	case IdentityTypeUser:
		return "user"
	case IdentityTypeMachine:
		return "machine"
	}
	return fmt.Sprintf("unknown (%d)", it)
}

type TLV struct {
	Mandatory bool
	Type      TLVType
	Value     []byte
	raw       []byte
}

func NewStatusTLV(t TLVType, s Status) TLV {
	return TLV{Mandatory: true, Type: t, Value: binary.BigEndian.AppendUint16(nil, uint16(s))}
}

func NewIdentityTypeTLV(it IdentityType) TLV {
	return TLV{Mandatory: true, Type: TLVTypeIdentityType, Value: binary.BigEndian.AppendUint16(nil, uint16(it))}
}

func NewErrorTLV(code uint32) TLV {
	return TLV{Mandatory: true, Type: TLVTypeError, Value: binary.BigEndian.AppendUint32(nil, code)}
}

func NewEAPPayloadTLV(eap []byte) TLV {
	return TLV{Mandatory: true, Type: TLVTypeEAPPayload, Value: eap}
}

func (t TLV) AppendBinary(b []byte) []byte {
	h := uint16(t.Type) & tlvTypeMask
	if t.Mandatory {
		h |= tlvFlagMandatory
	}
	b = binary.BigEndian.AppendUint16(b, h)
	b = binary.BigEndian.AppendUint16(b, uint16(len(t.Value)))
	return append(b, t.Value...)
}

func MarshalTLVs(tlvs []TLV) []byte {
	var b []byte
	for _, t := range tlvs {
		b = t.AppendBinary(b)
	}
	return b
}

func ParseTLVs(b []byte) ([]TLV, error) {
	var tlvs []TLV
	for len(b) > 0 {
		if len(b) < tlvHeaderLen {
			return nil, errors.New("teap: truncated TLV header")
		}
		h := binary.BigEndian.Uint16(b[:2])
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < tlvHeaderLen+l {
			return nil, fmt.Errorf("teap: truncated TLV of type %d", h&tlvTypeMask)
		}
		tlvs = append(tlvs, TLV{
			Mandatory: h&tlvFlagMandatory != 0,
			Type:      TLVType(h & tlvTypeMask),
			Value:     b[tlvHeaderLen : tlvHeaderLen+l],
			raw:       b[:tlvHeaderLen+l],
		})
		b = b[tlvHeaderLen+l:]
	}
	return tlvs, nil
}

// Message holds the TLVs of a single TEAP Phase 2 message that the peer acts on
type Message struct {
	Result             Status
	IntermediateResult Status
	ErrorCodes         []uint32
	NAKTypes           []TLVType
	IdentityType       IdentityType
	CryptoBinding      *CryptoBinding
	EAPPayload         []byte
}

func ParseMessage(b []byte) (*Message, error) {
	m, err := parseMessage(b)
	if err != nil {
		return nil, &ProtocolError{Code: ErrorUnexpectedTLVs, Err: err}
	}
	return m, nil
}

func parseMessage(b []byte) (*Message, error) {
	tlvs, err := ParseTLVs(b)
	if err != nil {
		return nil, err
	}
	m := &Message{}
	for _, t := range tlvs {
		switch t.Type {
		case TLVTypeResult:
			m.Result, err = parseStatus(t)
		case TLVTypeIntermediateResult:
			m.IntermediateResult, err = parseStatus(t)
		case TLVTypeError:
			if len(t.Value) != 4 {
				return nil, errors.New("teap: invalid Error TLV length")
			}
			m.ErrorCodes = append(m.ErrorCodes, binary.BigEndian.Uint32(t.Value))
		case TLVTypeNAK:
			if len(t.Value) < 6 {
				return nil, errors.New("teap: invalid NAK TLV length")
			}
			m.NAKTypes = append(m.NAKTypes, TLVType(binary.BigEndian.Uint16(t.Value[4:6])))
		case TLVTypeIdentityType:
			if len(t.Value) != 2 {
				return nil, errors.New("teap: invalid Identity-Type TLV length")
			}
			m.IdentityType = IdentityType(binary.BigEndian.Uint16(t.Value))
		case TLVTypeCryptoBinding:
			m.CryptoBinding, err = ParseCryptoBinding(t.Value)
			if err == nil {
				m.CryptoBinding.raw = t.raw
			}
		case TLVTypeEAPPayload:
			m.EAPPayload = t.Value
		default:
			// Optional TLVs, such as Authority-ID or Identity-Hint, carry
			// nothing an EAP-TLS peer needs, mandatory ones it cannot honour
			if t.Mandatory {
				return nil, fmt.Errorf("teap: unsupported mandatory TLV of type %d", t.Type)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Fatal reports whether the server ended the authentication, rather than an
// inner method only
func (m *Message) Fatal() bool {
	if m.Result == StatusFailure || len(m.NAKTypes) > 0 {
		return true
	}
	for _, c := range m.ErrorCodes {
		if c >= ErrorFatal {
			return true
		}
	}
	return false
}

// Err describes the failures and errors the server reported
func (m *Message) Err() error {
	var errs []error
	for _, c := range m.ErrorCodes {
		errs = append(errs, fmt.Errorf("teap: server sent error code %d", c))
	}
	for _, t := range m.NAKTypes {
		errs = append(errs, fmt.Errorf("teap: server does not support TLV of type %d", t))
	}
	if m.IntermediateResult == StatusFailure {
		errs = append(errs, errors.New("teap: server sent intermediate result failure"))
	}
	if m.Result == StatusFailure {
		errs = append(errs, errors.New("teap: server sent result failure"))
	}
	return errors.Join(errs...)
}

func parseStatus(t TLV) (Status, error) {
	// an Intermediate-Result TLV may carry TLVs of its own after the status
	if len(t.Value) < 2 {
		return 0, fmt.Errorf("teap: invalid status in TLV of type %d", t.Type)
	}
	s := Status(binary.BigEndian.Uint16(t.Value))
	if s != StatusSuccess && s != StatusFailure {
		return 0, fmt.Errorf("teap: unknown status %d in TLV of type %d", s, t.Type)
	}
	return s, nil
}
