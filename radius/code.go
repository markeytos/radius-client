/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS Codes
*/
package radius

import "fmt"

type Code uint8

const (
	// Defined in https://datatracker.ietf.org/doc/html/rfc2865
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	CodeAccessChallenge    Code = 11
	CodeStatusServer       Code = 12
	CodeStatusClient       Code = 13
	CodeReserved           Code = 255

	// Defined in https://datatracker.ietf.org/doc/html/rfc5176
	CodeDisconnectRequest Code = 40
	CodeDisconnectACK     Code = 41
	CodeDisconnectNAK     Code = 42
	CodeCoARequest        Code = 43
	CodeCoAACK            Code = 44
	CodeCoANAK            Code = 45
)

func (c Code) String() string {
	switch c {
	case CodeAccessRequest:
		return "Access-Request"
	case CodeAccessAccept:
		return "Access-Accept"
	case CodeAccessReject:
		return "Access-Reject"
	case CodeAccountingRequest:
		return "Accounting-Request"
	case CodeAccountingResponse:
		return "Accounting-Response"
	case CodeAccessChallenge:
		return "Access-Challenge"
	case CodeStatusServer:
		return "Status-Server"
	case CodeStatusClient:
		return "Status-Client"
	case CodeReserved:
		return "Reserved"
	case CodeDisconnectRequest:
		return "Disconnect-Request"
	case CodeDisconnectACK:
		return "Disconnect-ACK"
	case CodeDisconnectNAK:
		return "Disconnect-NAK"
	case CodeCoARequest:
		return "CoA-Request"
	case CodeCoAACK:
		return "CoA-ACK"
	case CodeCoANAK:
		return "CoA-NAK"
	}
	return fmt.Sprintf("Unknown (%d)", c)
}
