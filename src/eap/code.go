/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP Codes
*/
package eap

import "fmt"

type Code uint8

const (
	CodeRequest Code = iota + 1
	CodeResponse
	CodeSuccess
	CodeFailure
)

func (c Code) String() string {
	switch c {
	case CodeRequest:
		return "Request"
	case CodeResponse:
		return "Response"
	case CodeSuccess:
		return "Success"
	case CodeFailure:
		return "Failure"
	}
	return fmt.Sprintf("Unknown (%d)", c)
}
