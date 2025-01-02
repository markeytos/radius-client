/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 packets
*/
package mschapv2

type OpCode uint8

const (
	OpCodeChallenge OpCode = iota + 1
	OpCodeResponse
	OpCodeSuccess
	OpCodeFailure
)
