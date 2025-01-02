/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 packets
*/
package mschapv2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
)

type Challenge struct {
	OpCode     OpCode
	Identifier uint8
	Length     uint16
	ValueSize  uint8
	Challenge  [16]byte
	Name       []byte
}

func ReadChallenge(data []byte) (*Challenge, error) {
	if len(data) < 21 {
		return nil, fmt.Errorf("data too small to hold challenge packet")
	}
	c := &Challenge{
		OpCode:     OpCode(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		ValueSize:  data[4],
		Challenge:  [16]byte(data[5:21]),
	}
	c.Name = data[21:c.Length]
	if c.OpCode != OpCodeChallenge {
		return nil, fmt.Errorf("not an MS-CHAPv2 challenge")
	}
	return c, nil
}

type Response struct {
	OpCode        OpCode
	Identifier    uint8
	Length        uint16
	ValueSize     uint8
	PeerChallenge [16]byte
	Reserved      [8]byte
	NTResponse    [24]byte
	Flag          uint8
	Name          []byte
}

func CreateEmptyResponse(c *Challenge, uname string) *Response {
	r := &Response{
		OpCode:     OpCodeResponse,
		Identifier: c.Identifier,
		Length:     uint16(54 + len(uname)),
		ValueSize:  49,
		Flag:       0,
		Name:       []byte(uname),
	}
	_, err := rand.Read(r.PeerChallenge[:])
	if err != nil {
		log.Fatal(err)
	}
	return r
}

func (r Response) ToBinary() []byte {
	buff := make([]byte, r.Length)
	buff[0] = byte(r.OpCode)
	buff[1] = r.Identifier
	binary.BigEndian.PutUint16(buff[2:4], r.Length)
	buff[4] = r.ValueSize
	copy(buff[5:21], r.PeerChallenge[:])
	copy(buff[21:29], r.Reserved[:])
	copy(buff[29:53], r.NTResponse[:])
	buff[53] = r.Flag
	copy(buff[54:], r.Name)
	return buff
}

type Request struct {
	OpCode     OpCode
	Identifier uint8
	Length     uint16
	Message    string
}

func ReadRequest(data []byte) (*Request, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too small to hold request packet")
	}
	r := &Request{
		OpCode:     OpCode(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}
	r.Message = string(data[4:r.Length])
	if r.OpCode != OpCodeSuccess && r.OpCode != OpCodeFailure {
		return nil, fmt.Errorf("not an MS-CHAPv2 success or failure request")
	}
	return r, nil
}
