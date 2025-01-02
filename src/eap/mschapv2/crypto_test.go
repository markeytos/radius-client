/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 packets
*/
package mschapv2

import (
	"encoding/hex"
	"testing"
)

func TestWriteNTResponse(t *testing.T) {
	dst := make([]byte, 24)
	peerc, _ := hex.DecodeString("6c8c217ca7fda182bb5662ad3e54de83")
	authc, _ := hex.DecodeString("31149c19e0704707f4cff8635936e75f")
	pwh := NTPasswordHash(Utf16Bytes("test01"))
	chall := ChallengeHash(peerc, authc, "test01")
	WriteNTResponse(dst, pwh, chall)
	res := hex.EncodeToString(dst)
	expected := "47563111af9b8a8414899dd62a0cb0966dab42e592e0013f"
	if len(dst) != 24 {
		t.Fatalf("Destination changed size")
	}
	if res != expected {
		t.Fatalf("incorrect NT Response produced.\nexpected: \t%s\ngot: \t\t%s", expected, res)
	}
}
