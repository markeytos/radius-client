/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP Request/Response Types
*/
package eap

type Type uint8

const (
	TypeIdentity     Type = 1
	TypeNotification Type = 2
	TypeNAK          Type = 3
	TypeMD5          Type = 4
	TypeTLS          Type = 13
	TypeTTLS         Type = 21
	TypePEAP         Type = 25
	TypeMsCHAPv2     Type = 26
	TypeExtensions   Type = 33
)
