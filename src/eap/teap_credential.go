/*
Copyright © 2026 Keytos alan@keytos.io

Define the machine and user credentials a TEAP peer authenticates with
*/
package eap

import (
	"crypto/tls"
	"crypto/x509"
	encasn1 "encoding/asn1"

	"github.com/markeytos/radius-client/src/eap/teap"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidExtensionSubjectAltName = encasn1.ObjectIdentifier{2, 5, 29, 17}
	oidUserPrincipalName       = encasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

type TEAPCredential struct {
	IdentityType teap.IdentityType
	CertPath     string
	Identity     string
}

// NewTEAPCredential pairs a certificate with the EAP identity sent for it,
// which defaults to the one Windows sends for that certificate
func NewTEAPCredential(identityType teap.IdentityType, certPath, identity string) (TEAPCredential, error) {
	if identity == "" {
		pair, err := tls.LoadX509KeyPair(certPath, certPath)
		if err != nil {
			return TEAPCredential{}, err
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return TEAPCredential{}, err
		}
		identity = windowsIdentity(identityType, cert)
	}
	return TEAPCredential{
		IdentityType: identityType,
		CertPath:     certPath,
		Identity:     identity,
	}, nil
}

// windowsIdentity names a machine by its host service principal and a user
// by the user principal name in their certificate
func windowsIdentity(identityType teap.IdentityType, cert *x509.Certificate) string {
	if identityType == teap.IdentityTypeMachine {
		if len(cert.DNSNames) > 0 {
			return "host/" + cert.DNSNames[0]
		}
		return "host/" + cert.Subject.CommonName
	}
	if upn := userPrincipalName(cert); upn != "" {
		return upn
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return cert.Subject.CommonName
}

// userPrincipalName reads the UPN otherName of the subject alternative names,
// which Go does not parse
func userPrincipalName(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}
		input := cryptobyte.String(ext.Value)
		var names cryptobyte.String
		if !input.ReadASN1(&names, asn1.SEQUENCE) {
			return ""
		}
		for !names.Empty() {
			var name cryptobyte.String
			var tag asn1.Tag
			if !names.ReadAnyASN1(&name, &tag) {
				return ""
			}
			// otherName [0] { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
			if tag != asn1.Tag(0).ContextSpecific().Constructed() {
				continue
			}
			var oid encasn1.ObjectIdentifier
			var value, upn cryptobyte.String
			if !name.ReadASN1ObjectIdentifier(&oid) || !oid.Equal(oidUserPrincipalName) {
				continue
			}
			if name.ReadASN1(&value, asn1.Tag(0).ContextSpecific().Constructed()) &&
				value.ReadASN1(&upn, asn1.UTF8String) {
				return string(upn)
			}
		}
	}
	return ""
}
