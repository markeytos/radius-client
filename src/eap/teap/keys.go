/*
Copyright © 2026 Keytos alan@keytos.io

# Define TEAP key derivation and Compound MAC

TLS 1.2 tunnels follow RFC 9930 section 6, TLS 1.3 tunnels RFC 9427 section
2.2, which replaces the TLS PRF with TLS exporters. Some servers, hostapd among
them, keep the TLS 1.2 derivations for TLS 1.3 tunnels, so until a server's
Compound MAC shows which one it uses both are carried.

The IMSK of each inner method is taken from its MSK, and the MSK based S-IMCK
chain is the one carried from method to method and used to derive the session
keys, as for a peer that neither sends nor checks the EMSK Compound MAC, which
RFC 9930 section 5.2 describes as the most well-known supplicant.
*/
package teap

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"hash"
)

const (
	SessionKeySeedLabel = "EXPORTER: teap session key seed"
	SessionKeySeedLen   = 40
	imskLen             = 32
	imckLen             = 60
	sessionKeyLen       = 64
	eapType             = 55
)

type KeySchedule struct {
	mac    func() hash.Hash
	chains []*keyChain
}

// keyChain is the S-IMCK chain of one derivation, with TLS exporters for
// TLS 1.3 as RFC 9427 defines, else with the TLS 1.2 PRF
type keyChain struct {
	prf    func() hash.Hash
	export func(label string, context []byte, length int) ([]byte, error)
	simck  []byte
	cmk    []byte
	tls12  bool
}

// NewKeySchedule starts the S-IMCK chain from the session key seed exported
// from the TEAP tunnel, S-IMCK[0]
func NewKeySchedule(cs tls.ConnectionState) (*KeySchedule, error) {
	k := &KeySchedule{mac: macHash(cs.CipherSuite)}
	prf := prfHash(cs.CipherSuite)
	if cs.Version == tls.VersionTLS13 {
		seed, err := cs.ExportKeyingMaterial(SessionKeySeedLabel, []byte{eapType}, SessionKeySeedLen)
		if err != nil {
			return nil, err
		}
		k.chains = append(k.chains, &keyChain{prf: prf, export: cs.ExportKeyingMaterial, simck: seed})
	}
	seed, err := cs.ExportKeyingMaterial(SessionKeySeedLabel, nil, SessionKeySeedLen)
	if err != nil {
		return nil, err
	}
	k.chains = append(k.chains, &keyChain{prf: prf, simck: seed, tls12: true})
	return k, nil
}

// Next mixes the MSK of the inner method just completed into the chain, the
// CMK binding it. A nil MSK stands for a method without keys.
func (k *KeySchedule) Next(msk []byte) error {
	for _, c := range k.chains {
		if err := c.next(msk); err != nil {
			return err
		}
	}
	return nil
}

// HasCMK reports whether an inner method, or a keyless one, was mixed in
func (k *KeySchedule) HasCMK() bool {
	return k.chains[0].cmk != nil
}

// VerifyMSKCompoundMAC checks the server's MSK Compound MAC, and keeps only
// the derivations that it matches
func (k *KeySchedule) VerifyMSKCompoundMAC(cb *CryptoBinding, serverOuterTLVs, peerOuterTLVs []byte) bool {
	var matching []*keyChain
	for _, c := range k.chains {
		mac := k.compoundMAC(c.cmk, cb, serverOuterTLVs, peerOuterTLVs)
		if hmac.Equal(mac[:], cb.MSKCompoundMAC[:]) {
			matching = append(matching, c)
		}
	}
	if len(matching) == 0 {
		return false
	}
	k.chains = matching
	return true
}

// TLS12Derivation reports whether the derivation in use is the TLS 1.2 one
func (k *KeySchedule) TLS12Derivation() bool {
	return k.chains[0].tls12
}

// CompoundMAC computes the Compound MAC with the current CMK
func (k *KeySchedule) CompoundMAC(cb *CryptoBinding, serverOuterTLVs, peerOuterTLVs []byte) [CompoundMACLen]byte {
	return k.compoundMAC(k.chains[0].cmk, cb, serverOuterTLVs, peerOuterTLVs)
}

// compoundMAC covers the Crypto-Binding TLV with both its MACs zeroed, the
// TEAP EAP type, and the Outer TLVs of the first message of the server and of
// the peer
func (k *KeySchedule) compoundMAC(cmk []byte, cb *CryptoBinding, serverOuterTLVs, peerOuterTLVs []byte) [CompoundMACLen]byte {
	h := hmac.New(k.mac, cmk)
	h.Write(cb.zeroedTLV())
	h.Write([]byte{eapType})
	h.Write(serverOuterTLVs)
	h.Write(peerOuterTLVs)

	var mac [CompoundMACLen]byte
	copy(mac[:], h.Sum(nil))
	return mac
}

// SessionKeys derives the TEAP MSK from the final S-IMCK and splits it in the
// receive and send keys carried in MS-MPPE-Recv-Key and MS-MPPE-Send-Key
func (k *KeySchedule) SessionKeys() (recv, send []byte, err error) {
	c := k.chains[0]
	var msk []byte
	if c.export != nil {
		msk, err = c.export("EXPORTER: Session Key Generating Function", c.simck, sessionKeyLen)
		if err != nil {
			return nil, nil, err
		}
	} else {
		msk = PRF(c.prf, c.simck, "Session Key Generating Function", nil, sessionKeyLen)
	}
	return msk[:32], msk[32:], nil
}

func (c *keyChain) next(msk []byte) error {
	imsk := make([]byte, imskLen)
	var imck []byte
	if c.export != nil {
		var err error
		if msk != nil {
			imsk, err = c.export("TEAPbindkey@ietf.org", msk, imskLen)
			if err != nil {
				return err
			}
		}
		seed := append(append([]byte(nil), c.simck...), imsk...)
		imck, err = c.export("EXPORTER: Inner Methods Compound Keys", seed, imckLen)
		if err != nil {
			return err
		}
	} else {
		copy(imsk, msk)
		imck = PRF(c.prf, c.simck, "Inner Methods Compound Keys", imsk, imckLen)
	}
	c.simck = imck[:SessionKeySeedLen]
	c.cmk = imck[SessionKeySeedLen:]
	return nil
}

// PRF is the TLS 1.2 PRF, P_hash(secret, label + seed), of RFC 5246 section 5
func PRF(h func() hash.Hash, secret []byte, label string, seed []byte, length int) []byte {
	ls := append([]byte(label), seed...)
	mac := hmac.New(h, secret)
	out := make([]byte, 0, length+mac.Size())
	mac.Write(ls)
	a := mac.Sum(nil)
	for len(out) < length {
		mac.Reset()
		mac.Write(a)
		mac.Write(ls)
		out = mac.Sum(out)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:length]
}

// prfHash returns the hash of the PRF, or with TLS 1.3 of HKDF, negotiated by
// the tunnel cipher suite
func prfHash(cs uint16) func() hash.Hash {
	switch cs {
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_AES_256_GCM_SHA384:
		return sha512.New384
	}
	return sha256.New
}

// macHash returns the hash of the MAC negotiated by the tunnel cipher suite,
// which for AEAD cipher suites is the one of their PRF
func macHash(cs uint16) func() hash.Hash {
	switch cs {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return sha1.New
	}
	return prfHash(cs)
}
