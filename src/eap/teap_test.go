/*
Copyright © 2026 Keytos alan@keytos.io

Test TEAP authentication against an in-process server that chains machine and
user EAP-TLS authentication, as servers do for Windows peers. The server
derives its keys and Compound MACs from the RFC 9930 and RFC 9427 formulas
on its own, so that the peer's derivations are checked rather than mirrored.
*/
package eap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/markeytos/radius-client/src/eap/teap"
	eaptls "github.com/markeytos/radius-client/src/eap/tls"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	testServerName  = "radius.example.test"
	testMachineName = "pc1.corp.example.test"
	testUserUPN     = "alice@corp.example.test"
)

func TestTEAPMachineAndUserEAPTLS(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name string
		fakeTEAPServer
		clientMTU   int
		innerCA     bool // inner methods check the server against the wrong CA
		only13      bool
		expectedErr string
	}{
		{name: "plain"},
		// hostapd sends the first Phase 2 request with its TLS 1.2 Finished
		{name: "request with Finished", fakeTEAPServer: fakeTEAPServer{piggyback: true}},
		{name: "message over several records", fakeTEAPServer: fakeTEAPServer{splitRecords: true}},
		{name: "fragmented", fakeTEAPServer: fakeTEAPServer{maxFragment: 300}, clientMTU: 300},
		{name: "separate result", fakeTEAPServer: fakeTEAPServer{separateResult: true}},
		{name: "inner EAP-Success", fakeTEAPServer: fakeTEAPServer{innerSuccess: true}},
		{name: "server asks for the user first", fakeTEAPServer: fakeTEAPServer{userFirst: true}},
		{name: "machine fails and user goes on", fakeTEAPServer: fakeTEAPServer{failMachine: true}},
		{
			name:           "result alone after a failed method",
			fakeTEAPServer: fakeTEAPServer{userFirst: true, failMachine: true, separateResult: true},
			expectedErr:    "without a Crypto-Binding",
		},
		{name: "user rejected", fakeTEAPServer: fakeTEAPServer{rejectUser: true}, expectedErr: "result failure"},
		{name: "peer rejects the server", fakeTEAPServer: fakeTEAPServer{peerRejects: true}, innerCA: true, expectedErr: "machine authentication"},
		// hostapd sends neither for TLS 1.3 tunnels
		{name: "no commitment message", fakeTEAPServer: fakeTEAPServer{noCommitment: true}, only13: true},
		{name: "TLS 1.2 derivations", fakeTEAPServer: fakeTEAPServer{tls12Derivation: true}, only13: true},
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, test := range tests {
			if test.piggyback && version == tls.VersionTLS13 {
				continue // Go's TLS 1.3 server cannot write before the peer's Finished
			}
			if test.only13 && version != tls.VersionTLS13 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(version), test.name), func(t *testing.T) {
				srv := test.fakeTEAPServer
				srv.pki = pki
				srv.tlsVersion = version
				srv.tun = newFakeEAPTunnel(test.clientMTU)
				done := make(chan error, 1)
				go func() {
					err := srv.run()
					if err != nil {
						srv.tun.fail()
					}
					done <- err
				}()

				s := NewSession(srv.tun, "anonymous", false)
				tp, err := CreateTEAP(s, pki.caPath, map[uint16]string{tls.VersionTLS12: "1.2", tls.VersionTLS13: "1.3"}[version], testServerName, "", false)
				if err != nil {
					t.Fatalf("create: %v (server: %v)", err, <-done)
				}
				device, err := NewTEAPCredential(teap.IdentityTypeMachine, pki.devicePath, "")
				if err != nil {
					t.Fatal(err)
				}
				user, err := NewTEAPCredential(teap.IdentityTypeUser, pki.userPath, "")
				if err != nil {
					t.Fatal(err)
				}
				innerCA := pki.caPath
				if test.innerCA {
					innerCA = pki.devicePath
				}
				err = tp.Authenticate([]TEAPCredential{user, device}, innerCA, "")
				serr := <-done
				if serr != nil {
					t.Fatalf("server: %v (client: %v)", serr, err)
				}
				if test.expectedErr != "" {
					if err == nil || !strings.Contains(err.Error(), test.expectedErr) {
						t.Fatalf("expected error containing %q, got %v", test.expectedErr, err)
					}
					if !srv.peerFailed {
						t.Fatal("peer did not answer the failure")
					}
					return
				}
				if err != nil {
					t.Fatalf("client: %v", err)
				}

				expected := []string{"host/" + testMachineName, testUserUPN}
				if srv.userFirst {
					expected[0], expected[1] = expected[1], expected[0]
				}
				if fmt.Sprint(srv.identities) != fmt.Sprint(expected) {
					t.Fatalf("server saw identities %v, expected %v", srv.identities, expected)
				}
				if !bytes.Equal(s.RecvKey, srv.recvKey) || !bytes.Equal(s.SendKey, srv.sendKey) {
					t.Fatal("client and server session keys differ")
				}
			})
		}
	}
}

func TestTEAPMalformedStart(t *testing.T) {
	for _, data := range [][]byte{{}, {0xa1, 0x00}, {0x31, 0, 0, 0, 9}} {
		tp := &TEAP{}
		if err := tp.readStart(data); err == nil {
			t.Fatalf("expected an error for start data %x", data)
		}
	}
}

func TestPickTEAPCredential(t *testing.T) {
	machine := TEAPCredential{IdentityType: teap.IdentityTypeMachine}
	user := TEAPCredential{IdentityType: teap.IdentityTypeUser}
	creds := []TEAPCredential{machine, user}

	c, err := pickTEAPCredential(creds, teap.IdentityTypeUser, map[teap.IdentityType]bool{})
	if err != nil || c != user {
		t.Fatalf("expected the requested user credential, got %+v, %v", c, err)
	}
	// with no user credential, a user request is answered with the machine
	c, err = pickTEAPCredential([]TEAPCredential{machine}, teap.IdentityTypeUser, map[teap.IdentityType]bool{})
	if err != nil || c != machine {
		t.Fatalf("expected the machine credential, got %+v, %v", c, err)
	}
	c, err = pickTEAPCredential(creds, 0, map[teap.IdentityType]bool{teap.IdentityTypeMachine: true})
	if err != nil || c != user {
		t.Fatalf("expected the unused user credential, got %+v, %v", c, err)
	}
	_, err = pickTEAPCredential([]TEAPCredential{machine}, teap.IdentityTypeUser, map[teap.IdentityType]bool{teap.IdentityTypeMachine: true})
	if err == nil {
		t.Fatal("expected an error with every credential used")
	}
}

func TestSplitOuterTLVs(t *testing.T) {
	data, outer, err := splitOuterTLVs([]byte{0, 0, 0, 2, 0xaa, 0xbb, 0xcc})
	if err != nil || !bytes.Equal(data, []byte{0xaa}) || !bytes.Equal(outer, []byte{0xbb, 0xcc}) {
		t.Fatalf("unexpected split %x, %x, %v", data, outer, err)
	}
	if _, _, err = splitOuterTLVs([]byte{0, 0, 0, 2, 0xaa}); err == nil {
		t.Fatal("expected an error on outer TLVs longer than the message")
	}
}

// fakeTEAPServer runs the server side of TEAP: the tunnel, then one EAP-TLS
// inner method per identity type, each bound with Crypto-Binding TLVs
type fakeTEAPServer struct {
	tun        *fakeEAPTunnel
	pki        *testPKI
	tlsVersion uint16

	piggyback      bool // first Phase 2 request sent with the TLS 1.2 Finished
	splitRecords   bool // one TLS record per TLV
	maxFragment    int  // fragments outer messages longer than this
	separateResult bool // Result TLV after the last binding, on its own
	innerSuccess   bool // inner EAP-Success next to the last Intermediate-Result
	userFirst      bool // user authenticated before the machine
	failMachine    bool // machine method fails, the user one follows
	rejectUser     bool // session ends during the user's handshake
	peerRejects    bool // peer fails the machine handshake with an alert
	noCommitment   bool // TLS 1.3 inner methods end with an empty request
	// TLS 1.3 tunnel keys derived as for TLS 1.2
	tls12Derivation bool

	id              uint8
	serverOuterTLVs []byte
	identities      []string
	peerFailed      bool
	recvKey         []byte
	sendKey         []byte
}

func (fs *fakeTEAPServer) run() error {
	rd, err := fs.tun.recv()
	if err != nil {
		return err
	}
	if rd.Content == nil || rd.Content.Type != TypeIdentity {
		return fmt.Errorf("expected outer identity response")
	}

	// start with an Authority-ID outer TLV, which the Compound MACs cover
	fs.serverOuterTLVs = []byte{0, byte(teap.TLVTypeAuthorityID), 0, 4, 0xa, 0xb, 0xc, 0xd}
	start := binary.BigEndian.AppendUint32(nil, uint32(len(fs.serverOuterTLVs)))
	start = append(start, fs.serverOuterTLVs...)
	err = fs.sendOuter(eaptls.FlagsStart|eaptls.FlagsOuterTLVLength, start)
	if err != nil {
		return err
	}

	outer := &tlsServerTransport{send: func(b []byte) error { return fs.sendOuter(0, b) }, recv: fs.recvOuter}
	tunnel := tls.Server(outer, fs.tlsConfig(false))
	err = tunnel.Handshake()
	if err != nil {
		return fmt.Errorf("tunnel handshake: %w", err)
	}
	if !fs.piggyback {
		err = outer.awaitAck(fs.tlsVersion)
		if err != nil {
			return err
		}
	}
	keys, err := newRefKeys(tunnel.ConnectionState(), fs.tls12Derivation)
	if err != nil {
		return err
	}

	order := []teap.IdentityType{teap.IdentityTypeMachine, teap.IdentityTypeUser}
	if fs.userFirst {
		order[0], order[1] = order[1], order[0]
	}
	inner := &fakeInnerServer{tunnel: tunnel, split: fs.splitRecords}
	var binding []byte
	var failed bool
	for _, it := range order {
		inner.pending = append(inner.pending, teap.NewIdentityTypeTLV(it))
		m, tlvs, err := inner.exchange([]byte{byte(TypeIdentity)})
		if err != nil {
			return err
		}
		if err = keys.checkReply(m, tlvs, binding, failed, fs.serverOuterTLVs); err != nil {
			return err
		}
		if m.IdentityType != it {
			return fmt.Errorf("peer answered %s identity request with %s", it, m.IdentityType)
		}
		resp := &Datagram{}
		if err = resp.Deserialize(m.EAPPayload); err != nil {
			return err
		}
		fs.identities = append(fs.identities, string(resp.Content.Data))

		innerTLS := &tlsServerTransport{
			send: func(b []byte) error { return inner.send(append([]byte{byte(TypeTLS), 0}, b...)) },
			recv: inner.recvTLS,
		}
		err = inner.send([]byte{byte(TypeTLS), byte(eaptls.FlagsStart)})
		if err != nil {
			return err
		}
		if fs.rejectUser && it == teap.IdentityTypeUser {
			return fs.reject(inner, innerTLS)
		}
		ic := tls.Server(innerTLS, fs.tlsConfig(true))
		err = ic.Handshake()
		if fs.peerRejects {
			if err == nil {
				return fmt.Errorf("peer accepted the server it should reject")
			}
			return fs.endWithFailure(inner)
		}
		if err != nil {
			return fmt.Errorf("%s handshake: %w", it, err)
		}
		if fs.tlsVersion == tls.VersionTLS13 && !fs.noCommitment {
			// RFC 9190 commitment message
			if _, err = ic.Write([]byte{0}); err != nil {
				return err
			}
		}
		if err = innerTLS.awaitAck(tls.VersionTLS12); err != nil {
			return err
		}

		if fs.failMachine && it == teap.IdentityTypeMachine {
			binding, failed = nil, true
			inner.pending = append(inner.pending,
				teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusFailure),
				teap.NewErrorTLV(1020))
			continue
		}
		msk, err := refEAPTLSKey(ic.ConnectionState())
		if err != nil {
			return err
		}
		if err = keys.bind(msk); err != nil {
			return err
		}
		binding, failed = keys.bindingRequest(fs.serverOuterTLVs), false
		inner.pending = append(inner.pending,
			teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusSuccess),
			teap.TLV{Mandatory: true, Type: teap.TLVTypeCryptoBinding, Value: binding[4:]})
	}

	if fs.innerSuccess {
		inner.pending = append(inner.pending, teap.NewEAPPayloadTLV([]byte{byte(CodeSuccess), inner.id, 0, 4}))
	}
	if fs.separateResult {
		if err = inner.write(); err != nil {
			return err
		}
		m, tlvs, err := inner.read()
		if err != nil {
			return err
		}
		if err = keys.checkReply(m, tlvs, binding, failed, fs.serverOuterTLVs); err != nil {
			return err
		}
		binding = nil
	}
	inner.pending = append(inner.pending, teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusSuccess))
	if err = inner.write(); err != nil {
		return err
	}
	m, tlvs, err := inner.read()
	if err != nil {
		return err
	}
	if m.Result == teap.StatusFailure && len(m.ErrorCodes) > 0 {
		fs.peerFailed = true
		return fs.tun.send(newDatagram(&Header{Code: CodeFailure, Identifier: fs.id}, nil))
	}
	if m.Result != teap.StatusSuccess {
		return fmt.Errorf("peer did not confirm the result")
	}
	if binding != nil {
		if err = keys.checkReply(m, tlvs, binding, false, fs.serverOuterTLVs); err != nil {
			return err
		}
	}
	fs.recvKey, fs.sendKey = keys.sessionKeys()
	return fs.tun.send(newDatagram(&Header{Code: CodeSuccess, Identifier: fs.id}, nil))
}

// reject ends the session once the user's ClientHello arrives, and expects
// the peer to answer with its own failure before the EAP-Failure
func (fs *fakeTEAPServer) reject(inner *fakeInnerServer, innerTLS *tlsServerTransport) error {
	if _, err := innerTLS.recv(); err != nil {
		return err
	}
	inner.pending = append(inner.pending,
		teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusFailure),
		teap.NewErrorTLV(1020),
		teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusFailure))
	return fs.endWithFailure(inner)
}

// endWithFailure ends the session with the failures pending, expecting the
// peer to answer with its own, alone, before the EAP-Failure
func (fs *fakeTEAPServer) endWithFailure(inner *fakeInnerServer) error {
	if len(inner.pending) == 0 {
		inner.pending = append(inner.pending,
			teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusFailure),
			teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusFailure))
	}
	if err := inner.write(); err != nil {
		return err
	}
	m, _, err := inner.read()
	if err != nil {
		return err
	}
	if m.Result != teap.StatusFailure || m.IntermediateResult != teap.StatusFailure || m.CryptoBinding != nil || m.EAPPayload != nil {
		return fmt.Errorf("unexpected answer to the failure %+v", m)
	}
	fs.peerFailed = true
	return fs.tun.send(newDatagram(&Header{Code: CodeFailure, Identifier: fs.id}, nil))
}

func (fs *fakeTEAPServer) tlsConfig(clientAuth bool) *tls.Config {
	c := &tls.Config{
		Certificates:           []tls.Certificate{fs.pki.server},
		MinVersion:             fs.tlsVersion,
		MaxVersion:             fs.tlsVersion,
		SessionTicketsDisabled: true,
	}
	if clientAuth {
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = fs.pki.pool
	}
	return c
}

// sendOuter sends a TEAP request, fragmented over maxFragment
func (fs *fakeTEAPServer) sendOuter(flags eaptls.Flags, data []byte) error {
	first := true
	for {
		chunk := data
		more := fs.maxFragment > 0 && len(data) > fs.maxFragment
		f := flags | teap.Version
		var body []byte
		if more {
			chunk = data[:fs.maxFragment]
			f |= eaptls.FlagsMore
			if first {
				f |= eaptls.FlagsLength
				body = binary.BigEndian.AppendUint32(nil, uint32(len(data)))
			}
		}
		body = append(append([]byte{byte(f)}, body...), chunk...)
		fs.id++
		err := fs.tun.send(newDatagram(&Header{Code: CodeRequest, Identifier: fs.id}, &Content{Type: TypeTEAP, Data: body}))
		if err != nil || !more {
			return err
		}
		data = data[len(chunk):]
		first, flags = false, 0
		rd, err := fs.tun.recv()
		if err != nil {
			return err
		}
		if rd.Content == nil || !bytes.Equal(rd.Content.Data, []byte{teap.Version}) {
			return fmt.Errorf("expected acknowledgement of fragment")
		}
	}
}

// recvOuter reassembles a TEAP response, checking it is framed as Windows
// frames it: version in every packet, message length only on the first of
// several fragments
func (fs *fakeTEAPServer) recvOuter() ([]byte, error) {
	var msg []byte
	for first := true; ; first = false {
		rd, err := fs.tun.recv()
		if err != nil {
			return nil, err
		}
		if rd.Header.Code != CodeResponse || rd.Content == nil || rd.Content.Type != TypeTEAP || len(rd.Content.Data) == 0 {
			return nil, fmt.Errorf("expected TEAP response")
		}
		if rd.Header.Identifier != fs.id {
			return nil, fmt.Errorf("TEAP response does not match request identifier")
		}
		flags := eaptls.Flags(rd.Content.Data[0])
		body := rd.Content.Data[1:]
		if flags&eaptls.FlagsVersionMask != teap.Version || flags&(eaptls.FlagsStart|eaptls.FlagsOuterTLVLength) != 0 {
			return nil, fmt.Errorf("unexpected TEAP flags %#x", flags)
		}
		if flags&eaptls.FlagsLength != 0 {
			if !first || flags&eaptls.FlagsMore == 0 || len(body) < 4 {
				return nil, fmt.Errorf("message length outside the first of several fragments")
			}
			body = body[4:]
		}
		msg = append(msg, body...)
		if flags&eaptls.FlagsMore == 0 {
			return msg, nil
		}
		fs.id++
		err = fs.tun.send(newDatagram(&Header{Code: CodeRequest, Identifier: fs.id}, &Content{Type: TypeTEAP, Data: []byte{teap.Version}}))
		if err != nil {
			return nil, err
		}
	}
}

// fakeInnerServer carries inner EAP requests in EAP-Payload TLVs, with the
// TLVs pending for the next message to the peer
type fakeInnerServer struct {
	tunnel  *tls.Conn
	split   bool
	id      uint8
	pending []teap.TLV
}

func (fi *fakeInnerServer) send(content []byte) error {
	fi.id++
	l := 4 + len(content)
	p := append([]byte{byte(CodeRequest), fi.id, byte(l >> 8), byte(l)}, content...)
	fi.pending = append(fi.pending, teap.NewEAPPayloadTLV(p))
	return fi.write()
}

func (fi *fakeInnerServer) exchange(content []byte) (*teap.Message, []teap.TLV, error) {
	if err := fi.send(content); err != nil {
		return nil, nil, err
	}
	m, tlvs, err := fi.read()
	if err != nil {
		return nil, nil, err
	}
	if len(m.EAPPayload) < 2 || m.EAPPayload[1] != fi.id {
		return nil, nil, fmt.Errorf("inner response does not match request identifier")
	}
	return m, tlvs, nil
}

// recvTLS reassembles the TLS data of an inner EAP-TLS response
func (fi *fakeInnerServer) recvTLS() ([]byte, error) {
	var msg []byte
	for {
		m, _, err := fi.read()
		if err != nil {
			return nil, err
		}
		if m.Result != 0 || m.IntermediateResult != 0 {
			return nil, fmt.Errorf("result sent along an inner EAP response")
		}
		rd := &Datagram{}
		if err = rd.Deserialize(m.EAPPayload); err != nil {
			return nil, err
		}
		if rd.Header.Identifier != fi.id || rd.Content == nil || rd.Content.Type != TypeTLS {
			return nil, fmt.Errorf("expected EAP-TLS response to request %d", fi.id)
		}
		data, err := eaptls.CreateDataFromBuffer(rd.Content.Data)
		if err != nil {
			return nil, err
		}
		msg = append(msg, data.Data...)
		if data.Flags&eaptls.FlagsMore == 0 {
			return msg, nil
		}
		if err = fi.send([]byte{byte(TypeTLS), 0}); err != nil {
			return nil, err
		}
	}
}

func (fi *fakeInnerServer) write() error {
	defer func() { fi.pending = nil }()
	if !fi.split {
		_, err := fi.tunnel.Write(teap.MarshalTLVs(fi.pending))
		return err
	}
	for _, t := range fi.pending {
		if _, err := fi.tunnel.Write(t.AppendBinary(nil)); err != nil {
			return err
		}
	}
	return nil
}

func (fi *fakeInnerServer) read() (*teap.Message, []teap.TLV, error) {
	b := make([]byte, teapMessageMaxLen)
	n, err := fi.tunnel.Read(b)
	if err != nil {
		return nil, nil, err
	}
	m, err := teap.ParseMessage(b[:n])
	if err != nil {
		return nil, nil, err
	}
	tlvs, err := teap.ParseTLVs(b[:n])
	return m, tlvs, err
}

// refKeys derives TEAP keys as a server would, straight from RFC 9930
// section 6 for TLS 1.2 and RFC 9427 section 2.2 for TLS 1.3
type refKeys struct {
	cs    tls.ConnectionState
	tls13 bool
	h     func() hash.Hash
	simck []byte
	cmk   []byte
	nonce []byte
}

func newRefKeys(cs tls.ConnectionState, tls12Derivation bool) (*refKeys, error) {
	rk := &refKeys{cs: cs, tls13: cs.Version == tls.VersionTLS13 && !tls12Derivation, h: sha256.New}
	if strings.HasSuffix(tls.CipherSuiteName(cs.CipherSuite), "SHA384") {
		rk.h = sha512.New384
	}
	var context []byte
	if rk.tls13 {
		context = []byte{55}
	}
	var err error
	rk.simck, err = cs.ExportKeyingMaterial("EXPORTER: teap session key seed", context, 40)
	return rk, err
}

func (rk *refKeys) bind(msk []byte) error {
	imsk := make([]byte, 32)
	var imck []byte
	if rk.tls13 {
		var err error
		if imsk, err = rk.cs.ExportKeyingMaterial("TEAPbindkey@ietf.org", msk, 32); err != nil {
			return err
		}
		if imck, err = rk.cs.ExportKeyingMaterial("EXPORTER: Inner Methods Compound Keys", append(bytes.Clone(rk.simck), imsk...), 60); err != nil {
			return err
		}
	} else {
		copy(imsk, msk)
		imck = pHash(rk.h, rk.simck, append([]byte("Inner Methods Compound Keys"), imsk...), 60)
	}
	rk.simck, rk.cmk = imck[:40], imck[40:]
	return nil
}

// bindingRequest builds the wire form of a Crypto-Binding TLV request with
// both Compound MACs, the EMSK one wrong as Windows ignores it
func (rk *refKeys) bindingRequest(serverOuterTLVs []byte) []byte {
	rk.nonce = make([]byte, 32)
	_, _ = rand.Read(rk.nonce)
	rk.nonce[31] &^= 1
	b := []byte{0x80, 12, 0, 76, 0, 1, 1, 3<<4 | 0}
	b = append(b, rk.nonce...)
	b = append(b, bytes.Repeat([]byte{0xee}, 20)...)
	b = append(b, make([]byte, 20)...)
	mac := rk.compoundMAC(b, serverOuterTLVs)
	copy(b[len(b)-20:], mac)
	return b
}

func (rk *refKeys) compoundMAC(tlv, serverOuterTLVs []byte) []byte {
	buffer := bytes.Clone(tlv)
	clear(buffer[len(buffer)-40:])
	buffer = append(buffer, 55)
	buffer = append(buffer, serverOuterTLVs...)
	m := hmac.New(rk.h, rk.cmk)
	m.Write(buffer)
	return m.Sum(nil)[:20]
}

// checkReply checks the peer answered the server's last Intermediate-Result,
// with a valid Crypto-Binding TLV after a success
func (rk *refKeys) checkReply(m *teap.Message, tlvs []teap.TLV, request []byte, failed bool, serverOuterTLVs []byte) error {
	if failed {
		if m.IntermediateResult != teap.StatusFailure || m.CryptoBinding != nil {
			return fmt.Errorf("peer did not answer intermediate result failure")
		}
		return nil
	}
	if request == nil {
		if m.CryptoBinding != nil || m.IntermediateResult != 0 {
			return fmt.Errorf("unexpected intermediate result or crypto binding")
		}
		return nil
	}
	if m.IntermediateResult != teap.StatusSuccess {
		return fmt.Errorf("peer did not send intermediate result success")
	}
	var resp []byte
	for _, t := range tlvs {
		if t.Type == teap.TLVTypeCryptoBinding {
			resp = t.AppendBinary(nil)
		}
	}
	switch {
	case len(resp) != 80:
		return fmt.Errorf("peer did not send a crypto binding")
	case !bytes.Equal(resp[:8], []byte{0x80, 12, 0, 76, 0, 1, 1, 2<<4 | 1}):
		return fmt.Errorf("unexpected crypto binding response header %x", resp[:8])
	case !bytes.Equal(resp[8:39], rk.nonce[:31]) || resp[39] != rk.nonce[31]|1:
		return fmt.Errorf("unexpected crypto binding nonce")
	case !bytes.Equal(resp[40:60], make([]byte, 20)):
		return fmt.Errorf("peer sent an EMSK Compound MAC")
	case !hmac.Equal(resp[60:], rk.compoundMAC(resp, serverOuterTLVs)):
		return fmt.Errorf("peer MSK Compound MAC does not match")
	}
	return nil
}

func (rk *refKeys) sessionKeys() (recv, send []byte) {
	var msk []byte
	if rk.tls13 {
		msk, _ = rk.cs.ExportKeyingMaterial("EXPORTER: Session Key Generating Function", rk.simck, 64)
	} else {
		msk = pHash(rk.h, rk.simck, []byte("Session Key Generating Function"), 64)
	}
	return msk[:32], msk[32:64]
}

// refEAPTLSKey is the EAP-TLS MSK, RFC 5216 section 2.3 and RFC 9190 section 2.3
func refEAPTLSKey(cs tls.ConnectionState) ([]byte, error) {
	label, context := "client EAP encryption", []byte(nil)
	if cs.Version == tls.VersionTLS13 {
		label, context = "EXPORTER_EAP_TLS_Key_Material", []byte{13}
	}
	km, err := cs.ExportKeyingMaterial(label, context, 128)
	if err != nil {
		return nil, err
	}
	return km[:64], nil
}

// pHash is P_hash of RFC 5246 section 5, with the label already in the seed
func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	var out []byte
	a := seed
	for len(out) < n {
		m := hmac.New(h, secret)
		m.Write(a)
		a = m.Sum(nil)
		m = hmac.New(h, secret)
		m.Write(append(bytes.Clone(a), seed...))
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}

// tlsServerTransport is the server end of TLS carried in EAP requests: what
// TLS writes is sent once it waits for the peer's next response
type tlsServerTransport struct {
	send    func([]byte) error
	recv    func() ([]byte, error)
	in, out bytes.Buffer
}

func (st *tlsServerTransport) Read(b []byte) (int, error) {
	for st.in.Len() == 0 {
		if st.out.Len() > 0 {
			if err := st.flush(); err != nil {
				return 0, err
			}
		}
		d, err := st.recv()
		if err != nil {
			return 0, err
		}
		st.in.Write(d)
	}
	return st.in.Read(b)
}

func (st *tlsServerTransport) Write(b []byte) (int, error) {
	return st.out.Write(b)
}

func (st *tlsServerTransport) flush() error {
	d := bytes.Clone(st.out.Bytes())
	st.out.Reset()
	return st.send(d)
}

// awaitAck sends the server's last flight of a TLS 1.2 handshake, or any
// pending data, and reads the peer's empty acknowledgement
func (st *tlsServerTransport) awaitAck(version uint16) error {
	if st.out.Len() == 0 && version == tls.VersionTLS13 {
		return nil
	}
	if err := st.flush(); err != nil {
		return err
	}
	d, err := st.recv()
	if err != nil {
		return err
	}
	if len(d) != 0 {
		return fmt.Errorf("expected acknowledgement, got %d bytes", len(d))
	}
	return nil
}

func (st *tlsServerTransport) Close() error                     { return nil }
func (st *tlsServerTransport) LocalAddr() net.Addr              { return testAddr }
func (st *tlsServerTransport) RemoteAddr() net.Addr             { return testAddr }
func (st *tlsServerTransport) SetDeadline(time.Time) error      { return nil }
func (st *tlsServerTransport) SetReadDeadline(time.Time) error  { return nil }
func (st *tlsServerTransport) SetWriteDeadline(time.Time) error { return nil }

var testAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}

// fakeEAPTunnel hands EAP packets between the peer and the fake server
type fakeEAPTunnel struct {
	mtu      int
	toServer chan []byte
	toClient chan []byte
	failed   chan struct{}
}

func newFakeEAPTunnel(mtu int) *fakeEAPTunnel {
	if mtu == 0 {
		mtu = 60000
	}
	return &fakeEAPTunnel{
		mtu:      mtu,
		toServer: make(chan []byte, 1),
		toClient: make(chan []byte, 1),
		failed:   make(chan struct{}),
	}
}

func (ft *fakeEAPTunnel) fail() {
	close(ft.failed)
}

func (ft *fakeEAPTunnel) send(d *Datagram) error {
	var b bytes.Buffer
	if _, err := d.WriteTo(&b); err != nil {
		return err
	}
	ft.toClient <- b.Bytes()
	return nil
}

func (ft *fakeEAPTunnel) recv() (*Datagram, error) {
	select {
	case b := <-ft.toServer:
		d := &Datagram{}
		return d, d.Deserialize(b)
	case <-time.After(10 * time.Second):
		return nil, errors.New("timed out waiting for the peer")
	}
}

func (ft *fakeEAPTunnel) MaxDataSize() int {
	return ft.mtu
}

func (ft *fakeEAPTunnel) Read(b []byte) (int, error) {
	select {
	case d := <-ft.toClient:
		return copy(b, d), nil
	case <-ft.failed:
		return 0, errors.New("server failed")
	case <-time.After(10 * time.Second):
		return 0, errors.New("timed out waiting for the server")
	}
}

func (ft *fakeEAPTunnel) Write(b []byte) (int, error) {
	ft.toServer <- bytes.Clone(b)
	return len(b), nil
}

func (ft *fakeEAPTunnel) Close() error                     { return nil }
func (ft *fakeEAPTunnel) LocalAddr() net.Addr              { return testAddr }
func (ft *fakeEAPTunnel) RemoteAddr() net.Addr             { return testAddr }
func (ft *fakeEAPTunnel) SetDeadline(time.Time) error      { return nil }
func (ft *fakeEAPTunnel) SetReadDeadline(time.Time) error  { return nil }
func (ft *fakeEAPTunnel) SetWriteDeadline(time.Time) error { return nil }

type testPKI struct {
	pool       *x509.CertPool
	server     tls.Certificate
	caPath     string
	devicePath string
	userPath   string
}

func newTestPKI(t *testing.T) *testPKI {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(serial int64, tmpl *x509.Certificate) ([]byte, tls.Certificate) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber = big.NewInt(serial)
		tmpl.NotBefore = ca.NotBefore
		tmpl.NotAfter = ca.NotAfter
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		p = append(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
		cert, err := tls.X509KeyPair(p, p)
		if err != nil {
			t.Fatal(err)
		}
		return p, cert
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	pki := &testPKI{pool: x509.NewCertPool()}
	pki.pool.AddCert(ca)
	pki.caPath = write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	// a DNS name only, which both the tunnel and the inner methods check
	_, pki.server = issue(2, &x509.Certificate{
		Subject:     pkix.Name{CommonName: testServerName},
		DNSNames:    []string{testServerName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	device, _ := issue(3, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "PC1"},
		DNSNames:    []string{testMachineName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	pki.devicePath = write("device.pem", device)
	user, _ := issue(4, &x509.Certificate{
		Subject:         pkix.Name{CommonName: "Alice"},
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{upnSubjectAltName(testUserUPN, "alice@mail.example.test")},
	})
	pki.userPath = write("user.pem", user)
	return pki
}

func upnSubjectAltName(upn, email string) pkix.Extension {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(email))
		})
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidUserPrincipalName)
			b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(upn))
				})
			})
		})
	})
	return pkix.Extension{Id: oidExtensionSubjectAltName, Value: b.BytesOrPanic()}
}
