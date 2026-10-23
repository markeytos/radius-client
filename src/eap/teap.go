/*
Copyright © 2026 Keytos alan@keytos.io

# Define Tunnel EAP (TEAP) authentication session with EAP-TLS inner methods

The peer approximates the Windows TEAP supplicant: it presents no certificate
when building the tunnel, answers the Identity-Type the server asks for with the
matching machine or user credential, authenticates each with EAP-TLS, and binds
every inner method with the MSK Compound MAC only, which RFC 9930 section 5.2
describes as the behaviour of the most well-known supplicant.
*/
package eap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/markeytos/radius-client/src/eap/teap"
	eaptls "github.com/markeytos/radius-client/src/eap/tls"
)

const (
	eapTLS13KeyingLabel = "EXPORTER_EAP_TLS_Key_Material"
	teapMessageMaxLen   = 65536
)

// errInnerMethodEnded stops an inner method when the server ends it, leaving
// the server's message to be answered by the TEAP session
var errInnerMethodEnded = errors.New("teap: server ended the inner method")

// errEndOfMessage ends the read of a server message split over TLS records.
// It is temporary, so that TLS keeps the connection usable.
var errEndOfMessage net.Error = endOfMessageError{}

type endOfMessageError struct{}

func (endOfMessageError) Error() string   { return "teap: end of server message" }
func (endOfMessageError) Timeout() bool   { return false }
func (endOfMessageError) Temporary() bool { return true }

type TEAP struct {
	*TLS
	client             *tls.Conn
	tunnelKeyLogWriter *os.File
	innerTLSVersion    string
	serverName         string
	receivedVersion    uint8
	serverOuterTLVs    []byte
	keys               *teap.KeySchedule
	pending            *teap.Message
	writeBuffer        []byte
	collecting         bool
	ackFinished        bool
	warnedDerivation   bool
}

func CreateTEAP(session *Session, caCert, tlsVersion, serverName, tlsTunnelKeyLogFilename string, tlsSkipHostnameCheck bool) (*TEAP, error) {
	t, err := internalCreateTLS(session, caCert, tlsVersion, tlsSkipHostnameCheck, TypeTEAP)
	if err != nil {
		return nil, err
	}
	tp := &TEAP{TLS: t, innerTLSVersion: tlsVersion, serverName: serverName}
	err = tp.readStart(session.lastReadDatagram.Content.Data)
	if err != nil {
		return nil, err
	}
	t.packetVersion = teap.Version

	// no certificate of the peer's own while building the tunnel, the machine
	// and the user are only authenticated by the inner methods
	tlsConfig := &tls.Config{
		RootCAs:                t.rootCAs,
		MinVersion:             t.tlsVersion,
		MaxVersion:             t.tlsVersion,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     tlsSkipHostnameCheck,
		ServerName:             serverName,
		VerifyPeerCertificate:  t.verifyCertificateChain,
		Renegotiation:          tls.RenegotiateNever,
	}
	if tlsTunnelKeyLogFilename != "" {
		f, err := os.OpenFile(tlsTunnelKeyLogFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		tlsConfig.KeyLogWriter = f
		tp.tunnelKeyLogWriter = f
	}
	tp.client = tls.Client(tp, tlsConfig)
	return tp, nil
}

// readStart negotiates the version and keeps the Outer TLVs of the TEAP/Start
// message, which every Compound MAC covers
func (tp *TEAP) readStart(b []byte) error {
	data, err := eaptls.CreateDataFromBuffer(b)
	if err != nil {
		return fmt.Errorf("teap: invalid start message: %w", err)
	}
	if data.Flags&eaptls.FlagsStart == 0 {
		return fmt.Errorf("teap: server did not send a start message")
	}
	tp.receivedVersion = uint8(data.Flags & eaptls.FlagsVersionMask)
	if tp.receivedVersion < teap.Version {
		return fmt.Errorf("teap: unsupported server version %d", tp.receivedVersion)
	}
	if data.Flags&eaptls.FlagsOuterTLVLength != 0 {
		_, tp.serverOuterTLVs, err = splitOuterTLVs(data.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (tp *TEAP) Authenticate(credentials []TEAPCredential, caCert, keyLogFilename string) error {
	defer tp.closeKeyLog()

	err := tp.client.Handshake()
	if err != nil {
		return err
	}
	cs := tp.client.ConnectionState()
	// a TLS 1.2 server sends the last handshake message, which the peer
	// acknowledges unless the server sent its first request along
	tp.ackFinished = cs.Version != tls.VersionTLS13 && tp.lastAction == sessionLastActionReadDatagram
	tp.keys, err = teap.NewKeySchedule(cs)
	if err != nil {
		return fmt.Errorf("teap: failed to derive session key seed: %w", err)
	}

	used := make(map[teap.IdentityType]bool)
	var reply []teap.TLV
	var innerMSK []byte
	// whether the last inner method was bound, after which a Result TLV may
	// come on its own
	bound := false
	for {
		m, err := tp.nextMessage()
		if err != nil {
			return tp.abort(err)
		}
		payload, err := innerRequest(m)
		if err != nil {
			return tp.abort(err)
		}

		if m.Fatal() {
			return tp.fail(m)
		}
		if m.IntermediateResult == teap.StatusFailure {
			// the peer answers with its own result, and the server either moves
			// on to another inner method or ends the session
			innerMSK = nil
			bound = false
			reply = append(reply, teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusFailure))
		}

		if m.CryptoBinding != nil {
			if m.IntermediateResult != teap.StatusSuccess && m.Result != teap.StatusSuccess {
				return tp.abort(&teap.ProtocolError{Code: teap.ErrorUnexpectedTLVs, Err: errors.New("teap: server sent a Crypto-Binding TLV without a success result")})
			}
			cb, err := tp.cryptoBindingResponse(m.CryptoBinding, innerMSK)
			if err != nil {
				return tp.abort(err)
			}
			innerMSK = nil
			bound = true
			if m.IntermediateResult == teap.StatusSuccess {
				reply = append(reply, teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusSuccess))
			}
			reply = append(reply, cb.TLV())
		} else if m.IntermediateResult == teap.StatusSuccess || (m.Result == teap.StatusSuccess && !bound) {
			return tp.abort(&teap.ProtocolError{Code: teap.ErrorTunnelCompromise, Err: errors.New("teap: server sent a success result without a Crypto-Binding TLV")})
		}

		if m.Result == teap.StatusSuccess {
			reply = append([]teap.TLV{teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusSuccess)}, reply...)
			err = tp.writeTLVs(reply)
			if err != nil {
				return err
			}
			rd, err := tp.readOuter()
			if err != nil {
				return err
			}
			if rd.Header.Code != CodeSuccess {
				return fmt.Errorf("authentication failed")
			}
			tp.RecvKey, tp.SendKey, err = tp.keys.SessionKeys()
			return err
		}

		if payload == nil {
			if len(reply) == 0 {
				return tp.abort(&teap.ProtocolError{Code: teap.ErrorUnexpectedTLVs, Err: errors.New("teap: server sent a message without anything to respond to")})
			}
			err = tp.writeTLVs(reply)
			if err != nil {
				return err
			}
			reply = nil
			continue
		}

		cred, err := pickTEAPCredential(credentials, m.IdentityType, used)
		if err != nil {
			return tp.abort(err)
		}
		used[cred.IdentityType] = true
		if m.IdentityType != 0 {
			reply = append(reply, teap.NewIdentityTypeTLV(cred.IdentityType))
		}
		bound = false
		innerMSK, err = tp.innerEAPTLS(cred, payload, reply, caCert, keyLogFilename)
		reply = nil
		if errors.Is(err, errInnerMethodEnded) {
			// the server's message that ended it is handled next
			continue
		}
		if err != nil {
			return tp.abort(fmt.Errorf("teap: %s authentication: %w", cred.IdentityType, err))
		}
	}
}

// innerEAPTLS authenticates a credential with EAP-TLS, starting from the
// request the server already sent, and returns the MSK of the inner method
func (tp *TEAP) innerEAPTLS(cred TEAPCredential, request []byte, reply []teap.TLV, caCert, keyLogFilename string) ([]byte, error) {
	it := &teapInnerTunnel{teap: tp, request: request, reply: reply}
	inner, err := internalCreateTLS(NewSession(it, cred.Identity, true), caCert, tp.innerTLSVersion, tp.skipHostnameCheck, TypeTLS)
	if err != nil {
		return nil, err
	}
	inner.serverName = tp.serverName
	inner.commitmentOptional = true
	tc, err := inner.handshake(cred.CertPath, keyLogFilename)
	if err != nil {
		return nil, err
	}
	return eapTLSMasterSessionKey(tc)
}

// cryptoBindingResponse checks the server's MSK Compound MAC and answers with
// the peer's own. The EMSK Compound MAC is neither checked nor sent, so a
// server that offers only that one cannot be answered.
func (tp *TEAP) cryptoBindingResponse(req *teap.CryptoBinding, innerMSK []byte) (*teap.CryptoBinding, error) {
	resp, err := req.Response(tp.receivedVersion)
	if err != nil {
		return nil, err
	}
	if !req.Flags.HasMSK() {
		return nil, &teap.ProtocolError{Code: teap.ErrorMissingMSKCompoundMAC, Err: errors.New("teap: server sent only an EMSK Compound MAC, which this peer does not use")}
	}

	if innerMSK != nil || !tp.keys.HasCMK() {
		if err = tp.keys.Next(innerMSK); err != nil {
			return nil, err
		}
	}
	if !tp.keys.VerifyMSKCompoundMAC(req, tp.serverOuterTLVs, nil) {
		return nil, &teap.ProtocolError{Code: teap.ErrorMSKCompoundMAC, Err: errors.New("teap: server MSK Compound MAC does not match")}
	}
	if tp.client.ConnectionState().Version == tls.VersionTLS13 && tp.keys.TLS12Derivation() && !tp.warnedDerivation {
		tp.warnedDerivation = true
		slog.Warn("teap: server derives the keys of a TLS 1.3 tunnel as for TLS 1.2, not as RFC 9427 defines")
	}

	resp.Flags = teap.CryptoBindingFlagsMSK
	resp.MSKCompoundMAC = tp.keys.CompoundMAC(resp, tp.serverOuterTLVs, nil)
	return resp, nil
}

// fail answers a failure the server reported with the peer's own, for the
// server to end the session with an EAP-Failure (RFC 9930 section 3.9.3)
func (tp *TEAP) fail(m *teap.Message) error {
	reply := []teap.TLV{teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusFailure)}
	// a success would need a Crypto-Binding TLV, which may not come with a
	// failure Result
	if m.IntermediateResult != 0 {
		reply = append(reply, teap.NewStatusTLV(teap.TLVTypeIntermediateResult, teap.StatusFailure))
	}
	tp.terminate(reply)
	return m.Err()
}

// abort reports an error of the peer to the server and ends the session
func (tp *TEAP) abort(err error) error {
	// a failed inner TLS handshake leaves its alert to send, which goes on its
	// own as no EAP-Payload may come with a failure Result
	if len(tp.writeBuffer) > 0 && tp.lastAction != sessionLastActionError {
		m, rerr := tp.readMessage()
		if rerr == nil && (m.Fatal() || m.IntermediateResult == teap.StatusFailure) {
			_ = tp.fail(m)
			return err
		}
	}
	code := teap.ErrorInnerMethod
	var pe *teap.ProtocolError
	if errors.As(err, &pe) {
		code = pe.Code
	}
	tp.terminate([]teap.TLV{teap.NewErrorTLV(code), teap.NewStatusTLV(teap.TLVTypeResult, teap.StatusFailure)})
	return err
}

// terminate sends the peer's failure and reads the server's EAP-Failure. The
// session failed already, so a server that does not answer is only logged.
func (tp *TEAP) terminate(reply []teap.TLV) {
	// nothing reaches the server once the exchange with it broke down, or
	// once it ended the session in the clear
	if tp.lastAction == sessionLastActionError {
		return
	}
	if rd := tp.lastReadDatagram; rd != nil && (rd.Header.Code == CodeSuccess || rd.Header.Code == CodeFailure) {
		return
	}
	err := tp.writeTLVs(reply)
	if err == nil {
		var rd *Datagram
		rd, err = tp.readOuter()
		if err == nil && rd.Header.Code != CodeFailure {
			err = fmt.Errorf("server answered with EAP %s", rd.Header.Code)
		}
	}
	if err != nil {
		slog.Warn("teap: failed to end the session with the server",
			"error", err,
		)
	}
}

// nextMessage returns the server's message that ended an inner method, or
// else reads the next one
func (tp *TEAP) nextMessage() (*teap.Message, error) {
	if m := tp.pending; m != nil {
		tp.pending = nil
		return m, nil
	}
	return tp.readMessage()
}

// readMessage reads a whole Phase 2 message, which the server may have split
// over several TLS records
func (tp *TEAP) readMessage() (*teap.Message, error) {
	b := make([]byte, teapMessageMaxLen)
	n, err := tp.client.Read(b)
	if err != nil {
		return nil, err
	}
	tp.collecting = true
	defer func() { tp.collecting = false }()
	for {
		if n == len(b) {
			return nil, &teap.ProtocolError{Code: teap.ErrorUnexpectedTLVs, Err: errors.New("teap: server message too long")}
		}
		rn, err := tp.client.Read(b[n:])
		if errors.Is(err, errEndOfMessage) {
			break
		}
		if err != nil {
			return nil, err
		}
		n += rn
	}
	return teap.ParseMessage(b[:n])
}

func (tp *TEAP) writeTLVs(tlvs []teap.TLV) error {
	_, err := tp.client.Write(teap.MarshalTLVs(tlvs))
	return err
}

// readOuter sends what is pending and reads the server's next EAP packet
// outside of the tunnel
func (tp *TEAP) readOuter() (*Datagram, error) {
	err := tp.flush()
	if err != nil {
		return nil, err
	}
	rd := &Datagram{}
	_, err = tp.ReadDatagram(rd)
	return rd, err
}

// Read hands TLS the server's next message. When the server sent no request
// along with its last TLS 1.2 handshake message, the peer acknowledges that
// message to receive one.
func (tp *TEAP) Read(b []byte) (int, error) {
	received := len(tp.readBuffer) > 0 || tp.readMore
	if tp.collecting && !received {
		return 0, errEndOfMessage
	}
	err := tp.flush()
	if err != nil {
		return 0, err
	}
	if tp.ackFinished && !received && tp.lastAction == sessionLastActionReadDatagram {
		tp.ackFinished = false
		_, err = tp.WriteDatagram(tp.newDatagram(tp.ackContent()))
		if err != nil {
			return 0, err
		}
	}
	return tp.TLS.Read(b)
}

// Write holds TLS data until the peer waits for the server, so that a TLS
// flight and the Phase 2 data after it go out in a single message
func (tp *TEAP) Write(b []byte) (int, error) {
	tp.writeBuffer = append(tp.writeBuffer, b...)
	return len(b), nil
}

func (tp *TEAP) flush() error {
	if len(tp.writeBuffer) == 0 {
		return nil
	}
	tp.ackFinished = false
	_, err := tp.TLS.Write(tp.writeBuffer)
	tp.writeBuffer = nil
	return err
}

func (tp *TEAP) closeKeyLog() {
	if tp.tunnelKeyLogWriter == nil {
		return
	}
	err := tp.tunnelKeyLogWriter.Close()
	if err != nil {
		slog.Error("failed to close key log file",
			"error", err,
		)
	}
}

// innerRequest returns the EAP request in the EAP-Payload TLV, if any. An
// inner EAP-Success or EAP-Failure, which servers are not meant to send, only
// repeats the outcome of the inner method; one without an Intermediate-Result
// TLV stands for it.
func innerRequest(m *teap.Message) ([]byte, error) {
	if len(m.EAPPayload) == 0 {
		return nil, nil
	}
	if len(m.EAPPayload) < headerLen {
		return nil, &teap.ProtocolError{Code: teap.ErrorUnexpectedTLVs, Err: errors.New("teap: server sent a truncated inner EAP packet")}
	}
	switch Code(m.EAPPayload[0]) {
	case CodeRequest:
		return m.EAPPayload, nil
	case CodeSuccess:
		return nil, nil
	case CodeFailure:
		if m.IntermediateResult == 0 {
			m.IntermediateResult = teap.StatusFailure
		}
		return nil, nil
	}
	return nil, &teap.ProtocolError{Code: teap.ErrorUnexpectedTLVs, Err: fmt.Errorf("teap: server sent an inner EAP %s", Code(m.EAPPayload[0]))}
}

// pickTEAPCredential answers the Identity-Type the server asks for with that
// credential, or else with one that has not authenticated yet, as RFC 9930
// section 4.2.3 asks of peers
func pickTEAPCredential(credentials []TEAPCredential, requested teap.IdentityType, used map[teap.IdentityType]bool) (TEAPCredential, error) {
	for _, c := range credentials {
		if c.IdentityType == requested && !used[c.IdentityType] {
			return c, nil
		}
	}
	for _, c := range credentials {
		if !used[c.IdentityType] {
			return c, nil
		}
	}
	err := errors.New("teap: server requested another identity, but no credential is left to send")
	if requested != 0 {
		err = fmt.Errorf("teap: server requested a %s identity, but no credential is left to send", requested)
	}
	return TEAPCredential{}, err
}

func eapTLSMasterSessionKey(tc *tls.Conn) ([]byte, error) {
	cs := tc.ConnectionState()
	var km []byte
	var err error
	if cs.Version == tls.VersionTLS13 {
		// RFC 9190 section 2.3
		km, err = cs.ExportKeyingMaterial(eapTLS13KeyingLabel, []byte{byte(TypeTLS)}, 128)
	} else {
		km, err = cs.ExportKeyingMaterial(eapMasterKeyLabel, nil, 128)
	}
	if err != nil {
		return nil, err
	}
	return km[:64], nil
}

// splitOuterTLVs separates the TLS data of a TEAP message from the Outer TLVs
// that follow it, whose length leads the TLS data
func splitOuterTLVs(b []byte) (tlsData, outerTLVs []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("teap: missing outer TLV length")
	}
	l := int(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	b = b[4:]
	if l > len(b) {
		return nil, nil, fmt.Errorf("teap: outer TLVs longer than message")
	}
	return b[:len(b)-l], b[len(b)-l:], nil
}

// teapInnerTunnel carries the EAP packets of an inner method in EAP-Payload
// TLVs, alongside the TLVs answering the server's previous message
type teapInnerTunnel struct {
	teap    *TEAP
	request []byte
	reply   []teap.TLV
}

// MaxDataSize fragments inner EAP-TLS messages as the outer ones are
func (it *teapInnerTunnel) MaxDataSize() int {
	return it.teap.Tunnel.MaxDataSize()
}

func (it *teapInnerTunnel) Read(b []byte) (int, error) {
	if it.request == nil {
		m, err := it.teap.readMessage()
		if err != nil {
			return 0, err
		}
		p, err := innerRequest(m)
		if err != nil {
			return 0, err
		}
		if p == nil || m.Fatal() || m.IntermediateResult != 0 || m.Result != 0 || m.CryptoBinding != nil {
			it.teap.pending = m
			return 0, errInnerMethodEnded
		}
		it.request = p
	}
	n := copy(b, it.request)
	it.request = nil
	return n, nil
}

func (it *teapInnerTunnel) Write(b []byte) (int, error) {
	// the request starting the inner method was received with the last message
	if len(b) == 0 {
		return 0, nil
	}
	tlvs := append(it.reply, teap.NewEAPPayloadTLV(append([]byte(nil), b...)))
	it.reply = nil
	err := it.teap.writeTLVs(tlvs)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (it *teapInnerTunnel) Close() error {
	return nil
}

func (it *teapInnerTunnel) LocalAddr() net.Addr {
	return it.teap.LocalAddr()
}

func (it *teapInnerTunnel) RemoteAddr() net.Addr {
	return it.teap.RemoteAddr()
}

func (it *teapInnerTunnel) SetDeadline(t time.Time) error {
	return it.teap.SetDeadline(t)
}

func (it *teapInnerTunnel) SetReadDeadline(t time.Time) error {
	return it.teap.SetReadDeadline(t)
}

func (it *teapInnerTunnel) SetWriteDeadline(t time.Time) error {
	return it.teap.SetWriteDeadline(t)
}
