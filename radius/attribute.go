/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS attributes of the following format

	 0                   1                   2
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	|     Type      |    Length     |  Value ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

const (
	maxAttributeLen = 255 - 2
)

type AttributeMap map[AttributeType]string

type Attribute struct {
	Type  AttributeType
	Value []byte
}

func newAttribute(t AttributeType, v []byte) *Attribute {
	if len(v) > maxAttributeLen {
		panic("length of value of attribute too big")
	}
	return &Attribute{Type: t, Value: v}
}

func newEmptyAttribute(t AttributeType, l int) *Attribute {
	if l > maxAttributeLen {
		panic("length of empty attribute too big")
	}
	return newAttribute(t, make([]byte, l))
}

func newUserPasswordAttribute(password, secret string, authenticator []byte) *Attribute {
	s := []byte(secret)
	pw := []byte(password)
	enc := make([]byte, 0, ((len(pw)-1)|(15))+1)

	hash := md5.New()
	hash.Write(s)
	hash.Write(authenticator)
	enc = hash.Sum(enc)

	for i := 0; i < 16 && i < len(pw); i++ {
		enc[i] ^= pw[i]
	}

	for i := 16; i < len(pw); i += 16 {
		hash.Reset()
		hash.Write(s)
		hash.Write(enc[i-16 : i])
		enc = hash.Sum(enc)
		for j := 0; j < 16 && i+j < len(pw); j++ {
			enc[i+j] ^= pw[i+j]
		}
	}

	return newAttribute(AttributeTypeUserPassword, enc)
}

func newEmptyMessageAuthenticator() *Attribute {
	return newEmptyAttribute(AttributeTypeMessageAuthenticator, md5.Size)
}

func writeMessageAuthenticator(d *Datagram, ma *Attribute, secret string) error {
	if ma.Type != AttributeTypeMessageAuthenticator || len(ma.Value) != md5.Size {
		return fmt.Errorf("invalid message authenticator attribute")
	}
	for i := range ma.Value {
		ma.Value[i] = 0
	}
	mac := hmac.New(md5.New, []byte(secret))
	_, err := d.WriteTo(mac)
	if err != nil {
		return err
	}
	sum := mac.Sum(nil)
	copy(ma.Value, sum)
	return nil
}

func serializeAttributeMap(attrMap AttributeMap) ([]*Attribute, error) {
	attrs := make([]*Attribute, 0, len(attrMap))
	for t, v := range attrMap {
		switch t {
		case AttributeTypeUserName,
			AttributeTypeFilterId,
			AttributeTypeReplyMessage,
			AttributeTypeCallbackNumber,
			AttributeTypeCallbackId,
			AttributeTypeFramedRoute,
			AttributeTypeCalledStationId,
			AttributeTypeCallingStationId,
			AttributeTypeNasIdentifier,
			AttributeTypeLoginLatService,
			AttributeTypeLoginLatNode,
			AttributeTypeAcctSessionId,
			AttributeTypeAcctMultiSessionId,
			AttributeTypeLoginLatPort,
			AttributeTypeTunnelPrivateGroupId,
			AttributeTypeEgressVlanName:
			attrs = append(attrs, newAttribute(t, []byte(v)))
		case AttributeTypeState,
			AttributeTypeClass,
			AttributeTypeProxyState,
			AttributeTypeLoginLatGroup,
			AttributeTypeFramedAppleTalkZone,
			AttributeTypeUserPriorityTable:
			a := newEmptyAttribute(t, len(v)/2)
			_, err := hex.Decode(a.Value, []byte(v))
			if err != nil {
				return attrs, fmt.Errorf("invalid hex string: %w", err)
			}
			attrs = append(attrs, a)
		case AttributeTypeMessageAuthenticator:
			attrs = append(attrs, newEmptyMessageAuthenticator())
		case AttributeTypeNasIpAddress,
			AttributeTypeFramedIpAddress,
			AttributeTypeFramedIpNetmask,
			AttributeTypeLoginIpHost:
			ip := net.ParseIP(v)
			ip = ip.To4()
			if ip == nil {
				return attrs, fmt.Errorf("invalid IPv4 address: %s", v)
			}
			attrs = append(attrs, newAttribute(t, ip))
		case AttributeTypeNasPort,
			AttributeTypeFramedMtu,
			AttributeTypeLoginTcpPort,
			AttributeTypeFramedIpxNetwork,
			AttributeTypeSessionTimeout,
			AttributeTypeIdleTimeout,
			AttributeTypeFramedAppleTalkLink,
			AttributeTypeFramedAppleTalkNetwork,
			AttributeTypeAcctDelayTime,
			AttributeTypeAcctInputOctets,
			AttributeTypeAcctOutputOctets,
			AttributeTypeAcctSessionTime,
			AttributeTypeAcctInputPackets,
			AttributeTypeAcctOutputPackets,
			AttributeTypeAcctLinkCount,
			AttributeTypePortLimit:
			i, err := strconv.ParseUint(v, 10, 0)
			if err != nil {
				return attrs, err
			}
			a := newEmptyAttribute(t, 4)
			binary.BigEndian.PutUint32(a.Value, uint32(i))
			attrs = append(attrs, a)
		case AttributeTypeServiceType,
			AttributeTypeFramedProtocol,
			AttributeTypeFramedRouting,
			AttributeTypeFramedCompression,
			AttributeTypeLoginService,
			AttributeTypeTerminationAction,
			AttributeTypeErrorCause,
			AttributeTypeAcctStatusType,
			AttributeTypeAcctAuthentic,
			AttributeTypeAcctTerminateCause,
			AttributeTypeNasPortType,
			AttributeTypeTunnelType,
			AttributeTypeTunnelMediumType,
			AttributeTypeIngressFilters:
			return attrs, fmt.Errorf("TODO: enums not implemented yet")
		case AttributeTypeVendorSpecific:
			return attrs, fmt.Errorf("TODO: VSA not implemented yet")
		case AttributeTypeEgressVlanId:
			return attrs, fmt.Errorf("TODO: egress VLAN ID not implemented yet")
		case AttributeTypeUserPassword:
			return attrs, fmt.Errorf("use other constructors for encrypted attributes")
		default:
			return attrs, fmt.Errorf("unimplemented attribute: %s", t.String())
		}
	}
	return attrs, nil
}

type AttributeType uint8

const (
	AttributeTypeUserName               AttributeType = 1
	AttributeTypeUserPassword           AttributeType = 2
	AttributeTypeChapPassword           AttributeType = 3
	AttributeTypeNasIpAddress           AttributeType = 4
	AttributeTypeNasPort                AttributeType = 5
	AttributeTypeServiceType            AttributeType = 6
	AttributeTypeFramedProtocol         AttributeType = 7
	AttributeTypeFramedIpAddress        AttributeType = 8
	AttributeTypeFramedIpNetmask        AttributeType = 9
	AttributeTypeFramedRouting          AttributeType = 10
	AttributeTypeFilterId               AttributeType = 11
	AttributeTypeFramedMtu              AttributeType = 12
	AttributeTypeFramedCompression      AttributeType = 13
	AttributeTypeLoginIpHost            AttributeType = 14
	AttributeTypeLoginService           AttributeType = 15
	AttributeTypeLoginTcpPort           AttributeType = 16
	AttributeTypeReplyMessage           AttributeType = 18
	AttributeTypeCallbackNumber         AttributeType = 19
	AttributeTypeCallbackId             AttributeType = 20
	AttributeTypeFramedRoute            AttributeType = 22
	AttributeTypeFramedIpxNetwork       AttributeType = 23
	AttributeTypeState                  AttributeType = 24
	AttributeTypeClass                  AttributeType = 25
	AttributeTypeVendorSpecific         AttributeType = 26
	AttributeTypeSessionTimeout         AttributeType = 27
	AttributeTypeIdleTimeout            AttributeType = 28
	AttributeTypeTerminationAction      AttributeType = 29
	AttributeTypeCalledStationId        AttributeType = 30
	AttributeTypeCallingStationId       AttributeType = 31
	AttributeTypeNasIdentifier          AttributeType = 32
	AttributeTypeProxyState             AttributeType = 33
	AttributeTypeLoginLatService        AttributeType = 34
	AttributeTypeLoginLatNode           AttributeType = 35
	AttributeTypeLoginLatGroup          AttributeType = 36
	AttributeTypeFramedAppleTalkLink    AttributeType = 37
	AttributeTypeFramedAppleTalkNetwork AttributeType = 38
	AttributeTypeFramedAppleTalkZone    AttributeType = 39
	AttributeTypeErrorCause             AttributeType = 101

	// Accounting Attributes
	AttributeTypeAcctStatusType     AttributeType = 40
	AttributeTypeAcctDelayTime      AttributeType = 41
	AttributeTypeAcctInputOctets    AttributeType = 42
	AttributeTypeAcctOutputOctets   AttributeType = 43
	AttributeTypeAcctSessionId      AttributeType = 44
	AttributeTypeAcctAuthentic      AttributeType = 45
	AttributeTypeAcctSessionTime    AttributeType = 46
	AttributeTypeAcctInputPackets   AttributeType = 47
	AttributeTypeAcctOutputPackets  AttributeType = 48
	AttributeTypeAcctTerminateCause AttributeType = 49
	AttributeTypeAcctMultiSessionId AttributeType = 50
	AttributeTypeAcctLinkCount      AttributeType = 51

	AttributeTypeChapChallenge AttributeType = 60
	AttributeTypeNasPortType   AttributeType = 61
	AttributeTypePortLimit     AttributeType = 62
	AttributeTypeLoginLatPort  AttributeType = 63

	// Tunnel for Cisco
	AttributeTypeTunnelType           AttributeType = 64
	AttributeTypeTunnelMediumType     AttributeType = 65
	AttributeTypeTunnelPrivateGroupId AttributeType = 81

	// VLAN Attributes
	AttributeTypeEgressVlanId      AttributeType = 56
	AttributeTypeIngressFilters    AttributeType = 57
	AttributeTypeEgressVlanName    AttributeType = 58
	AttributeTypeUserPriorityTable AttributeType = 59

	// RADIUS/EAP attributes
	AttributeTypeEapMessage           AttributeType = 79
	AttributeTypeMessageAuthenticator AttributeType = 80
)

func (t AttributeType) String() string {
	switch t {
	case AttributeTypeUserName:
		return "User-Name"
	case AttributeTypeUserPassword:
		return "User-Password"
	case AttributeTypeChapPassword:
		return "CHAP-Password"
	case AttributeTypeNasIpAddress:
		return "NAS-IP-Address"
	case AttributeTypeNasPort:
		return "NAS-Port"
	case AttributeTypeServiceType:
		return "Service-Type"
	case AttributeTypeFramedProtocol:
		return "Framed-Protocol"
	case AttributeTypeFramedIpAddress:
		return "Framed-IP-Address"
	case AttributeTypeFramedIpNetmask:
		return "Framed-IP-Netmask"
	case AttributeTypeFramedRouting:
		return "Framed-Routing"
	case AttributeTypeFilterId:
		return "Filter-Id"
	case AttributeTypeFramedMtu:
		return "Framed-MTU"
	case AttributeTypeFramedCompression:
		return "Framed-Compression"
	case AttributeTypeLoginIpHost:
		return "Login-IP-Host"
	case AttributeTypeLoginService:
		return "Login-Service"
	case AttributeTypeLoginTcpPort:
		return "Login-TCP-Port"
	case AttributeTypeReplyMessage:
		return "Reply-Message"
	case AttributeTypeCallbackNumber:
		return "Callback-Number"
	case AttributeTypeCallbackId:
		return "Callback-Id"
	case AttributeTypeFramedRoute:
		return "Framed-Route"
	case AttributeTypeFramedIpxNetwork:
		return "Framed-IPX-Network"
	case AttributeTypeState:
		return "State"
	case AttributeTypeClass:
		return "Class"
	case AttributeTypeVendorSpecific:
		return "Vendor-Specific"
	case AttributeTypeSessionTimeout:
		return "Session-Timeout"
	case AttributeTypeIdleTimeout:
		return "Idle-Timeout"
	case AttributeTypeTerminationAction:
		return "Termination-Action"
	case AttributeTypeCalledStationId:
		return "Called-Station-Id"
	case AttributeTypeCallingStationId:
		return "Calling-Station-Id"
	case AttributeTypeNasIdentifier:
		return "NAS-Identifier"
	case AttributeTypeProxyState:
		return "Proxy-State"
	case AttributeTypeLoginLatService:
		return "Login-LAT-Service"
	case AttributeTypeLoginLatNode:
		return "Login-LAT-Node"
	case AttributeTypeLoginLatGroup:
		return "Login-LAT-Group"
	case AttributeTypeFramedAppleTalkLink:
		return "Framed-AppleTalk-Link"
	case AttributeTypeFramedAppleTalkNetwork:
		return "Framed-AppleTalk-Network"
	case AttributeTypeFramedAppleTalkZone:
		return "Framed-AppleTalk-Zone"
	case AttributeTypeErrorCause:
		return "Error-Cause"
	case AttributeTypeAcctStatusType:
		return "Acct-Status-Type"
	case AttributeTypeAcctDelayTime:
		return "Acct-Delay-Time"
	case AttributeTypeAcctInputOctets:
		return "Acct-Input-Octets"
	case AttributeTypeAcctOutputOctets:
		return "Acct-Output-Octets"
	case AttributeTypeAcctSessionId:
		return "Acct-Session-Id"
	case AttributeTypeAcctAuthentic:
		return "Acct-Authentic"
	case AttributeTypeAcctSessionTime:
		return "Acct-Session-Time"
	case AttributeTypeAcctInputPackets:
		return "Acct-Input-Packets"
	case AttributeTypeAcctOutputPackets:
		return "Acct-Output-Packets"
	case AttributeTypeAcctTerminateCause:
		return "Acct-Terminate-Cause"
	case AttributeTypeAcctMultiSessionId:
		return "Acct-Multi-Session-Id"
	case AttributeTypeAcctLinkCount:
		return "Acct-Link-Count"
	case AttributeTypeChapChallenge:
		return "CHAP-Challenge"
	case AttributeTypeNasPortType:
		return "NAS-Port-Type"
	case AttributeTypePortLimit:
		return "Port-Limit"
	case AttributeTypeLoginLatPort:
		return "Login-LAT-Port"
	case AttributeTypeTunnelType:
		return "Tunnel-Type"
	case AttributeTypeTunnelMediumType:
		return "Tunnel-Medium-Type"
	case AttributeTypeTunnelPrivateGroupId:
		return "Tunnel-Private-Group-ID"
	case AttributeTypeEgressVlanId:
		return "Egress-VLANID"
	case AttributeTypeIngressFilters:
		return "Ingress-Filters"
	case AttributeTypeEgressVlanName:
		return "Egress-VLAN-Name"
	case AttributeTypeUserPriorityTable:
		return "User-Priority-Table"
	case AttributeTypeEapMessage:
		return "EAP-Message"
	case AttributeTypeMessageAuthenticator:
		return "Message-Authenticator"
	}
	return fmt.Sprintf("Unknown (%d)", t)
}
