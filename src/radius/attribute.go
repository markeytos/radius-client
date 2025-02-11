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

	h := md5.New()
	h.Write(s)
	h.Write(authenticator)
	enc = h.Sum(enc)

	for i := 0; i < 16 && i < len(pw); i++ {
		enc[i] ^= pw[i]
	}

	for i := 16; i < len(pw); i += 16 {
		h.Reset()
		h.Write(s)
		h.Write(enc[i-16 : i])
		enc = h.Sum(enc)
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

type Attributes []*Attribute

func (as Attributes) FirstOfType(t AttributeType) *Attribute {
	for _, a := range as {
		if a.Type == t {
			return a
		}
	}
	return nil
}

func (as *Attributes) ContainsOfType(t AttributeType) bool {
	return as.FirstOfType(t) != nil
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

type AttributeTypeLabel string

const (
	AttributeTypeLabelUserName               AttributeTypeLabel = "User-Name"
	AttributeTypeLabelUserPassword           AttributeTypeLabel = "User-Password"
	AttributeTypeLabelChapPassword           AttributeTypeLabel = "CHAP-Password"
	AttributeTypeLabelNasIpAddress           AttributeTypeLabel = "NAS-IP-Address"
	AttributeTypeLabelNasPort                AttributeTypeLabel = "NAS-Port"
	AttributeTypeLabelServiceType            AttributeTypeLabel = "Service-Type"
	AttributeTypeLabelFramedProtocol         AttributeTypeLabel = "Framed-Protocol"
	AttributeTypeLabelFramedIpAddress        AttributeTypeLabel = "Framed-IP-Address"
	AttributeTypeLabelFramedIpNetmask        AttributeTypeLabel = "Framed-IP-Netmask"
	AttributeTypeLabelFramedRouting          AttributeTypeLabel = "Framed-Routing"
	AttributeTypeLabelFilterId               AttributeTypeLabel = "Filter-Id"
	AttributeTypeLabelFramedMtu              AttributeTypeLabel = "Framed-MTU"
	AttributeTypeLabelFramedCompression      AttributeTypeLabel = "Framed-Compression"
	AttributeTypeLabelLoginIpHost            AttributeTypeLabel = "Login-IP-Host"
	AttributeTypeLabelLoginService           AttributeTypeLabel = "Login-Service"
	AttributeTypeLabelLoginTcpPort           AttributeTypeLabel = "Login-TCP-Port"
	AttributeTypeLabelReplyMessage           AttributeTypeLabel = "Reply-Message"
	AttributeTypeLabelCallbackNumber         AttributeTypeLabel = "Callback-Number"
	AttributeTypeLabelCallbackId             AttributeTypeLabel = "Callback-Id"
	AttributeTypeLabelFramedRoute            AttributeTypeLabel = "Framed-Route"
	AttributeTypeLabelFramedIpxNetwork       AttributeTypeLabel = "Framed-IPX-Network"
	AttributeTypeLabelState                  AttributeTypeLabel = "State"
	AttributeTypeLabelClass                  AttributeTypeLabel = "Class"
	AttributeTypeLabelVendorSpecific         AttributeTypeLabel = "Vendor-Specific"
	AttributeTypeLabelSessionTimeout         AttributeTypeLabel = "Session-Timeout"
	AttributeTypeLabelIdleTimeout            AttributeTypeLabel = "Idle-Timeout"
	AttributeTypeLabelTerminationAction      AttributeTypeLabel = "Termination-Action"
	AttributeTypeLabelCalledStationId        AttributeTypeLabel = "Called-Station-Id"
	AttributeTypeLabelCallingStationId       AttributeTypeLabel = "Calling-Station-Id"
	AttributeTypeLabelNasIdentifier          AttributeTypeLabel = "NAS-Identifier"
	AttributeTypeLabelProxyState             AttributeTypeLabel = "Proxy-State"
	AttributeTypeLabelLoginLatService        AttributeTypeLabel = "Login-LAT-Service"
	AttributeTypeLabelLoginLatNode           AttributeTypeLabel = "Login-LAT-Node"
	AttributeTypeLabelLoginLatGroup          AttributeTypeLabel = "Login-LAT-Group"
	AttributeTypeLabelFramedAppleTalkLink    AttributeTypeLabel = "Framed-AppleTalk-Link"
	AttributeTypeLabelFramedAppleTalkNetwork AttributeTypeLabel = "Framed-AppleTalk-Network"
	AttributeTypeLabelFramedAppleTalkZone    AttributeTypeLabel = "Framed-AppleTalk-Zone"
	AttributeTypeLabelErrorCause             AttributeTypeLabel = "Error-Cause"

	AttributeTypeLabelAcctStatusType     AttributeTypeLabel = "Acct-Status-Type"
	AttributeTypeLabelAcctDelayTime      AttributeTypeLabel = "Acct-Delay-Time"
	AttributeTypeLabelAcctInputOctets    AttributeTypeLabel = "Acct-Input-Octets"
	AttributeTypeLabelAcctOutputOctets   AttributeTypeLabel = "Acct-Output-Octets"
	AttributeTypeLabelAcctSessionId      AttributeTypeLabel = "Acct-Session-Id"
	AttributeTypeLabelAcctAuthentic      AttributeTypeLabel = "Acct-Authentic"
	AttributeTypeLabelAcctSessionTime    AttributeTypeLabel = "Acct-Session-Time"
	AttributeTypeLabelAcctInputPackets   AttributeTypeLabel = "Acct-Input-Packets"
	AttributeTypeLabelAcctOutputPackets  AttributeTypeLabel = "Acct-Output-Packets"
	AttributeTypeLabelAcctTerminateCause AttributeTypeLabel = "Acct-Terminate-Cause"
	AttributeTypeLabelAcctMultiSessionId AttributeTypeLabel = "Acct-Multi-Session-Id"
	AttributeTypeLabelAcctLinkCount      AttributeTypeLabel = "Acct-Link-Count"

	AttributeTypeLabelChapChallenge AttributeTypeLabel = "CHAP-Challenge"
	AttributeTypeLabelNasPortType   AttributeTypeLabel = "NAS-Port-Type"
	AttributeTypeLabelPortLimit     AttributeTypeLabel = "Port-Limit"
	AttributeTypeLabelLoginLatPort  AttributeTypeLabel = "Login-LAT-Port"

	AttributeTypeLabelTunnelType           AttributeTypeLabel = "Tunnel-Type"
	AttributeTypeLabelTunnelMediumType     AttributeTypeLabel = "Tunnel-Medium-Type"
	AttributeTypeLabelTunnelPrivateGroupId AttributeTypeLabel = "Tunnel-Private-Group-ID"

	AttributeTypeLabelEgressVlanId      AttributeTypeLabel = "Egress-VLANID"
	AttributeTypeLabelIngressFilters    AttributeTypeLabel = "Ingress-Filters"
	AttributeTypeLabelEgressVlanName    AttributeTypeLabel = "Egress-VLAN-Name"
	AttributeTypeLabelUserPriorityTable AttributeTypeLabel = "User-Priority-Table"

	AttributeTypeLabelEapMessage           AttributeTypeLabel = "EAP-Message"
	AttributeTypeLabelMessageAuthenticator AttributeTypeLabel = "Message-Authenticator"
)

func AttributeTypeFromString(label string) (AttributeType, error) {
	switch AttributeTypeLabel(label) {
	case AttributeTypeLabelUserName:
		return AttributeTypeUserName, nil
	case AttributeTypeLabelUserPassword:
		return AttributeTypeUserPassword, nil
	case AttributeTypeLabelChapPassword:
		return AttributeTypeChapPassword, nil
	case AttributeTypeLabelNasIpAddress:
		return AttributeTypeNasIpAddress, nil
	case AttributeTypeLabelNasPort:
		return AttributeTypeNasPort, nil
	case AttributeTypeLabelServiceType:
		return AttributeTypeServiceType, nil
	case AttributeTypeLabelFramedProtocol:
		return AttributeTypeFramedProtocol, nil
	case AttributeTypeLabelFramedIpAddress:
		return AttributeTypeFramedIpAddress, nil
	case AttributeTypeLabelFramedIpNetmask:
		return AttributeTypeFramedIpNetmask, nil
	case AttributeTypeLabelFramedRouting:
		return AttributeTypeFramedRouting, nil
	case AttributeTypeLabelFilterId:
		return AttributeTypeFilterId, nil
	case AttributeTypeLabelFramedMtu:
		return AttributeTypeFramedMtu, nil
	case AttributeTypeLabelFramedCompression:
		return AttributeTypeFramedCompression, nil
	case AttributeTypeLabelLoginIpHost:
		return AttributeTypeLoginIpHost, nil
	case AttributeTypeLabelLoginService:
		return AttributeTypeLoginService, nil
	case AttributeTypeLabelLoginTcpPort:
		return AttributeTypeLoginTcpPort, nil
	case AttributeTypeLabelReplyMessage:
		return AttributeTypeReplyMessage, nil
	case AttributeTypeLabelCallbackNumber:
		return AttributeTypeCallbackNumber, nil
	case AttributeTypeLabelCallbackId:
		return AttributeTypeCallbackId, nil
	case AttributeTypeLabelFramedRoute:
		return AttributeTypeFramedRoute, nil
	case AttributeTypeLabelFramedIpxNetwork:
		return AttributeTypeFramedIpxNetwork, nil
	case AttributeTypeLabelState:
		return AttributeTypeState, nil
	case AttributeTypeLabelClass:
		return AttributeTypeClass, nil
	case AttributeTypeLabelVendorSpecific:
		return AttributeTypeVendorSpecific, nil
	case AttributeTypeLabelSessionTimeout:
		return AttributeTypeSessionTimeout, nil
	case AttributeTypeLabelIdleTimeout:
		return AttributeTypeIdleTimeout, nil
	case AttributeTypeLabelTerminationAction:
		return AttributeTypeTerminationAction, nil
	case AttributeTypeLabelCalledStationId:
		return AttributeTypeCalledStationId, nil
	case AttributeTypeLabelCallingStationId:
		return AttributeTypeCallingStationId, nil
	case AttributeTypeLabelNasIdentifier:
		return AttributeTypeNasIdentifier, nil
	case AttributeTypeLabelProxyState:
		return AttributeTypeProxyState, nil
	case AttributeTypeLabelLoginLatService:
		return AttributeTypeLoginLatService, nil
	case AttributeTypeLabelLoginLatNode:
		return AttributeTypeLoginLatNode, nil
	case AttributeTypeLabelLoginLatGroup:
		return AttributeTypeLoginLatGroup, nil
	case AttributeTypeLabelFramedAppleTalkLink:
		return AttributeTypeFramedAppleTalkLink, nil
	case AttributeTypeLabelFramedAppleTalkNetwork:
		return AttributeTypeFramedAppleTalkNetwork, nil
	case AttributeTypeLabelFramedAppleTalkZone:
		return AttributeTypeFramedAppleTalkZone, nil
	case AttributeTypeLabelErrorCause:
		return AttributeTypeErrorCause, nil
	case AttributeTypeLabelAcctStatusType:
		return AttributeTypeAcctStatusType, nil
	case AttributeTypeLabelAcctDelayTime:
		return AttributeTypeAcctDelayTime, nil
	case AttributeTypeLabelAcctInputOctets:
		return AttributeTypeAcctInputOctets, nil
	case AttributeTypeLabelAcctOutputOctets:
		return AttributeTypeAcctOutputOctets, nil
	case AttributeTypeLabelAcctSessionId:
		return AttributeTypeAcctSessionId, nil
	case AttributeTypeLabelAcctAuthentic:
		return AttributeTypeAcctAuthentic, nil
	case AttributeTypeLabelAcctSessionTime:
		return AttributeTypeAcctSessionTime, nil
	case AttributeTypeLabelAcctInputPackets:
		return AttributeTypeAcctInputPackets, nil
	case AttributeTypeLabelAcctOutputPackets:
		return AttributeTypeAcctOutputPackets, nil
	case AttributeTypeLabelAcctTerminateCause:
		return AttributeTypeAcctTerminateCause, nil
	case AttributeTypeLabelAcctMultiSessionId:
		return AttributeTypeAcctMultiSessionId, nil
	case AttributeTypeLabelAcctLinkCount:
		return AttributeTypeAcctLinkCount, nil
	case AttributeTypeLabelChapChallenge:
		return AttributeTypeChapChallenge, nil
	case AttributeTypeLabelNasPortType:
		return AttributeTypeNasPortType, nil
	case AttributeTypeLabelPortLimit:
		return AttributeTypePortLimit, nil
	case AttributeTypeLabelLoginLatPort:
		return AttributeTypeLoginLatPort, nil
	case AttributeTypeLabelTunnelType:
		return AttributeTypeTunnelType, nil
	case AttributeTypeLabelTunnelMediumType:
		return AttributeTypeTunnelMediumType, nil
	case AttributeTypeLabelTunnelPrivateGroupId:
		return AttributeTypeTunnelPrivateGroupId, nil
	case AttributeTypeLabelEgressVlanId:
		return AttributeTypeEgressVlanId, nil
	case AttributeTypeLabelIngressFilters:
		return AttributeTypeIngressFilters, nil
	case AttributeTypeLabelEgressVlanName:
		return AttributeTypeEgressVlanName, nil
	case AttributeTypeLabelUserPriorityTable:
		return AttributeTypeUserPriorityTable, nil
	case AttributeTypeLabelEapMessage:
		return AttributeTypeEapMessage, nil
	case AttributeTypeLabelMessageAuthenticator:
		return AttributeTypeMessageAuthenticator, nil
	}
	return 0, fmt.Errorf("unknown attribute type label: %s", label)
}

func (t AttributeType) String() string {
	switch t {
	case AttributeTypeUserName:
		return string(AttributeTypeLabelUserName)
	case AttributeTypeUserPassword:
		return string(AttributeTypeLabelUserPassword)
	case AttributeTypeChapPassword:
		return string(AttributeTypeLabelChapPassword)
	case AttributeTypeNasIpAddress:
		return string(AttributeTypeLabelNasIpAddress)
	case AttributeTypeNasPort:
		return string(AttributeTypeLabelNasPort)
	case AttributeTypeServiceType:
		return string(AttributeTypeLabelServiceType)
	case AttributeTypeFramedProtocol:
		return string(AttributeTypeLabelFramedProtocol)
	case AttributeTypeFramedIpAddress:
		return string(AttributeTypeLabelFramedIpAddress)
	case AttributeTypeFramedIpNetmask:
		return string(AttributeTypeLabelFramedIpNetmask)
	case AttributeTypeFramedRouting:
		return string(AttributeTypeLabelFramedRouting)
	case AttributeTypeFilterId:
		return string(AttributeTypeLabelFilterId)
	case AttributeTypeFramedMtu:
		return string(AttributeTypeLabelFramedMtu)
	case AttributeTypeFramedCompression:
		return string(AttributeTypeLabelFramedCompression)
	case AttributeTypeLoginIpHost:
		return string(AttributeTypeLabelLoginIpHost)
	case AttributeTypeLoginService:
		return string(AttributeTypeLabelLoginService)
	case AttributeTypeLoginTcpPort:
		return string(AttributeTypeLabelLoginTcpPort)
	case AttributeTypeReplyMessage:
		return string(AttributeTypeLabelReplyMessage)
	case AttributeTypeCallbackNumber:
		return string(AttributeTypeLabelCallbackNumber)
	case AttributeTypeCallbackId:
		return string(AttributeTypeLabelCallbackId)
	case AttributeTypeFramedRoute:
		return string(AttributeTypeLabelFramedRoute)
	case AttributeTypeFramedIpxNetwork:
		return string(AttributeTypeLabelFramedIpxNetwork)
	case AttributeTypeState:
		return string(AttributeTypeLabelState)
	case AttributeTypeClass:
		return string(AttributeTypeLabelClass)
	case AttributeTypeVendorSpecific:
		return string(AttributeTypeLabelVendorSpecific)
	case AttributeTypeSessionTimeout:
		return string(AttributeTypeLabelSessionTimeout)
	case AttributeTypeIdleTimeout:
		return string(AttributeTypeLabelIdleTimeout)
	case AttributeTypeTerminationAction:
		return string(AttributeTypeLabelTerminationAction)
	case AttributeTypeCalledStationId:
		return string(AttributeTypeLabelCalledStationId)
	case AttributeTypeCallingStationId:
		return string(AttributeTypeLabelCallingStationId)
	case AttributeTypeNasIdentifier:
		return string(AttributeTypeLabelNasIdentifier)
	case AttributeTypeProxyState:
		return string(AttributeTypeLabelProxyState)
	case AttributeTypeLoginLatService:
		return string(AttributeTypeLabelLoginLatService)
	case AttributeTypeLoginLatNode:
		return string(AttributeTypeLabelLoginLatNode)
	case AttributeTypeLoginLatGroup:
		return string(AttributeTypeLabelLoginLatGroup)
	case AttributeTypeFramedAppleTalkLink:
		return string(AttributeTypeLabelFramedAppleTalkLink)
	case AttributeTypeFramedAppleTalkNetwork:
		return string(AttributeTypeLabelFramedAppleTalkNetwork)
	case AttributeTypeFramedAppleTalkZone:
		return string(AttributeTypeLabelFramedAppleTalkZone)
	case AttributeTypeErrorCause:
		return string(AttributeTypeLabelErrorCause)
	case AttributeTypeAcctStatusType:
		return string(AttributeTypeLabelAcctStatusType)
	case AttributeTypeAcctDelayTime:
		return string(AttributeTypeLabelAcctDelayTime)
	case AttributeTypeAcctInputOctets:
		return string(AttributeTypeLabelAcctInputOctets)
	case AttributeTypeAcctOutputOctets:
		return string(AttributeTypeLabelAcctOutputOctets)
	case AttributeTypeAcctSessionId:
		return string(AttributeTypeLabelAcctSessionId)
	case AttributeTypeAcctAuthentic:
		return string(AttributeTypeLabelAcctAuthentic)
	case AttributeTypeAcctSessionTime:
		return string(AttributeTypeLabelAcctSessionTime)
	case AttributeTypeAcctInputPackets:
		return string(AttributeTypeLabelAcctInputPackets)
	case AttributeTypeAcctOutputPackets:
		return string(AttributeTypeLabelAcctOutputPackets)
	case AttributeTypeAcctTerminateCause:
		return string(AttributeTypeLabelAcctTerminateCause)
	case AttributeTypeAcctMultiSessionId:
		return string(AttributeTypeLabelAcctMultiSessionId)
	case AttributeTypeAcctLinkCount:
		return string(AttributeTypeLabelAcctLinkCount)
	case AttributeTypeChapChallenge:
		return string(AttributeTypeLabelChapChallenge)
	case AttributeTypeNasPortType:
		return string(AttributeTypeLabelNasPortType)
	case AttributeTypePortLimit:
		return string(AttributeTypeLabelPortLimit)
	case AttributeTypeLoginLatPort:
		return string(AttributeTypeLabelLoginLatPort)
	case AttributeTypeTunnelType:
		return string(AttributeTypeLabelTunnelType)
	case AttributeTypeTunnelMediumType:
		return string(AttributeTypeLabelTunnelMediumType)
	case AttributeTypeTunnelPrivateGroupId:
		return string(AttributeTypeLabelTunnelPrivateGroupId)
	case AttributeTypeEgressVlanId:
		return string(AttributeTypeLabelEgressVlanId)
	case AttributeTypeIngressFilters:
		return string(AttributeTypeLabelIngressFilters)
	case AttributeTypeEgressVlanName:
		return string(AttributeTypeLabelEgressVlanName)
	case AttributeTypeUserPriorityTable:
		return string(AttributeTypeLabelUserPriorityTable)
	case AttributeTypeEapMessage:
		return string(AttributeTypeLabelEapMessage)
	case AttributeTypeMessageAuthenticator:
		return string(AttributeTypeLabelMessageAuthenticator)
	}
	return fmt.Sprintf("Unknown (%d)", t)
}
