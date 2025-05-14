/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS attributes enum values
*/
package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

func ParseAttributeEnumData(b []byte, t AttributeType, v string) error {
	var enum uint32
	switch t {
	case AttributeTypeServiceType:
		e, err := ParseAttributeEnumServiceType(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeFramedProtocol:
		e, err := ParseAttributeEnumFramedProtocol(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeFramedRouting:
		e, err := ParseAttributeEnumFramedRouting(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeFramedCompression:
		e, err := ParseAttributeEnumFramedCompression(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeLoginService:
		e, err := ParseAttributeEnumLoginService(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeTerminationAction:
		e, err := ParseAttributeEnumTerminationAction(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeErrorCause:
		e, err := ParseAttributeEnumErrorCause(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeAcctStatusType:
		e, err := ParseAttributeEnumAcctStatusType(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeAcctAuthentic:
		e, err := ParseAttributeEnumAcctAuthentic(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeAcctTerminateCause:
		e, err := ParseAttributeEnumAcctTerminateCause(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeNasPortType:
		e, err := ParseAttributeEnumNasPortType(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeTunnelType:
		e, err := ParseAttributeEnumTunnelType(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeTunnelMediumType:
		e, err := ParseAttributeEnumTunnelMediumType(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	case AttributeTypeIngressFilters:
		e, err := ParseAttributeEnumIngressFilters(v)
		if err != nil {
			return err
		}
		enum = uint32(e)
	default:
		return fmt.Errorf("unknown attribute enum type: %s", t.String())
	}

	binary.BigEndian.PutUint32(b, enum)
	return nil
}

type AttributeEnumServiceType uint32

const (
	AttributeEnumServiceTypeLogin AttributeEnumServiceType = iota + 1
	AttributeEnumServiceTypeFramed
	AttributeEnumServiceTypeCallbackLogin
	AttributeEnumServiceTypeCallbackFramed
	AttributeEnumServiceTypeOutbound
	AttributeEnumServiceTypeAdministrative
	AttributeEnumServiceTypeNASPrompt
	AttributeEnumServiceTypeAuthenticateOnly
	AttributeEnumServiceTypeCallbackNASPrompt
	AttributeEnumServiceTypeCallCheck
	AttributeEnumServiceTypeCallbackAdministrative
)

func ParseAttributeEnumServiceType(v string) (AttributeEnumServiceType, error) {
	switch v {
	case "Login":
		return AttributeEnumServiceTypeLogin, nil
	case "Framed":
		return AttributeEnumServiceTypeFramed, nil
	case "Callback Login":
		return AttributeEnumServiceTypeCallbackLogin, nil
	case "Callback Framed":
		return AttributeEnumServiceTypeCallbackFramed, nil
	case "Outbound":
		return AttributeEnumServiceTypeOutbound, nil
	case "Administrative":
		return AttributeEnumServiceTypeAdministrative, nil
	case "NAS Prompt":
		return AttributeEnumServiceTypeNASPrompt, nil
	case "Authenticate Only":
		return AttributeEnumServiceTypeAuthenticateOnly, nil
	case "Callback NAS Prompt":
		return AttributeEnumServiceTypeCallbackNASPrompt, nil
	case "Call Check":
		return AttributeEnumServiceTypeCallCheck, nil
	case "Callback Administrative":
		return AttributeEnumServiceTypeCallbackAdministrative, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumServiceType(i), nil
		}
		return 0, fmt.Errorf("invalid service type value: %s", v)
	}
}

type AttributeEnumFramedProtocol uint32

const (
	AttributeEnumFramedProtocolPPP AttributeEnumFramedProtocol = iota + 1
	AttributeEnumFramedProtocolSLIP
	AttributeEnumFramedProtocolARAP
	AttributeEnumFramedProtocolGandalfProtocol
	AttributeEnumFramedProtocolXylogics
	AttributeEnumFramedProtocolX75Synchronous
)

func ParseAttributeEnumFramedProtocol(v string) (AttributeEnumFramedProtocol, error) {
	switch v {
	case "PPP":
		return AttributeEnumFramedProtocolPPP, nil
	case "SLIP":
		return AttributeEnumFramedProtocolSLIP, nil
	case "ARAP":
		return AttributeEnumFramedProtocolARAP, nil
	case "Gandalf Protocol":
		return AttributeEnumFramedProtocolGandalfProtocol, nil
	case "Xylogics":
		return AttributeEnumFramedProtocolXylogics, nil
	case "X.75 Synchronous":
		return AttributeEnumFramedProtocolX75Synchronous, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumFramedProtocol(i), nil
		}
		return 0, fmt.Errorf("invalid framed protocol value: %s", v)
	}
}

type AttributeEnumFramedRouting uint32

const (
	AttributeEnumFramedRoutingNone AttributeEnumFramedRouting = iota
	AttributeEnumFramedRoutingSend
	AttributeEnumFramedRoutingListen
	AttributeEnumFramedRoutingSendListen
)

func ParseAttributeEnumFramedRouting(v string) (AttributeEnumFramedRouting, error) {
	switch v {
	case "None":
		return AttributeEnumFramedRoutingNone, nil
	case "Send":
		return AttributeEnumFramedRoutingSend, nil
	case "Listen":
		return AttributeEnumFramedRoutingListen, nil
	case "SendListen":
		return AttributeEnumFramedRoutingSendListen, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumFramedRouting(i), nil
		}
		return 0, fmt.Errorf("invalid framed routing value: %s", v)
	}
}

type AttributeEnumFramedCompression uint32

const (
	AttributeEnumFramedCompressionNone AttributeEnumFramedCompression = iota
	AttributeEnumFramedCompressionVJHeaderCompression
	AttributeEnumFramedCompressionIPXHeaderCompression
	AttributeEnumFramedCompressionStacLZSCompression
)

func ParseAttributeEnumFramedCompression(v string) (AttributeEnumFramedCompression, error) {
	switch v {
	case "None":
		return AttributeEnumFramedCompressionNone, nil
	case "VJ header compression":
		return AttributeEnumFramedCompressionVJHeaderCompression, nil
	case "IPX header compression":
		return AttributeEnumFramedCompressionIPXHeaderCompression, nil
	case "Stac-LZS compression":
		return AttributeEnumFramedCompressionStacLZSCompression, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumFramedCompression(i), nil
		}
		return 0, fmt.Errorf("invalid framed compression value: %s", v)
	}
}

type AttributeEnumLoginService uint32

const (
	AttributeEnumLoginServiceTelnet AttributeEnumLoginService = iota
	AttributeEnumLoginServiceRlogin
	AttributeEnumLoginServiceTCPClear
	AttributeEnumLoginServicePortMaster
	AttributeEnumLoginServiceLAT
	AttributeEnumLoginServiceX25PAD
	AttributeEnumLoginServiceX25T3POS
)

func ParseAttributeEnumLoginService(v string) (AttributeEnumLoginService, error) {
	switch v {
	case "Telnet":
		return AttributeEnumLoginServiceTelnet, nil
	case "Rlogin":
		return AttributeEnumLoginServiceRlogin, nil
	case "TCP Clear":
		return AttributeEnumLoginServiceTCPClear, nil
	case "PortMaster":
		return AttributeEnumLoginServicePortMaster, nil
	case "LAT":
		return AttributeEnumLoginServiceLAT, nil
	case "X25-PAD":
		return AttributeEnumLoginServiceX25PAD, nil
	case "X25-T3POS":
		return AttributeEnumLoginServiceX25T3POS, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumLoginService(i), nil
		}
		return 0, fmt.Errorf("invalid login service value: %s", v)
	}
}

type AttributeEnumTerminationAction uint32

const (
	AttributeEnumTerminationActionDefault AttributeEnumTerminationAction = iota
	AttributeEnumTerminationActionRadiusRequest
)

func ParseAttributeEnumTerminationAction(v string) (AttributeEnumTerminationAction, error) {
	switch v {
	case "Default":
		return AttributeEnumTerminationActionDefault, nil
	case "RADIUS-Request":
		return AttributeEnumTerminationActionRadiusRequest, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumTerminationAction(i), nil
		}
		return 0, fmt.Errorf("invalid termination action value: %s", v)
	}
}

type AttributeEnumErrorCause uint32

const (
	AttributeEnumErrorCauseResidualSessionContextRemoved AttributeEnumErrorCause = 201
	AttributeEnumErrorCauseInvalidEAPPacket              AttributeEnumErrorCause = 202
	AttributeEnumErrorCauseUnsupportedAttribute          AttributeEnumErrorCause = 401
	AttributeEnumErrorCauseMissingAttribute              AttributeEnumErrorCause = 402
	AttributeEnumErrorCauseNASIdentificationMismatch     AttributeEnumErrorCause = 403
	AttributeEnumErrorCauseInvalidRequest                AttributeEnumErrorCause = 404
	AttributeEnumErrorCauseUnsupportedService            AttributeEnumErrorCause = 405
	AttributeEnumErrorCauseUnsupportedExtension          AttributeEnumErrorCause = 406
	AttributeEnumErrorCauseAdministrativelyProhibited    AttributeEnumErrorCause = 501
	AttributeEnumErrorCauseRequestNotRoutable            AttributeEnumErrorCause = 502
	AttributeEnumErrorCauseSessionContextNotFound        AttributeEnumErrorCause = 503
	AttributeEnumErrorCauseSessionContextNotRemovable    AttributeEnumErrorCause = 504
	AttributeEnumErrorCauseOtherProxyProcessingError     AttributeEnumErrorCause = 505
	AttributeEnumErrorCauseResourcesUnavailable          AttributeEnumErrorCause = 506
	AttributeEnumErrorCauseRequestInitiated              AttributeEnumErrorCause = 507
)

func ParseAttributeEnumErrorCause(v string) (AttributeEnumErrorCause, error) {
	switch v {
	case "Residual Session Context Removed":
		return AttributeEnumErrorCauseResidualSessionContextRemoved, nil
	case "Invalid EAP Packet":
		return AttributeEnumErrorCauseInvalidEAPPacket, nil
	case "Unsupported Attribute":
		return AttributeEnumErrorCauseUnsupportedAttribute, nil
	case "Missing Attribute":
		return AttributeEnumErrorCauseMissingAttribute, nil
	case "NAS Identification Mismatch":
		return AttributeEnumErrorCauseNASIdentificationMismatch, nil
	case "Invalid Request":
		return AttributeEnumErrorCauseInvalidRequest, nil
	case "Unsupported Service":
		return AttributeEnumErrorCauseUnsupportedService, nil
	case "Unsupported Extension":
		return AttributeEnumErrorCauseUnsupportedExtension, nil
	case "Administratively Prohibited":
		return AttributeEnumErrorCauseAdministrativelyProhibited, nil
	case "Request Not Routable":
		return AttributeEnumErrorCauseRequestNotRoutable, nil
	case "Session Context Not Found":
		return AttributeEnumErrorCauseSessionContextNotFound, nil
	case "Session Context Not Removable":
		return AttributeEnumErrorCauseSessionContextNotRemovable, nil
	case "Other Proxy Processing Error":
		return AttributeEnumErrorCauseOtherProxyProcessingError, nil
	case "Resources Unavailable":
		return AttributeEnumErrorCauseResourcesUnavailable, nil
	case "Request Initiated":
		return AttributeEnumErrorCauseRequestInitiated, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumErrorCause(i), nil
		}
		return 0, fmt.Errorf("invalid error cause value: %s", v)
	}
}

type AttributeEnumAcctStatusType uint32

const (
	AttributeEnumAcctStatusTypeStart AttributeEnumAcctStatusType = iota + 1
	AttributeEnumAcctStatusTypeStop
	AttributeEnumAcctStatusTypeInterimUpdate
	AttributeEnumAcctStatusTypeAccountingOn
	AttributeEnumAcctStatusTypeAccountingOff
)

func ParseAttributeEnumAcctStatusType(v string) (AttributeEnumAcctStatusType, error) {
	switch v {
	case "Start":
		return AttributeEnumAcctStatusTypeStart, nil
	case "Stop":
		return AttributeEnumAcctStatusTypeStop, nil
	case "Interim-Update":
		return AttributeEnumAcctStatusTypeInterimUpdate, nil
	case "Accounting-On":
		return AttributeEnumAcctStatusTypeAccountingOn, nil
	case "Accounting-Off":
		return AttributeEnumAcctStatusTypeAccountingOff, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumAcctStatusType(i), nil
		}
		return 0, fmt.Errorf("invalid accounting status type value: %s", v)
	}
}

type AttributeEnumAcctAuthentic uint32

const (
	AttributeEnumAcctAuthenticRadius AttributeEnumAcctAuthentic = iota + 1
	AttributeEnumAcctAuthenticLocal
	AttributeEnumAcctAuthenticRemote
)

func ParseAttributeEnumAcctAuthentic(v string) (AttributeEnumAcctAuthentic, error) {
	switch v {
	case "RADIUS":
		return AttributeEnumAcctAuthenticRadius, nil
	case "Local":
		return AttributeEnumAcctAuthenticLocal, nil
	case "Remote":
		return AttributeEnumAcctAuthenticRemote, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumAcctAuthentic(i), nil
		}
		return 0, fmt.Errorf("invalid accounting authentic value: %s", v)
	}
}

type AttributeEnumAcctTerminateCause uint32

const (
	AttributeEnumAcctTerminateCauseUserRequest AttributeEnumAcctTerminateCause = iota + 1
	AttributeEnumAcctTerminateCauseLostCarrier
	AttributeEnumAcctTerminateCauseLostService
	AttributeEnumAcctTerminateCauseIdleTimeout
	AttributeEnumAcctTerminateCauseSessionTimeout
	AttributeEnumAcctTerminateCauseAdminReset
	AttributeEnumAcctTerminateCauseAdminReboot
	AttributeEnumAcctTerminateCausePortError
	AttributeEnumAcctTerminateCauseNASError
	AttributeEnumAcctTerminateCauseNASRequest
	AttributeEnumAcctTerminateCauseNASReboot
	AttributeEnumAcctTerminateCausePortUnneeded
	AttributeEnumAcctTerminateCausePortPreempted
	AttributeEnumAcctTerminateCausePortSuspended
	AttributeEnumAcctTerminateCauseServiceUnavailable
	AttributeEnumAcctTerminateCauseCallback
	AttributeEnumAcctTerminateCauseUserError
	AttributeEnumAcctTerminateCauseHostRequest
)

func ParseAttributeEnumAcctTerminateCause(v string) (AttributeEnumAcctTerminateCause, error) {
	switch v {
	case "User Request":
		return AttributeEnumAcctTerminateCauseUserRequest, nil
	case "Lost Carrier":
		return AttributeEnumAcctTerminateCauseLostCarrier, nil
	case "Lost Service":
		return AttributeEnumAcctTerminateCauseLostService, nil
	case "Idle Timeout":
		return AttributeEnumAcctTerminateCauseIdleTimeout, nil
	case "Session Timeout":
		return AttributeEnumAcctTerminateCauseSessionTimeout, nil
	case "Admin Reset":
		return AttributeEnumAcctTerminateCauseAdminReset, nil
	case "Admin Reboot":
		return AttributeEnumAcctTerminateCauseAdminReboot, nil
	case "Port Error":
		return AttributeEnumAcctTerminateCausePortError, nil
	case "NAS Error":
		return AttributeEnumAcctTerminateCauseNASError, nil
	case "NAS Request":
		return AttributeEnumAcctTerminateCauseNASRequest, nil
	case "Port Unneeded":
		return AttributeEnumAcctTerminateCausePortUnneeded, nil
	case "Port Preempted":
		return AttributeEnumAcctTerminateCausePortPreempted, nil
	case "Port Suspended":
		return AttributeEnumAcctTerminateCausePortSuspended, nil
	case "Service Unavailable":
		return AttributeEnumAcctTerminateCauseServiceUnavailable, nil
	case "Callback":
		return AttributeEnumAcctTerminateCauseCallback, nil
	case "User Error":
		return AttributeEnumAcctTerminateCauseUserError, nil
	case "Host Request":
		return AttributeEnumAcctTerminateCauseHostRequest, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumAcctTerminateCause(i), nil
		}
		return 0, fmt.Errorf("invalid accounting terminate cause value: %s", v)
	}
}

type AttributeEnumNasPortType uint32

const (
	AttributeEnumNasPortTypeAsync AttributeEnumNasPortType = iota
	AttributeEnumNasPortTypeSync
	AttributeEnumNasPortTypeISDNSync
	AttributeEnumNasPortTypeISDNAsyncV120
	AttributeEnumNasPortTypeISDNAsyncV110
	AttributeEnumNasPortTypeVirtual
	AttributeEnumNasPortTypePIAFS
	AttributeEnumNasPortTypeHDLCClearChannel
	AttributeEnumNasPortTypeX25
	AttributeEnumNasPortTypeX75
	AttributeEnumNasPortTypeG3Fax
	AttributeEnumNasPortTypeSDSL
	AttributeEnumNasPortTypeADSLCAP
	AttributeEnumNasPortTypeADSLDMT
	AttributeEnumNasPortTypeIDSL
	AttributeEnumNasPortTypeEthernet
	AttributeEnumNasPortTypeXDSL
	AttributeEnumNasPortTypeCable
	AttributeEnumNasPortTypeWirelessOther
	AttributeEnumNasPortTypeWirelessIEEE80211
)

func ParseAttributeEnumNasPortType(v string) (AttributeEnumNasPortType, error) {
	switch v {
	case "Async":
		return AttributeEnumNasPortTypeAsync, nil
	case "Sync":
		return AttributeEnumNasPortTypeSync, nil
	case "ISDN Sync":
		return AttributeEnumNasPortTypeISDNSync, nil
	case "ISDN Async V.120":
		return AttributeEnumNasPortTypeISDNAsyncV120, nil
	case "ISDN Async V.110":
		return AttributeEnumNasPortTypeISDNAsyncV110, nil
	case "Virtual":
		return AttributeEnumNasPortTypeVirtual, nil
	case "PIAFS":
		return AttributeEnumNasPortTypePIAFS, nil
	case "HDLC Clear Channel":
		return AttributeEnumNasPortTypeHDLCClearChannel, nil
	case "X.25":
		return AttributeEnumNasPortTypeX25, nil
	case "X.75":
		return AttributeEnumNasPortTypeX75, nil
	case "G.3 Fax":
		return AttributeEnumNasPortTypeG3Fax, nil
	case "SDSL":
		return AttributeEnumNasPortTypeSDSL, nil
	case "ADSL-CAP":
		return AttributeEnumNasPortTypeADSLCAP, nil
	case "ADSL-DMT":
		return AttributeEnumNasPortTypeADSLDMT, nil
	case "IDSL":
		return AttributeEnumNasPortTypeIDSL, nil
	case "Ethernet":
		return AttributeEnumNasPortTypeEthernet, nil
	case "xDSL":
		return AttributeEnumNasPortTypeXDSL, nil
	case "Cable":
		return AttributeEnumNasPortTypeCable, nil
	case "Wireless - Other":
		return AttributeEnumNasPortTypeWirelessOther, nil
	case "Wireless - IEEE 802.11":
		return AttributeEnumNasPortTypeWirelessIEEE80211, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumNasPortType(i), nil
		}
		return 0, fmt.Errorf("invalid NAS port type value: %s", v)
	}
}

type AttributeEnumTunnelType uint32

const (
	AttributeEnumTunnelTypePointToPointTunnelingProtocol AttributeEnumTunnelType = iota + 1
	AttributeEnumTunnelTypeLayerTwoForwarding
	AttributeEnumTunnelTypeLayerTwoTunnelingProtocol
	AttributeEnumTunnelTypeAscendTunnelManagementProtocol
	AttributeEnumTunnelTypeVirtualTunnelingProtocol
	AttributeEnumTunnelTypeIPAuthenticationHeader
	AttributeEnumTunnelTypeIPInIPEncapsulation
	AttributeEnumTunnelTypeMinimalIPInIPEncapsulation
	AttributeEnumTunnelTypeIPEncapsulationSecurityPayload
	AttributeEnumTunnelTypeGenericRouteEncapsulation
	AttributeEnumTunnelTypeBayDialVirtualServices
	AttributeEnumTunnelTypeIPInIPTunneling
	AttributeEnumTunnelTypeVirtualLAN
)

func ParseAttributeEnumTunnelType(v string) (AttributeEnumTunnelType, error) {
	switch v {
	case "PointToPointTunnelingProtocol":
		return AttributeEnumTunnelTypePointToPointTunnelingProtocol, nil
	case "Layer Two Forwarding":
		return AttributeEnumTunnelTypeLayerTwoForwarding, nil
	case "Layer Two Tunneling Protocol":
		return AttributeEnumTunnelTypeLayerTwoTunnelingProtocol, nil
	case "Ascend Tunnel Management Protocol":
		return AttributeEnumTunnelTypeAscendTunnelManagementProtocol, nil
	case "Virtual Tunneling Protocol":
		return AttributeEnumTunnelTypeVirtualTunnelingProtocol, nil
	case "IP Authentication Header":
		return AttributeEnumTunnelTypeIPAuthenticationHeader, nil
	case "Minimal IP-in-IP Encapsulation":
		return AttributeEnumTunnelTypeMinimalIPInIPEncapsulation, nil
	case "IP Encapsulation Security Payload":
		return AttributeEnumTunnelTypeIPEncapsulationSecurityPayload, nil
	case "Generic Route Encapsulation":
		return AttributeEnumTunnelTypeGenericRouteEncapsulation, nil
	case "Bay Dial Virtual Services":
		return AttributeEnumTunnelTypeBayDialVirtualServices, nil
	case "IP-in-IP Tunneling":
		return AttributeEnumTunnelTypeIPInIPTunneling, nil
	case "Virtual LAN":
		return AttributeEnumTunnelTypeVirtualLAN, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumTunnelType(i), nil
		}
		return 0, fmt.Errorf("invalid tunnel type value: %s", v)
	}
}

type AttributeEnumTunnelMediumType uint32

const (
	AttributeEnumTunnelMediumTypeIPv4 AttributeEnumTunnelMediumType = iota + 1
	AttributeEnumTunnelMediumTypeIPv6
	AttributeEnumTunnelMediumTypeNSAP
	AttributeEnumTunnelMediumTypeHDLC
	AttributeEnumTunnelMediumTypeBBN1822
	AttributeEnumTunnelMediumType802
	AttributeEnumTunnelMediumTypeE163
	AttributeEnumTunnelMediumTypeE164
	AttributeEnumTunnelMediumTypeF69
	AttributeEnumTunnelMediumTypeX121
	AttributeEnumTunnelMediumTypeIPX
	AttributeEnumTunnelMediumTypeAppletalk
	AttributeEnumTunnelMediumTypeDecnetIV
	AttributeEnumTunnelMediumTypeBanyanVines
	AttributeEnumTunnelMediumTypeE164WithNSAPSubaddress
)

func ParseAttributeEnumTunnelMediumType(v string) (AttributeEnumTunnelMediumType, error) {
	switch v {
	case "IPv4":
		return AttributeEnumTunnelMediumTypeIPv4, nil
	case "IPv6":
		return AttributeEnumTunnelMediumTypeIPv6, nil
	case "NSAP":
		return AttributeEnumTunnelMediumTypeNSAP, nil
	case "HDLC":
		return AttributeEnumTunnelMediumTypeHDLC, nil
	case "BBN 1822":
		return AttributeEnumTunnelMediumTypeBBN1822, nil
	case "802":
		return AttributeEnumTunnelMediumType802, nil
	case "E.163":
		return AttributeEnumTunnelMediumTypeE163, nil
	case "E.164":
		return AttributeEnumTunnelMediumTypeE164, nil
	case "F.69":
		return AttributeEnumTunnelMediumTypeF69, nil
	case "X.121":
		return AttributeEnumTunnelMediumTypeX121, nil
	case "IPX":
		return AttributeEnumTunnelMediumTypeIPX, nil
	case "Appletalk":
		return AttributeEnumTunnelMediumTypeAppletalk, nil
	case "Decnet IV":
		return AttributeEnumTunnelMediumTypeDecnetIV, nil
	case "Banyan Vines":
		return AttributeEnumTunnelMediumTypeBanyanVines, nil
	case "E.164 with NSAP subaddress":
		return AttributeEnumTunnelMediumTypeE164WithNSAPSubaddress, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumTunnelMediumType(i), nil
		}
		return 0, fmt.Errorf("invalid tunnel medium type value: %s", v)
	}
}

type AttributeEnumIngressFilters uint32

const (
	AttributeEnumIngressFiltersEnabled AttributeEnumIngressFilters = iota + 1
	AttributeEnumIngressFiltersDisabled
)

func ParseAttributeEnumIngressFilters(v string) (AttributeEnumIngressFilters, error) {
	switch v {
	case "Enabled":
		return AttributeEnumIngressFiltersEnabled, nil
	case "Disabled":
		return AttributeEnumIngressFiltersDisabled, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return AttributeEnumIngressFilters(i), nil
		}
		return 0, fmt.Errorf("invalid ingress filter value: %s", v)
	}
}
