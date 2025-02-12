# RADIUS Attributes

## Attribute Value Types

Each attribute has an expected value type, which are the following:

- `string`: UTF-8 encoded strings
- `binary`: Hex string for a binary blob value
- `ipv4`: Valid IPv4 address
- `uint`: Unsigned integer
- `enum`: Unsigned integer or Enum value

> [!IMPORTANT]
> The maximum size of an attribute is 255 bytes.

## Attribute Types

These are the supported attributes that can be defined and their value types:

- `Acct-Authentic`: [`enum`](#acct-authentic)
- `Acct-Delay-Time`: `uint`
- `Acct-Input-Octets`: `uint`
- `Acct-Input-Packets`: `uint`
- `Acct-Link-Count`: `uint`
- `Acct-Multi-Session-Id`: `string`
- `Acct-Output-Octets`: `uint`
- `Acct-Output-Packets`: `uint`
- `Acct-Session-Id`: `string`
- `Acct-Session-Time`: `uint`
- `Acct-Status-Type`: [`enum`](#acct-status-type)
- `Acct-Terminate-Cause`: [`enum`](#acct-terminate-cause)
- `CHAP-Challenge`: _unsupported_
- `CHAP-Password`: _unsupported_
- `Callback-Id`: `string`
- `Callback-Number`: `string`
- `Called-Station-Id`: `string`
- `Calling-Station-Id`: `string`
- `Class`: `binary`
- `EAP-Message`: `binary`
- `Egress-VLAN-Name`: `string`
- `Egress-VLANID`: _not implemented_
- `Error-Cause`: [`enum`](#error-cause)
- `Filter-Id`: `string`
- `Framed-AppleTalk-Link`: `uint`
- `Framed-AppleTalk-Network`: `uint`
- `Framed-AppleTalk-Zone`: `binary`
- `Framed-Compression`: [`enum`](#framed-compression)
- `Framed-IP-Address`: `ipv4`
- `Framed-IP-Netmask`: `ipv4`
- `Framed-IPX-Network`: `uint`
- `Framed-MTU`: `uint`
- `Framed-Protocol`: [`enum`](#framed-protocol)
- `Framed-Route`: `string`
- `Framed-Routing`: [`enum`](#framed-routing)
- `Idle-Timeout`: `uint`
- `Ingress-Filters`: [`enum`](#ingress-filters)
- `Login-IP-Host`: `ipv4`
- `Login-LAT-Group`: `binary`
- `Login-LAT-Node`: `string`
- `Login-LAT-Port`: `string`
- `Login-LAT-Service`: `string`
- `Login-Service`: [`enum`](#login-service)
- `Login-TCP-Port`: `uint`
- `Message-Authenticator`: _enter empty string_
- `NAS-IP-Address`: `ipv4`
- `NAS-Identifier`: `string`
- `NAS-Port-Type`: [`enum`](#nas-port-type)
- `NAS-Port`: `uint`
- `Port-Limit`: `uint`
- `Proxy-State`: `binary`
- `Reply-Message`: `string`
- `Service-Type`: [`enum`](#service-type)
- `Session-Timeout`: `uint`
- `State`: `binary`
- `Termination-Action`: [`enum`](#termination-action)
- `Tunnel-Medium-Type`: [`enum`](#tunnel-medium-type)
- `Tunnel-Private-Group-ID`: `string`
- `Tunnel-Type`: [`enum`](#tunnel-type)
- `User-Name`: `string`
- `User-Password`: _use `auth pap`_
- `User-Priority-Table`: `binary`
- `Vendor-Specific`: _not implemented_

## Enum values

### Acct-Authentic

- `RADIUS`
- `Local`
- `Remote`

### Acct-Status-Type

- `Start`
- `Stop`
- `Interim-Update`
- `Accounting-On`
- `Accounting-Off`

### Acct-Terminate-Cause

- `User Request`
- `Lost Carrier`
- `Lost Service`
- `Idle Timeout`
- `Session Timeout`
- `Admin Reset`
- `Admin Reboot`
- `Port Error`
- `NAS Error`
- `NAS Request`
- `Port Unneeded`
- `Port Preempted`
- `Port Suspended`
- `Service Unavailable`
- `Callback`
- `User Error`
- `Host Request`

### Error-Cause

- `Residual Session Context Removed`
- `Invalid EAP Packet`
- `Unsupported Attribute`
- `Missing Attribute`
- `NAS Identification Mismatch`
- `Invalid Request`
- `Unsupported Service`
- `Unsupported Extension`
- `Administratively Prohibited`
- `Request Not Routable`
- `Session Context Not Found`
- `Session Context Not Removable`
- `Other Proxy Processing Error`
- `Resources Unavailable`
- `Request Initiated`

### Framed-Compression

- `None`
- `VJ header compression`
- `IPX header compression`
- `Stac-LZS compression`

### Framed-Protocol

- `PPP`
- `SLIP`
- `ARAP`
- `Gandalf Protocol`
- `Xylogics`
- `X.75 Synchronous`

### Framed-Routing

- `None`
- `Send`
- `Listen`
- `SendListen`

### Ingress-Filters

- `Enabled`
- `Disabled`

### Login-Service

- `Telnet`
- `Rlogin`
- `TCP Clear`
- `PortMaster`
- `LAT`
- `X25-PAD`
- `X25-T3POS`

### NAS-Port-Type

- `Async`
- `Sync`
- `ISDN Sync`
- `ISDN Async V.120`
- `ISDN Async V.110`
- `Virtual`
- `PIAFS`
- `HDLC Clear Channel`
- `X.25`
- `X.75`
- `G.3 Fax`
- `SDSL`
- `ADSL-CAP`
- `ADSL-DMT`
- `IDSL`
- `Ethernet`
- `xDSL`
- `Cable`
- `Wireless - Other`
- `Wireless - IEEE 802.11`

### Service-Type

- `Login`
- `Framed`
- `Callback Login`
- `Callback Framed`
- `Outbound`
- `Administrative`
- `NAS Prompt`
- `Authenticate Only`
- `Callback NAS Prompt`
- `Call Check`
- `Callback Administrative`

### Termination-Action

- `Default`
- `RADIUS-Request`

### Tunnel-Medium-Type

- `IPv4`
- `IPv6`
- `NSAP`
- `HDLC`
- `BBN 1822`
- `802`
- `E.163`
- `E.164`
- `F.69`
- `X.121`
- `IPX`
- `Appletalk`
- `Decnet IV`
- `Banyan Vines`
- `E.164 with NSAP subaddress`

### Tunnel-Type

- `PointToPointTunnelingProtocol`
- `Layer Two Forwarding`
- `Layer Two Tunneling Protocol`
- `Ascend Tunnel Management Protocol`
- `Virtual Tunneling Protocol`
- `IP Authentication Header`
- `Minimal IP-in-IP Encapsulation`
- `IP Encapsulation Security Payload`
- `Generic Route Encapsulation`
- `Bay Dial Virtual Services`
- `IP-in-IP Tunneling`
- `Virtual LAN`
