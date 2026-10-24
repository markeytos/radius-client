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

- `APC-Service-Type`: [`enum`](#apc-service-type)
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
- `Aruba-User-Role`: `string`
- `CHAP-Challenge`: _unsupported_
- `CHAP-Password`: _unsupported_
- `Callback-Id`: `string`
- `Callback-Number`: `string`
- `Called-Station-Id`: `string`
- `Calling-Station-Id`: `string`
- `Cisco-AVPair`: `string`
- `Class`: `string`
- `EAP-Message`: `binary`
- `Egress-VLAN-Name`: `string`, optional [`tagged:` or `untagged:`](#egress-vlans)
- `Egress-VLANID`: [`tagged:<vlan>` or `untagged:<vlan>`](#egress-vlans)
- `Error-Cause`: [`enum`](#error-cause)
- `Filter-Id`: `string`
- `Fortinet-Group-Name`: `string`
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
- `Tunnel-Medium-Type`: [`enum`](#tunnel-medium-type), optional [tag](#tunnel-tags)
- `Tunnel-Private-Group-ID`: `string`, optional [tag](#tunnel-tags)
- `Tunnel-Type`: [`enum`](#tunnel-type), optional [tag](#tunnel-tags)
- `User-Name`: `string`
- `User-Password`: _use `auth pap`_
- `User-Priority-Table`: `binary`
- `Vendor-Specific`: [see below](#vendor-specific-attributes)

## Vendor specific attributes

A vendor specific attribute is identified by a vendor ID and a vendor type,
not by its attribute type, since every vendor attribute is carried in an
attribute of type `Vendor-Specific`. The vendor attributes listed above are
addressed by name just like any other attribute:

```sh
--attrs-to-recv Fortinet-Group-Name:NetAdmins \
--attrs-to-recv APC-Service-Type:Admin
```

The value is everything that follows the attribute name, so it may hold
colons and equals signs of its own, as a Cisco AVPair does:

```sh
--attrs-to-recv Cisco-AVPair:shell:priv-lvl=15
```

| Attribute             | Vendor   | Vendor ID | Vendor type |
| --------------------- | -------- | --------- | ----------- |
| `APC-Service-Type`    | APC      | 318       | 1           |
| `Aruba-User-Role`     | Aruba    | 14823     | 1           |
| `Cisco-AVPair`        | Cisco    | 9         | 1           |
| `Fortinet-Group-Name` | Fortinet | 12356     | 1           |

Any other vendor attribute is addressed by number, as
`Vendor-Specific:<vendor ID>:<vendor type>`, and takes a `binary` value:

```sh
--attrs-to-recv Vendor-Specific:12356:1:4e657441646d696e73
```

> [!NOTE]
> A vendor attribute that is in the table above keeps its value type when it
> is addressed by number, so `Vendor-Specific:318:1:Admin` and
> `APC-Service-Type:Admin` are the same attribute.

A server may pack several vendor attributes of one vendor into a single
attribute of type `Vendor-Specific`, which RFC 2865 §5.26 allows. An attribute
given to `--attrs-to-recv` is matched against each vendor attribute a reply
holds, so it is found either way.

## Tunnel tags

[RFC 2868](https://datatracker.ietf.org/doc/html/rfc2868) puts a tag in the
first value octet of `Tunnel-Type`, `Tunnel-Medium-Type`, and
`Tunnel-Private-Group-ID`. The tag is a number from 0 to 31 and groups the
attributes that describe one tunnel. Tag 0 means the tag is unused.

Write the tag as a `#` suffix on the attribute name. The value after the
colon is then the whole value, so a group id of `10:20` is not read as a tag:

```sh
--attrs-to-recv Tunnel-Type#1:Virtual LAN \
--attrs-to-recv Tunnel-Medium-Type#1:802 \
--attrs-to-recv Tunnel-Private-Group-ID#1:20
```

`Tunnel-Private-Group-ID:20` is the string `20` with no tag octet. That is
the unused-tag form, because the first byte of `20` is greater than 0x1F.
`Tunnel-Private-Group-ID#0:20` is the same string with an explicit zero tag
octet, which is what a server sends when it includes the tag and sets it to
zero. `Tunnel-Private-Group-ID:10:20` is the literal string `10:20`. A tag
above 31 is an error.

## Egress VLANs

[RFC 4675](https://datatracker.ietf.org/doc/html/rfc4675) marks a VLAN as
tagged (`0x31`) or untagged (`0x32`). `Egress-VLANID` is that indication
plus a VLAN id from 0 to 4095:

```sh
--attrs-to-recv Egress-VLANID:tagged:100
--attrs-to-recv Egress-VLANID:untagged:100
```

`Egress-VLAN-Name` takes the same prefix. RFC 4675 requires that indication,
so use it when sending or expecting a name. A name with no prefix is a legacy
form this client still sends unchanged. A compliant NAS reads the first byte
of that string as the indication, which makes a name such as `1st-floor` look
like a tagged VLAN called `st-floor`.

```sh
--attrs-to-recv Egress-VLAN-Name:tagged:Engineering
--attrs-to-send Egress-VLAN-Name:untagged:Engineering
```

## Enum values

### APC-Service-Type

- `Admin`
- `Device`
- `ReadOnly`
- `Outlet`
- `Card`
- `NetworkOnly`

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
