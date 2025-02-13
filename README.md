# Keytos' RADIUS Client

A RADIUS client that can carry out the following authentication protocols:

- `mab` (MAC address authentication bypass)
- `pap`
- `eap-ms-chapv2`
- `eap-tls`
- `eap-ttls-pap`
- `eap-ttls-eap-ms-chapv2`
- `eap-ttls-eap-tls`
- `peap-ms-chapv2`

As well as `status` packets and accounting (WIP).

This is used internally at Keytos to thoroughly test [EZRADIUS](https://www.keytos.io/cloud-radius-as-a-service-for-azure-and-entra-id).
This client seeks to close the gap from existing testing clients such as [`radclient`](https://wiki.freeradius.org/config/Radclient)
and [`eapol_test`](https://manpages.debian.org/testing/eapoltest/eapol_test.8.en.html),
by first consolidating the capabilities of both tools into one, and then extending
the tool to support [RADIUS-over-TLS (RadSec)](https://datatracker.ietf.org/doc/html/rfc6614)
and simple, granular controls for Keytos' use-cases.

## Usage

To install the tool locally for use, you can run the following command

```bash
go install github.com/markeytos/radius-client@latest

# To install a specific version, replace `latest` with a version
# $ go install github.com/markeytos/radius-client@vX.X.X
```

### Status

If the RADIUS server you are probing supports [`Status-Server`](https://datatracker.ietf.org/doc/html/rfc5997),
you can probe the server with the following commands:

```bash
# Test UDP authentication
radius-client status udp-auth $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# Test UDP accounting
radius-client status udp-acct $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# Test RADIUS TLS
radius-client status tls $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

You can change the specific ports away from defaults if desired with the following
flags:

- `--udp-auth-port` (default is 1812)
- `--udp-acct-port` (default is 1813)
- `--tcp-port` (default is 2083)

### Authentication

All authentication protocols supported by this client can be tested against a Classic
RADIUS endpoint (unencrypted RADIUS over UDP), or over RadSec (encrypted and authenticated
RADIUS over TCP-TLS).

The following examples will assume that either of the following is exported:

```bash
# Classic RADIUS
export RADIUS_AUTH_COMMAND=radius-client authentication udp \
    $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# If you want to test RadSec (RADIUS over TCP-TLS), use:
export RADIUS_AUTH_COMMAND=radius-client authentication tls \
    $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

If you do not need to trust the RadSec server certificate, you can append the `--radsec-unsafe`
flag. This flag will skip server authentication.

#### MAC Authentication Bypass

To test MAC authentication bypass, run the following:

```bash
$RADIUS_AUTH_COMMAND mab --mac $MAC_ADDRESS
```

#### Password-based Authentication

To test basic password authentication, you can use the following:

```bash
# Testing PAP
$RADIUS_AUTH_COMMAND pap --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2
$RADIUS_AUTH_COMMAND eap-ms-chapv2 --username $USERNAME --password $PASSWORD
```

For password-based authentication schemes that run over an internal TLS tunnel, here
are the commands to test them:

```bash
# Testing PAP over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-ttls-pap --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2 over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-ttls-eap-ms-chapv2 --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2 over PEAP
$RADIUS_AUTH_COMMAND peap-ms-chapv2 --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD
```

#### Certificate-based Authentication

Two variants of TLS can be tested, basic EAP-TLS and EAP-TLS inside a EAP-TTLS tunnel:

```bash
# Testing EAP-TLS
$RADIUS_AUTH_COMMAND eap-tls --client-cert $CLIENT_CERT_PATH --ca-cert $SERVER_CA_CERT_PATH

# Testing EAP-TLS over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-tls --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --client-cert $CLIENT_CERT_PATH --ca-cert $SERVER_CA_CERT_PATH
```

The default TLS version supported is 1.2, 1.3 is supported but has not been tested,
and it can be enabled by adding the flag `--tls-version 1.X`.

### Attributes

RADIUS servers can be configured to expect and behave differently depending on the
set of attributes sent. This can be tested and verified by defining attributes that
the client should send in every packet in the handshake, and all the attributes it
expects to receive in a successful final packet.

- `--attrs-to-send`: Define attributes to be sent in all packets sent to the server
- `--attrs-to-recv`: Define attributes that the server must send on successful handshakes

These can be used in the following format:

```bash
$RADIUS_AUTH_COMMAND $AUTHENTICATION_PROTOCOL $AUTHENTICATION_PROTOCOL_PARAMETERS \
    --attrs-to-send $ATTRIBUTE_TYPE:$ATTRIBUTE_VALUE \
    --attrs-to-recv $ATTRIBUTE_TYPE:$ATTRIBUTE_VALUE
```

> [!NOTE]
> Keep in mind that some attributes should not be sent as they may be utilized by
> the authentication protocol and will be overwritten or require different treatment,
> such as `User-Password`.

You can also send multiple attributes and expect multiple attributes. Each attribute
type cannot be defined more than once for each direction for simplicity's sake. Below
is an example of how to define multiple attributes to be sent and received in `pap`
authentication:

```bash
$RADIUS_AUTH_COMMAND pap --username test_user --password test_password \
    --attrs-to-send NAS-Identifier:fake-router \
    --attrs-to-send Framed-Protocol:PPP \
    --attrs-to-recv Framed-Protocol:PPP \
    --attrs-to-recv Service-Type:Framed \
    --attrs-to-recv Filter-Id:20
```

In the example above, the client attempts to authenticate with `pap`, sends two
additional attributes to the server, and expects three attributes from the server
in the `Access-Accept` packet.

You can view all attributes and their values can be defined in this [document](./RADIUS_ATTRIBUTES.md).

### Accounting

Accounting can be tested against a Classic RADIUS endpoint and RadSec.

The following examples will assume that either of the following is exported:

```bash
# Classic RADIUS
export RADIUS_ACCT_COMMAND=radius-client accounting udp \
    $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# If you want to test RadSec (RADIUS over TCP-TLS), use:
export RADIUS_ACCT_COMMAND=radius-client accounting tls \
    $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

An accounting request **must** contain both `Acct-Status-Type` and `Acct-Session-Id`
attributes. These are passed via the `--attrs-to-send` flag. For example:

```bash
$RADIUS_ACCT_COMMAND --attrs-to-send Acct-Status-Type:Start --attrs-to-send Acct-Session-Id:1234
```

Additional accounting values can be passed by adding the other accounting attributes,
which can be found in [the list of attributes](./RADIUS_ATTRIBUTES.md). Accounting-specific
attributes generally have a `Acct-` prefix.

## Relevant RFCs And Documents

- [RFC 2759: MS-CHAP-V2](https://datatracker.ietf.org/doc/html/rfc2759)
- [RFC 2865: RADIUS](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 2866: RADIUS Accounting](https://datatracker.ietf.org/doc/html/rfc2866)
- [RFC 3579: RADIUS EAP](https://datatracker.ietf.org/doc/html/rfc3579)
- [RFC 3748: EAP](https://datatracker.ietf.org/doc/html/rfc3748)
- [RFC 5080: Common RADIUS Implementation Issues and Suggested Fixes](https://datatracker.ietf.org/doc/html/rfc5080)
- [RFC 5216: EAP-TLS](https://datatracker.ietf.org/doc/html/rfc5216)
- [RFC 5281: EAP-TTLS](https://datatracker.ietf.org/doc/html/rfc5281)
- [RFC 5997: Status in RADIUS](https://datatracker.ietf.org/doc/html/rfc5997)
- [RFC 8940: Session-Id Derivation for EAP-based Authentication](https://datatracker.ietf.org/doc/html/rfc8940)
- [PEAP](https://datatracker.ietf.org/doc/html/draft-josefsson-pppext-eap-tls-eap-06)
- [MAC Authentication Bypass](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/15-sy/sec-usr-aaa-15-sy-book/sec-usr-mac-auth-bypass.pdf)
