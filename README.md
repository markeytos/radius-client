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

This is used internally at Keytos to thoroughly test [EZRADIUS](https://www.keytos.io/cloud-radius-as-a-service-for-azure-and-entra-id).
This client seeks to close the gap from existing testing clients such as [`radclient`](https://wiki.freeradius.org/config/Radclient)
and [`eapol_test`](https://manpages.debian.org/testing/eapoltest/eapol_test.8.en.html),
by first consolidating the capabilities of both tools into one, and then extending
the tool to support [RADIUS-over-TLS (RadSec)](https://datatracker.ietf.org/doc/html/rfc6614)
and simple, granular controls for Keytos' use-cases.

## Relevant RFCs And Documents

- [RFC 2759: MS-CHAP-V2](https://datatracker.ietf.org/doc/html/rfc2759)
- [RFC 2865: RADIUS](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 2866: RADIUS Accounting](https://datatracker.ietf.org/doc/html/rfc2866)
- [RFC 3579: RADIUS EAP](https://datatracker.ietf.org/doc/html/rfc3579)
- [RFC 3748: EAP](https://datatracker.ietf.org/doc/html/rfc3748)
- [RFC 5080: Common RADIUS Implementation Issues and Suggested Fixes](https://datatracker.ietf.org/doc/html/rfc5080)
- [RFC 5216: EAP-TLS](https://datatracker.ietf.org/doc/html/rfc5216)
- [RFC 5281: EAP-TTLS](https://datatracker.ietf.org/doc/html/rfc5281)
- [RFC 8940: Session-Id Derivation for EAP-based Authentication](https://datatracker.ietf.org/doc/html/rfc8940)
- [PEAP](https://datatracker.ietf.org/doc/html/draft-josefsson-pppext-eap-tls-eap-06)
- [MAC Authentication Bypass](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/15-sy/sec-usr-aaa-15-sy-book/sec-usr-mac-auth-bypass.pdf)
