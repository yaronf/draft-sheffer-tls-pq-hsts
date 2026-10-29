---
title: "An HSTS-like Header for Secure PQ Migration"
abbrev: "PQ-HSTS"
category: std

docname: draft-sheffer-tls-pq-hsts-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
pi:
  comments: yes
keyword:
 - post-quantum migration
 - HSTS
 - Structured Fields
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "yaronf/draft-sheffer-tls-pq-hsts"
  latest: "https://yaronf.github.io/draft-sheffer-tls-pq-hsts/draft-sheffer-tls-pq-hsts.html"

author:
 -
    ins: Y. Sheffer
    name: Yaron Sheffer
    organization: Independent
    email: yaronf.ietf@gmail.com
 -
    name: Tirumaleswar|Reddy.K
    organization: Nokia
    email: kondtir@gmail.com
 -
    ins: D. Benjamin
    name: David Benjamin
    organization: Google LLC
    email: davidben@google.com

informative:
  RescorlaPQEmergency:
    title: "PQ emergency"
    target: https://educatedguesswork.org/posts/pq-emergency/
    author:
      ins: E. Rescorla
      name: Eric Rescorla
    date: 2024-04
  ChromiumPQAuthRoadmap:
    title: "Post-Quantum HTTPS Authentication Roadmap"
    target: https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/
    author:
      -
        ins: D. Benjamin
        name: David Benjamin
      -
        ins: J. DeBlasio
        name: Joe DeBlasio
    date: 2026-02
  ProtectingAgainstHSTSAbuse:
    title: Protecting Against HSTS Abuse
    target: https://webkit.org/blog/8146/protecting-against-hsts-abuse/
    author:
      -
        name: Brent Fulgham
    date: 2018-03-16
  StrictNavigationalSecurity:
    title: Strict Navigational Security
    target: https://github.com/mikewest/strict-navigation-security
    author:
      -
        name: Mike West
    date: 2019-09

...

--- abstract

This document defines an HTTP response header field, `Require-PQ-Auth`, that
instructs user agents to require a quantum-resistant certificate chain in
subsequent connections. This is a short-term, opt-in mechanism for HTTP
origins to protect against legacy classical trust anchors. It will become
unnecessary when UAs remove these trust anchors.


--- middle

# Introduction

Migrating TLS authentication to post-quantum cryptography cannot be done
by flipping a single switch. For a long period, many origins will still
present classical certificate chains, so user agents (UAs) will need to trust
classical trust anchors alongside quantum-resistant ones.
This allows an attacker able to forge classical certificates to downgrade the
connection. Whether or not the origin had actually upgraded, a client that
still accepts classical paths will treat that forged credential as valid.

This document defines an HTTP response header field, `Require-PQ-Auth`,
which allows an origin to indicate to the user agent to only accept chains
from quantum-resistant trust anchors in subsequent connections.

This is a near-term mechanism with several limitations described in
{{limitations}}. It is intended to be temporary, for use until classical trust
anchors are removed. {{ChromiumPQAuthRoadmap}} describes an example roadmap to
do so.

## PQ-HSTS in the Broader Migration Context

This mechanism addresses classical trust-anchor impersonation during the
dual-trust-store period. It is one near-term lever within the bigger industry migration. The
harder problem is coordinating clients, servers, and trust-anchor
operators onto quantum-resistant authentication on a compressed timeline
{{RescorlaPQEmergency}}. {{ChromiumPQAuthRoadmap}} describes a fuller
migration program in which an HSTS-like opt-in is only an early stage.

As additional context, deployments will use different quantum-resistant
credential forms, including Merkle Tree Certificates (MTC). Normative
requirements in this document stay at the trust-anchor abstraction so
those forms can satisfy `Require-PQ-Auth` without tying the pin to a
single encoding.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used in this document:

classical:
: Cryptography or credentials that are not designed to remain secure
  against a cryptographically-relevant quantum computer (CQRC), such as RSA
  or elliptic-curve public-key algorithms. A classical trust anchor is a trust
  anchor that authenticates only classical paths.

quantum-resistant:
: Not classical-only. For authentication material, this document treats
  pure post-quantum algorithms and composite algorithms
  {{?I-D.ietf-lamps-pq-composite-sigs}} as one class, consistent with the
  PQC end-entity classification in
  {{?I-D.sheffer-tls-pqc-continuity}}. Which algorithms a UA accepts as
  quantum-resistant is a matter of local policy and the relevant algorithm
  specifications;
  this document states the property, not a closed algorithm list.

<cref>TODO: add a more precise definition of quantum-resistance for MTC.</cref>

trust anchor:
: The root of acceptance for a server credential: an X.509 trust anchor
  {{?RFC5280}} or an MTC trust base / cosigner trust as defined by
  {{?I-D.ietf-plants-merkle-tree-certs}}. Normative requirements in this
  document refer to the class of trust anchor (classical vs
  quantum-resistant), not to a single encoding.

HSTS terms:
: This document refers to Known HSTS Host, HSTS Policy, and related
  terminology from {{?RFC6797}} only for comparison. HSTS state is
  independent of the policy defined here.

Known PQ Host / PQ Policy:
: A host for which the UA has noted a valid `Require-PQ-Auth` policy
  ({{syntax}}, {{ua-behavior}}), including expiry derived from `max-age`
  and whether `include-subdomains` applies. Storage is parallel to—not
  part of—HSTS Policy storage.

superdomain:
: As in {{?RFC6797}}, a domain name of which another domain name is a
  subdomain. For example, `example.com` is a superdomain of
  `www.example.com`.

# Threat Model

This document addresses classical trust-anchor impersonation during the
dual-trust-store migration period. An attacker forges a classical
certificate with a CRQC for a name whose operator intends to use only
quantum-resistant authentication, and presents that credential to a
dual-accepting UA. The negotiated key agreement does not matter for this
attack: the holder of the forged credential can impersonate the server
whether key agreement is classical or quantum-resistant.

# Syntax {#syntax}

`Require-PQ-Auth` is an HTTP Structured Header field {{!RFC9651}}. Its
value MUST be a Dictionary. Recipients that cannot parse the field value
as a Dictionary MUST NOT update any Noted PQ Policy for the host based on
that field (any previously Noted policy remains unchanged).

The following Dictionary members are defined. Keys are lowercase as
required by Structured Fields. Unknown members MUST be ignored.
Recognized members are processed as specified below when the Dictionary
parses successfully.

max-age:
: Integer (required). Non-negative number of seconds after receipt
  during which the UA regards the host as a Known PQ Host with this
  policy. A value of 0 signals the UA to delete any Noted PQ Policy for
  the host (including subdomain scope learned from this host).

include-subdomains:
: Boolean true if present as a bare Dictionary member (optional). If
  present, the PQ Policy applies to the host and to hosts whose domain
  names are subdomains of that host's domain name, analogous to HSTS
  `includeSubDomains` {{?RFC6797}} but applying only to this PQ Policy.
  Absence means host-only scope.

If the Dictionary does not include a usable `max-age`, or if any present
member is malformed for its type, the UA MUST NOT update Noted PQ Policy
from this field.

Examples:

~~~
Require-PQ-Auth: max-age=86400
Require-PQ-Auth: max-age=31536000, include-subdomains
~~~

# Server Processing {#server}

Servers MUST emit `Require-PQ-Auth` only when they can keep the following
commitment for the lifetime conveyed by `max-age` (and for any hosts
covered by `include-subdomains`): serve a certification path anchored at
a quantum-resistant trust anchor (pure post-quantum or composite per the
server's deployment), with no mixed classical/quantum-resistant path.

The commitment applies to every server that answers for each covered
hostname, not only the instance that sent the header—including all
CDN edges, failover or backup providers, and HTTP/3 endpoints advertised
via Alt-Svc {{?RFC7838}}. If any such endpoint cannot meet the policy,
UAs that reach it will fail to connect.

The server MUST send `Require-PQ-Auth` only over HTTPS. Otherwise UAs
will not note the field ({{ua-behavior}}). The server SHOULD include the
header on every HTTPS response, unless it omits the header for
performance reasons (which typically does not make sense given the
header's small size).

## Choosing policy parameters

`max-age` should reflect how long the operator is willing to keep the
commitment above. Operators typically start with a short `max-age` while
gaining confidence, then increase it.

`include-subdomains` MUST NOT be sent unless every host that would be
covered can likewise satisfy the commitment for the same window.

## Updating and clearing policy

A valid `Require-PQ-Auth` field replaces any previously Noted PQ Policy
for that host when the UA notes it ({{ua-behavior}}). Omitting the header
does not clear Noted policy.

To delete client state before expiry, the server sends `max-age` with
value 0. UAs that successfully note that response MUST delete the Noted
PQ Policy ({{ua-behavior}}). That escape hatch is useful only
in laboratory or similar conditions, where the client population is small
and individually identifiable. It works only while the server can still
meet the commitment: enforcing UAs reject connections that do not, and so
never see the clear. Operators should keep meeting the commitment until
outstanding pins expire. If the server loses that ability first, those
UAs stay locked out until expiry or manual action.

# User Agent Behavior {#ua-behavior}

This section defines how UAs note and enforce `Require-PQ-Auth` policy.

## Noting the header {#noting}

Upon receipt of a `Require-PQ-Auth` header field in an HTTP response, the
UA notes a PQ Policy when all of the following hold, and MUST NOT note
one otherwise:

1. The response was received over an error-free HTTPS connection that
   uses TLS 1.3 {{!RFC9846}} or later.
2. That connection meets the checks in {{pq-checks}}, whether or not a
   PQ Policy is already Noted for the host.
3. The field value parses as a Structured Fields Dictionary per
   {{syntax}}, including a valid `max-age` member.

The host need not be a Known HSTS Host. Noting PQ Policy MUST NOT modify
HSTS Policy storage.

When noting, the UA MUST:

1. Store a PQ Policy for the host as a Known PQ Host, with expiry derived
   from `max-age` (or delete the policy if `max-age` is 0).
2. Record subdomain scope from `include-subdomains` when that member is
   usable; otherwise host-only scope.

If a subsequent valid `Require-PQ-Auth` field is noted for the host, it
replaces the prior PQ Policy (including subdomain scope) for that host.
Absence of the header field on a later response does not by itself clear
PQ Policy before expiry; servers clear state with `max-age` of 0.

UAs MAY additionally configure other hosts as Known PQ Hosts via local policy.
For example, the UA MAY be pre-configured with a list of pre-loaded Known PQ
Hosts, similar to {{Section 12.3 of ?RFC6797}}.

## Connection checks {#pq-checks}

A connection meets the checks of this section when all of the following
hold. These checks apply to the connection itself. They do not depend on
a PQ Policy already being Noted.

1. The trust anchor that caused acceptance is quantum-resistant (pure
   post-quantum or composite per local policy), whether that trust anchor
   is an X.509 trust anchor or an MTC trust base / cosigner.
2. The accepted certification path is entirely quantum-resistant: no hop is
   classical. (Detailed mixed-path rejection may be refined here or by
   reference to a dedicated path-validation document.)

## Enforcement {#enforcement}

When establishing a connection to a host covered by an unexpired Noted PQ
Policy — either because the host itself is a Known PQ Host, or because a
Known PQ Host that is a superdomain of this host has `include-subdomains`
— the connection MUST meet the checks in {{pq-checks}}, and MUST use
TLS 1.3 {{!RFC9846}} or later.

If the connection does not meet those requirements, the UA MUST abort the
TLS handshake with a fatal "handshake_failure" alert ({{!RFC9846}},
Section 6.2). The UA MUST NOT offer the user a way to proceed
({{Section 12.1 of ?RFC6797}}).

The UA MAY skip enforcement according to local policy. For example,
similar to {{Section 2.6 of ?RFC7469}}, the UA MAY skip enforcement if
the validated certificate chain terminates at a user-defined trust
anchor, rather than a trust anchor built into the UA (or underlying
platform). The main use case is a middlebox that terminates TLS using
such a locally installed trust anchor.

This document does not impose separate end-entity signature-algorithm
requirements beyond the trust-anchor class and path-consistency rules
above. It does not enumerate MTC validation procedures; those remain
matters for {{?I-D.ietf-plants-merkle-tree-certs}}.

Once classical trust anchors are no longer accepted for authentication,
`Require-PQ-Auth` is redundant. UAs MAY clear PQ Policy for Known PQ Hosts when
local policy determines that the pin is obsolete.
Servers SHOULD stop sending the header in that environment. HSTS policy,
if any, is unaffected.


# Operational Considerations {#ops}

<cref>TODO Operational considerations: CDN / multi-CDN consistency;
staged `max-age` independent of HSTS; independent HSTS
`includeSubDomains` vs PQ `include-subdomains`; HTTPS required to note,
HSTS not required; public Web ≈ MTC vs enterprise ≈ X.509 PQ chains; MTC
evolving; SFV serialization (lowercase keys, commas). Middlebox
carve-out is in {{enforcement}}.</cref>


# Security Considerations

The security considerations of HSTS ({{Section 14 of ?RFC6797}}) apply
to `Require-PQ-Auth`. This section covers where they differ.

## Key Agreement {#security-ke}

Quantum resistance for a TLS session also requires a quantum-resistant
key agreement mechanism. While `Require-PQ-Auth` does not directly
constrain the key agreement, the TLS handshake provides downgrade
protection when the authentication itself is secure
({{Appendix F.1 of !RFC9846}}). Provided the Known PQ Host's TLS server
is correctly configured to prefer quantum-resistant key agreement
methods, a CRQC cannot downgrade the TLS session to a classical key
agreement mechanism.

The authentication pin still mitigates the threat this document
targets even if key agreement remains classical. Classical trust-anchor
impersonation is offline certificate forgery with a CRQC, then
presentation of that credential. Breaking a live classical Diffie-Hellman
key agreement to recover session keys requires a real-time
CRQC attack on that handshake. That is a harder, later capability than
the dual-trust-store impersonation this pin blocks for Known PQ Hosts.

## Non-Conformant User Agent Implications

UAs that do not implement this document ignore the header field. If
such a UA accepts both classical and quantum-resistant authentication, a
quantum attacker can present a forged classical certificate even when
the server offers a quantum-resistant one.

## Limitations

As with HSTS, noting a PQ Policy does not protect initial visits to an origin.
An attacker who can modify that first response can strip `Require-PQ-Auth`,
and the UA never notes the policy. Additionally, UAs might limit state set by
an origin, e.g. as part of private browsing modes or to protect against
cross-sign tracking {{ProtectingAgainstHSTSAbuse}}
{{StrictNavigationalSecurity}}. When state is limited, there are more "initial"
responses for an attacker to intercept.

{{noting}} permits UAs to configure other Known PQ Hosts as local policy,
such as a pre-configured list. While such measures can mitigate this attack,
they can introduce other limitations when the number of otherwise
quantum-resistant hosts exceeds an implementation's size limits.

Non-browser clients may be further limited in their ability to both maintain
state and include large, pre-configured lists.

These limitations mean `Require-PQ-Auth` is only viable as a temporary measure
for a limited number of applications. In many applications, it will still be
necessary to trust anchors in the near term. {{ChromiumPQAuthRoadmap}}
describes one such transition plan.

## Denial of Service

An attacker that controls a middlebox that terminates TLS can cause a UA
to note `Require-PQ-Auth` only when the connection meets {{pq-checks}}. A
middlebox that cannot meet those checks cannot set the policy.

If the attacker can meet the checks and sets a large `max-age`, UAs that
note the policy require {{pq-checks}} until the policy expires.
`include-subdomains` extends that requirement to every covered name.
Sending `max-age` of 0 does not remove the policy unless some endpoint
the UA will accept can still meet {{pq-checks}} and deliver that value
({{server}}). If the attacker was the only such endpoint and then stops
meeting the checks, the origin stays unreachable until the policy
expires.

# Privacy Considerations

<cref>TODO Privacy Considerations (sticky state parallel to HSTS; private
browsing alignment; subdomain bitvectors;
residual `max-age` TTL entropy without overselling oracles).</cref>


# IANA Considerations

IANA is requested to register the following entry in the "Hypertext
Transfer Protocol (HTTP) Field Name Registry" defined in
{{Section 16.3.1 of !RFC9110}}. The registration is:

Field name:
: `Require-PQ-Auth`

Status:
: permanent

Structured Type:
: Dictionary

Specification document(s):
: this document; see {{syntax}}

Comments:
: Defined for the header section of HTTP responses. Not defined for
  use as a trailer field. The field value is a Structured Fields
  Dictionary {{!RFC9651}}.


--- back

# Document History

RFC Editor: please remove before publication.

## draft-sheffer-tls-pq-hsts-00

Initial version.

# Acknowledgments
{:numbered="false"}

{{?I-D.sheffer-tls-pqc-continuity}} defines a similar opt-in mechanism, but at
the TLS layer, instead of the HTTP layer. This document adapts those ideas for
the HTTP layer.
