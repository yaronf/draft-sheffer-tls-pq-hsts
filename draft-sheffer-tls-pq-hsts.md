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

normative:
  IANA.TLS-Parameters: IANA.tls-parameters

informative:
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

This document defines an HTTP response header field, `Require-PQ-Auth`,
modeled on HTTP Strict Transport Security (HSTS) {{?RFC6797}} but
carried separately with its own sticky client state as a Structured
Fields Dictionary {{!RFC9651}}. When a user agent has noted that policy
for a host, it MUST authenticate using a quantum-resistant trust anchor and
MUST negotiate quantum-resistant key agreement. The header
is a near-term, origin-opt-in lever for dual-trust-store PKI migration
and is intended to become unnecessary once classical trust anchors are
retired.


--- middle

# Introduction

Migrating TLS authentication to post-quantum cryptography cannot be done
by flipping a single switch. For a long period, relying parties will keep
classical trust anchors in their trust stores alongside
quantum-resistant ones, and
many origins will still present only
classical credentials. Under active attack, what matters is not whether
a server can present a post-quantum credential, but whether the client
accepts a classical path. An attacker able to forge certificates that
chain to a classical CA can strip a post-quantum credential and present
only a classical one. A client that still accepts classical paths will
treat that forged credential as valid, as if the origin had never
upgraded.

Key agreement is on a different track. Hybrid and pure post-quantum key
agreement are already being deployed independently of authentication
migration. That work does not by itself prevent classical trust-anchor
downgrade; rather, it mitigates the more pressing "harvest now, decrypt
later" threat model. Once an origin has asserted a post-quantum posture
via the mechanism in this document, however, allowing a later
classical-only key agreement would re-open a confidentiality downgrade
for that host. Therefore, when `Require-PQ-Auth` is enforced, this
document also requires quantum-resistant key agreement for that host.

This document defines an HTTP response header field, `Require-PQ-Auth`,
with HSTS-like semantics but carried separately from
`Strict-Transport-Security`, with its own sticky UA state. That
structure follows HTTP Public Key Pinning {{?RFC7469}}. An industry
outline of the same migration, including an HSTS-like opt-in stage,
appears in {{ChromiumPQAuthRoadmap}}.

Noting `Require-PQ-Auth` requires a securely delivered HTTPS response. It
does not require the host to be a Known HSTS Host {{?RFC6797}}. HSTS and
`Require-PQ-Auth` lifecycles are independent. UAs that do not implement
this document ignore the unknown header field.

The normative contribution of this document is the near-term opt-in
`Require-PQ-Auth` pin and the associated user-agent behavior. Where this
document uses "PQ" in the title and abbreviation (PQ-HSTS), the
normative requirement is quantum-resistant trust-anchor authentication and
quantum-resistant key agreement as defined below—not a single algorithm.
The informal name reflects HSTS-like behavior, not an extension of the
`Strict-Transport-Security` header field.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used in this document:

classical:
: Cryptography or credentials that are not designed to remain secure
  against a cryptographically-relevant quantum computer (CQRC), such as RSA
  or elliptic-curve public-key algorithms. A classical trust anchor is a trust
  anchor that authenticates only classical paths.

quantum-resistant (signatures / trust anchors):
: Not classical-only. For authentication material, this document treats
  pure post-quantum algorithms and composite algorithms
  {{?I-D.ietf-lamps-pq-composite-sigs}} as one class, consistent with the
  PQC end-entity classification in
  {{?I-D.sheffer-tls-pqc-continuity}}. Which algorithms a UA accepts as
  quantum-resistant is a matter of local policy and the relevant algorithm
  specifications;
  this document states the property, not a closed algorithm list.

<cref>TODO: add a more precise definition of quantum-resistance for MTC.</cref>

quantum-resistant (key agreement):
: Not classical-only. Hybrid key agreement (classical combined with a
  post-quantum KEM) and pure post-quantum key agreement both satisfy
  this document. Exact NamedGroup / codepoint acceptance is left to UA
  policy and the TLS Supported Groups registry
  {{IANA.TLS-Parameters}}.

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
covered by `include-subdomains`):

1. Serve a certification path anchored at a quantum-resistant trust anchor
   (pure post-quantum or composite per the server's deployment), with no
   mixed classical/quantum-resistant path; and
2. Complete quantum-resistant key agreement (hybrid or pure post-quantum)
   with clients that implement this document.

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
3. The negotiated key agreement is quantum-resistant (hybrid or pure
   post-quantum per local policy).

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

This document does not impose separate end-entity signature-algorithm
requirements beyond the trust-anchor class and path-consistency rules
above. It does not enumerate TLS NamedGroup codepoints or MTC validation
procedures; those remain matters for TLS/IANA policy and
{{?I-D.ietf-plants-merkle-tree-certs}}, respectively.

Once classical trust anchors are no longer accepted for authentication,
`Require-PQ-Auth` is redundant. UAs MAY clear PQ Policy for Known PQ Hosts when
local policy determines that the pin is obsolete.
Servers SHOULD stop sending the header in that environment. HSTS policy,
if any, is unaffected.


# Operational Considerations {#ops}

<cref>TODO Operational considerations: CDN / multi-CDN consistency;
staged `max-age` independent of HSTS; independent HSTS
`includeSubDomains` vs PQ `include-subdomains`; HTTPS required to note,
HSTS not required; enterprise TLS interception; public Web ≈ MTC vs
enterprise ≈ X.509 PQ chains; MTC evolving; SFV serialization (lowercase
keys, commas); do not assert the pin before hybrid/PQ KE is solid for the
served audience.</cref>


# Security Considerations

The security considerations of HSTS ({{Section 14 of ?RFC6797}}) apply
to `Require-PQ-Auth`. This section covers where they differ.

## Underlying Secure Transport Considerations

Quantum-resistant key exchange and authentication are specified for TLS
1.3 {{!RFC9846}} and not for earlier versions. `Require-PQ-Auth` can
therefore be used only with TLS 1.3 or later.

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
such as a pre-configured list. Which such measures can mitigate this attack,
they can introduce other limitations when the number of otherwise
quantum-resistant hosts exceeds an implementation's size limits.

Non-browser clients may be further limited in their ability to both maintain
state and include large, pre-configured lists.

These limitations mean `Require-PQ-Auth` is only viable as a temporary measure
for a limited number of applications. In many applications, it will still be
necessary to trust anchors in the near term. {{ChromiumPQAuthRoadmap}}
describes one such transition plan.

## Denial of Service

An attacker that controls a TLS-terminating proxy can cause a UA to note
`Require-PQ-Auth` only when the connection meets {{pq-checks}}. A proxy
that cannot meet those checks cannot set the policy.

If the attacker can meet the checks and sets a large `max-age`, UAs that
note the policy require {{pq-checks}} until the policy expires.
`include-subdomains` extends that requirement to every covered name.
Sending `max-age` of 0 does not remove the policy unless some endpoint
the UA will accept can still meet {{pq-checks}} and deliver that value
({{server}}). If the attacker was the only such endpoint and then stops
meeting the checks, the origin stays unreachable until the policy
expires.

After a policy is legitimately Noted, a TLS interceptor that cannot meet
{{pq-checks}} causes the same hard failure. That is an availability
problem for deployments that intercept TLS, separate from injection.


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
