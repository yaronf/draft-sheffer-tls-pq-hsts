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

The following Dictionary members are defined. Unknown members MUST be ignored.

max-age:
: Integer (required). Non-negative number of seconds after receipt
  during which the UA regards the host as a Known PQ Host with this
  policy. A value of 0 signals the UA to delete any Noted PQ Policy for
  the host (including subdomain scope learned from this host).

include-subdomains:
: Boolean true if present as a bare Dictionary member (optional). If
  present, the PQ Policy applies to the host and to hosts whose domain
  names are subdomains of that host's domain name, analogous to HSTS
  `includeSubDomains` {{?RFC6797}}.
  Absence means host-only scope.

If the Dictionary does not include a valid `max-age` member, or if any
member is malformed, the UA MUST ignore the entire field. (See
{{Section 2.2 of !RFC9651}}.)

Examples:

~~~
Require-PQ-Auth: max-age=86400
Require-PQ-Auth: max-age=31536000, include-subdomains
~~~

# Server Processing {#server}

If the server sends a `Require-PQ-Auth` header, all servers that are
authoritative for the origin MUST, for at least the period denoted by `max-age`,
serve a certification path issued by a quantum-resistant trust anchor in
response to TLS connections from post-quantum-capable UAs. If the
`include-subdomains` member is true, all servers authoritative for any subdomain
of the origin MUST also meet this requirement.

A typical server deployment will need a combination of classical and
post-quantum certification paths for all its supported UAs, including legacy
ones that do not support quantum-resistant trust anchors. This header does not
constrain connections from legacy UA. Servers MAY continue to serve classical
certification paths in those cases.

How legacy and post-quantum-capable UAs are determined is out of scope for this
document. {{Section 4.5.1.2 of !RFC9846}} describes the general framework for
TLS certificate selection, but the exact criteria can be application-dependent,
depending on the ClientHello fields sent by each UA, the trust anchors each UA
trusts, etc.

The server MUST send `Require-PQ-Auth` only over HTTPS. If sent, it SHOULD
include the header on every HTTPS response.

## Choosing Policy Parameters

`max-age` SHOULD reflect how long the operator is willing to keep the
commitment above. Operators typically start with a short `max-age` while
gaining confidence, then increase it.

`include-subdomains` MUST NOT be sent unless every host that would be
covered can likewise satisfy the commitment for the same window.

## Updating and Clearing Policy

A valid `Require-PQ-Auth` field replaces any previously Noted PQ Policy
for that host when the UA notes it ({{ua-behavior}}). Omitting the header
does not clear Noted policy.

To delete client state before expiry, the server sends `max-age` with
value 0. UAs that successfully note that response MUST delete the Noted
PQ Policy ({{ua-behavior}}). However, this mechanism is limited. UAs with
the previous Noted policy will continue to enforce the policy until it is
cleared. A server that is no longer able to meet the commitment might be
unable to serve such UAs until the outstanding policies expire.

# User Agent Behavior {#ua-behavior}

This section defines how UAs note and enforce `Require-PQ-Auth` policy.

## Noting the Header {#noting}

Upon receipt of a valid `Require-PQ-Auth` header field in an HTTP response, the
UA notes a PQ Policy when all of the following hold, and MUST NOT note
one otherwise:

1. The response was received over an error-free HTTPS connection that
   uses TLS 1.3 {{!RFC9846}} or later.
2. That connection is authenticated with a certification path that is issued by
   a quantum-resistant trust anchor {{pq-checks}}.

When noting, the UA MUST:

1. Store a PQ Policy for the host as a Known PQ Host, with expiry derived
   from `max-age` (or delete the policy if `max-age` is 0).
2. Store the value of the `include-subdomains` member.

If a subsequent valid `Require-PQ-Auth` field is noted for the host, it
replaces the prior PQ Policy (including the `include-subdomains` member) for
that host. Absence of the header field on a later response does not by itself
clear PQ Policy before expiry; servers clear state with `max-age` of 0.

Although this mechanism is similar to HSTS {{?RFC6797}}, Known PQ Hosts are
separate from Known HSTS Hosts, with separate values for `max-age` and
`include-subdomains`.

UAs MAY additionally configure other hosts as Known PQ Hosts via local policy.
For example, the UA MAY be pre-configured with a list of pre-loaded Known PQ
Hosts, similar to {{Section 12.3 of ?RFC6797}}.

## Quantum-Resistant Trust Anchors {#pq-checks}

A UA, when connecting to a Known PQ Host or determining whether to note a new
Known PQ Host, checks if the certification path is issued by a quantum-resistant
trust anchor.

The choice of trust anchors is application-dependent and ultimately out of scope
for this document. The UA is presumed to maintain a legacy set of classical
trust anchors, as well as some new set of quantum-resistant trust anchors.

X.509 is extensible, so this document does not enumerate the full list of
quantum-resistant constructions and instead leaves the exact classification to
local policy. Quantum-resistant trust anchors MUST authenticate certification
paths using algorithms that are believed to be quantum-resistant.

## Enforcement {#enforcement}

When a UA establishes a connection to a host, it checks if either:

* the host is a Known PQ Host
* some superdomain of this host is a Known PQ Host with `include-subdomains`

If either of this conditions hold, the connection MUST use TLS 1.3 {{!RFC9846}}
or later, and the connection MUST be authenticated by a certification path
from a quantum-resistant trust anchor, as described in {{pq-checks}}.

If the connection does not meet those requirements, the UA MUST abort the
TLS handshake with a fatal "handshake_failure" alert ({{!RFC9846}},
Section 6.2).

Once the UA has removed classical trust anchors, `Require-PQ-Auth` is redundant.
Such UAs MAY remove support for this mechanism and stop tracking Known PQ Hosts.
Once all supported UAs are at this stage, servers MAY stop sending this header.


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
an origin, as described in {{privacy}}. When state is limited, there are more
"initial" responses for an attacker to intercept.

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


# Privacy Considerations {#privacy}

The mechanism described in {{noting}} causes a UA to maintain state based on
user activity in the UA. This state could be used to correlate user activity
across contexts, such as across sites or between normal and private browsing
profiles. {{ProtectingAgainstHSTSAbuse}} and {{StrictNavigationalSecurity}}
discuss analogous issues for HSTS.

UAs SHOULD mitigate this by clearing Known PQ Hosts when the user clears other
site-specific state, and by partitioning Known PQ Host state across sensitive
contexts, such as across sites or across browsing profiles. Note that these
mitigations will limit the effectiveness of this mechanism, as discussed in
{{limitations}}.

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
