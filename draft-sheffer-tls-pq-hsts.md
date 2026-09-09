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
  RescorlaPQEmergency:
    title: "PQ emergency"
    target: https://educatedguesswork.org/posts/pq-emergency/
    author:
      ins: E. Rescorla
      name: Eric Rescorla
    date: 2024-04
  CABForumSC081v3:
    title: "Ballot SC081v3: Introduce Schedule of Reducing Validity and Data Reuse Periods"
    target: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
    author:
      org: CA/Browser Forum
    date: 2025-04
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

...

--- abstract

This document defines an HTTP response header field, `Require-PQ-Auth`,
modeled on HTTP Strict Transport Security (HSTS) {{?RFC6797}} but
carried separately with its own sticky client state as a Structured
Fields Dictionary {{!RFC9651}}. When a user agent has noted that policy
for a host, it MUST authenticate using a cryptographically relevant
quantum computer (CRQC)-resistant trust anchor and MUST negotiate
CRQC-resistant (pure post-quantum or hybrid) key agreement. The header
is a near-term, origin-opt-in lever for dual-trust-store PKI migration
and is intended to become unnecessary once classical trust anchors are
retired.


--- middle

# Introduction

Migrating TLS authentication to post-quantum cryptography cannot be done
by flipping a single switch. For a long period, relying parties will keep
classical trust anchors in their trust stores alongside
CRQC-resistant ones, and
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
document also requires CRQC-resistant key agreement for that host.

This document defines an HTTP response header field, `Require-PQ-Auth`,
with HSTS-like semantics but carried separately from
`Strict-Transport-Security`, with its own sticky UA state. That
structure follows HTTP Public Key Pinning {{?RFC7469}}. An industry
outline of the same migration, including an HSTS-like opt-in stage,
appears in {{ChromiumPQAuthRoadmap}}.

HTTPS and PQ readiness often diverge on `max-age`, subdomain scope, and
preload, so those knobs cannot usefully share one HSTS policy.

Noting `Require-PQ-Auth` requires a securely delivered HTTPS response. It
does not require the host to be a Known HSTS Host {{!RFC6797}}. HSTS and
`Require-PQ-Auth` lifecycles are independent. UAs that do not implement
this document ignore the unknown header field.

The normative contribution of this document is the near-term opt-in
`Require-PQ-Auth` pin and the associated user-agent behavior. Where this
document uses "PQ" in the title and abbreviation (PQ-HSTS), the
normative requirement is CRQC-resistant trust-anchor authentication and
CRQC-resistant key agreement as defined below—not a single algorithm.
The informal name reflects HSTS-like behavior, not an extension of the
`Strict-Transport-Security` header field.

## PQ-HSTS in the Broader Migration Context

This mechanism addresses a specific, comparatively well-understood threat:
classical trust-anchor downgrade during the dual-trust-store period, and
classical-only key-agreement downgrade once a host has asserted a
post-quantum posture.

The harder problem is coordinating a three-sided ecosystem of clients,
servers, and certificate authorities (or other trust-anchor operators)
from today's set of acceptable authentication algorithms to a
CRQC-resistant set on a compressed timeline
{{RescorlaPQEmergency}}.
<cref>TODO: add references to government/industry post-quantum migration
directives.</cref>

This document defines one near-term, origin-opt-in lever within an
incremental migration program. Other parts of that program are still
being designed. {{migration}} states the problem and sketches a proposed
plan, including why voluntary opt-in alone is too slow for industry
timelines and how later mechanisms (such as a PQ-secure signal embedded
in classical certificates, specified elsewhere) can unlock a strict client policy for acceptable authentication algorithms afterward.

## Relation to Other Work {#other-work}

{{?I-D.sheffer-tls-pqc-continuity}} defines a TLS-layer commitment that a
server will present a PQC or composite end-entity certificate for a period
of time. This document instead defines an HTTP sticky policy that pins
CRQC-resistant trust anchors (and key agreement when the pin is enforced).
The two approaches address related downgrade problems at different layers.

Physically large post-quantum certificates motivate new certificate
distribution mechanisms. This document is intended to work with that
evolution, including Merkle Tree Certificates (MTC)
{{?I-D.ietf-plants-merkle-tree-certs}} for the public Web PKI, without
depending on a single encoding.

- Public Web PKI is assumed to move toward MTC. MTC remains evolving;
  normative text in this document stays abstract about trust-anchor
  encoding. The migration stages in {{migration}} are written primarily
  for this ecosystem.
- Enterprise PKI may use X.509 post-quantum certificate chains (pure PQ
  and/or composite under CRQC-resistant trust anchors) rather than MTC.
  Enterprises set their own migration timelines; this document neither
  drives nor constrains them. The `Require-PQ-Auth` mechanism remains
  available where an enterprise origin and its clients choose to use it.

Both forms of CRQC-resistant trust anchor can satisfy `Require-PQ-Auth`.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used in this document:

classical:
: Cryptography or credentials that are not designed to remain secure
  against a CRQC (for example, RSA or elliptic-curve public-key algorithms
  in wide use on the Web today). A classical trust anchor is a trust
  anchor that authenticates only classical paths.

CRQC-resistant (signatures / trust anchors):
: Not classical-only. For authentication material, this document treats
  pure post-quantum algorithms and composite algorithms
  {{?I-D.ietf-lamps-pq-composite-sigs}} as one class, consistent with the
  PQC end-entity classification in
  {{?I-D.sheffer-tls-pqc-continuity}}. Which algorithms a UA accepts as
  CRQC-resistant is a matter of local policy and the relevant algorithm
  specifications;
  this document states the property, not a closed algorithm list.

<cref>TODO: add a more precise definition of CRQC-resistance for MTC.</cref>

CRQC-resistant (key agreement):
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
  CRQC-resistant), not to a single encoding.

HSTS terms:
: This document refers to Known HSTS Host, HSTS Policy, and related
  terminology from {{!RFC6797}} only for comparison. HSTS state is
  independent of the policy defined here.

Known PQ Host / PQ Policy:
: A host for which the UA has noted a valid `Require-PQ-Auth` policy
  ({{syntax}}, {{ua-behavior}}), including expiry derived from `max-age`
  and whether `include-subdomains` applies. Storage is parallel to—not
  part of—HSTS Policy storage.


# Threat Model

This document addresses the following threats during the dual-trust-store
migration period:

- Classical trust-anchor MitM: An active attacker forges a classical
  certificate (or otherwise obtains acceptance under a classical trust
  anchor) for a name whose operator intends to use only CRQC-resistant
  authentication, and presents that credential to a dual-accepting UA.
- Classical-only key-agreement downgrade after pin: Once a host has
  asserted post-quantum posture via `Require-PQ-Auth`, an attacker that
  can force classical-only key agreement would undermine confidentiality
  for subsequent visits even if authentication remains CRQC-resistant.

Trust-on-first-use (TOFU) limits apply as for HSTS: the first successful
HTTPS visit that delivers the policy is not itself protected by the pin.
Preload closes that gap for configured names, as it does for HSTS today.
It is especially important for origins that are often visited in private
browsing (incognito) modes, where UAs typically do not retain durable
sticky policy state—preload is then the only way to obtain the pin's
protection. Preload semantics are outlined in {{preload}}.

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
  `includeSubDomains` {{!RFC6797}} but applying only to this PQ Policy.
  Absence means host-only scope.

preload:
: Boolean true if present as a bare Dictionary member (optional). Presence
  does not change how the UA enforces a Noted PQ Policy. It only indicates
  that the operator wants this host considered for inclusion on a PQ
  preload list (the same role the HSTS `preload` token plays for HSTS
  preload submission; see <https://hstspreload.org/>). Whether and how
  such a list is operated is out of scope (see {{preload}}).

If the Dictionary does not include a usable `max-age`, or if any present
member is malformed for its type, the UA MUST NOT update Noted PQ Policy
from this field.

Examples:

~~~
Require-PQ-Auth: max-age=86400
~~~

~~~
Require-PQ-Auth: max-age=31536000, include-subdomains
~~~

~~~
Require-PQ-Auth: max-age=31536000, include-subdomains, preload
~~~

# Server Processing {#server}

<cref>TODO Server processing: emit `Require-PQ-Auth` only when the origin
can serve a CRQC-resistant-TA credential and complete PQ/hybrid key
agreement for the commitment window; emit `include-subdomains` only when
the entire covered subdomain tree is similarly ready; choose `max-age`
independently of HSTS; serialize as an RFC 9651 Dictionary; staged
ramp; noting requires HTTPS but not HSTS; clear Noted policy with
`max-age` of 0 (omitting the header does not clear).</cref>

# User Agent Behavior {#ua-behavior}

This section defines how UAs note and enforce `Require-PQ-Auth` policy.

## Noting the header

Upon receipt of a `Require-PQ-Auth` header field in an HTTP response, the
UA MUST NOT note a PQ Policy unless all of the following hold:

1. The response was received over an error-free TLS connection
   (HTTPS).
2. The field value parses as a Structured Fields Dictionary per
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

UAs that do not implement this document ignore the unknown header field.

## Enforcement

When establishing a connection to a host covered by an unexpired Noted PQ
Policy—either because the host itself is a Known PQ Host, or because an
ancestor Known PQ Host has `include-subdomains` covering this host—the UA
MUST:

1. Authenticate the server such that the trust anchor that caused
   acceptance is CRQC-resistant (pure post-quantum or composite per local
   policy), whether that trust anchor is an X.509 trust anchor or an MTC
   trust base / cosigner.
2. Ensure the accepted certification path is not mixed: every hop is
   classical, or every hop is CRQC-resistant, consistent with local
   policy. (Detailed mixed-path rejection may be refined here or by
   reference to a dedicated path-validation document.)
3. Negotiate a CRQC-resistant key agreement (hybrid or pure
   post-quantum per local policy). Classical-only key agreement MUST cause
   failure of the connection attempt.

If any of the above checks fail, the UA MUST fail the connection in a
manner consistent with HSTS hard failure (no click-through bypass)
({{Section 8.4 of !RFC6797}}).

This document does not impose separate end-entity signature-algorithm
requirements beyond the trust-anchor class and path-consistency rules
above. It does not enumerate TLS NamedGroup codepoints or MTC validation
procedures; those remain matters for TLS/IANA policy and
{{?I-D.ietf-plants-merkle-tree-certs}}, respectively.

Once classical trust anchors are no longer accepted for authentication
(Stage 5 of {{migration}}), `Require-PQ-Auth` is redundant (Stage 6). UAs
MAY clear PQ Policy for Known PQ Hosts (including any preloaded
equivalent) when local policy determines that the pin is obsolete.
Servers SHOULD stop sending the header in that environment. HSTS policy,
if any, is unaffected.


# Preload {#preload}

<cref>TODO Preload: semantics only—configured/preloaded names may be
treated as already Noted Known PQ Hosts (with optional
`include-subdomains`) before first visit, closing the TOFU gap as for
HSTS today; the `preload` Dictionary member signals submission intent for
a PQ preload list and is independent of HSTS `preload`; informative
submission expectations (evidence of `Require-PQ-Auth`,
CRQC-resistant-TA serving, PQ/hybrid KE). Do not prescribe one shared
list vs a parallel list (implementation/operations detail). Stage 6: UAs
MAY drop preloaded PQ enforcement when the pin is obsolete.</cref>


# Operational Considerations {#ops}

<cref>TODO Operational considerations: CDN / multi-CDN consistency;
staged `max-age` independent of HSTS; independent HSTS
`includeSubDomains` vs PQ `include-subdomains`; HTTPS required to note,
HSTS not required; enterprise TLS interception; public Web ≈ MTC vs
enterprise ≈ X.509 PQ chains; MTC evolving; SFV serialization (lowercase
keys, commas); do not assert the pin before hybrid/PQ KE is solid for the
served audience.</cref>


# Security Considerations

<cref>TODO Security Considerations (orthogonal HSTS vs PQ state;
trust-anchor and key-agreement downgrade; unknown-header UAs; enterprise
interception; cookie scoping / `__Host-` and related Stage 2 risks from
{{ChromiumPQAuthRoadmap}}; MTC evolving).</cref>


# Privacy Considerations

<cref>TODO Privacy Considerations (sticky state parallel to HSTS; private
browsing alignment; preload privacy profile; subdomain bitvectors;
residual `max-age` TTL entropy without overselling oracles).</cref>


# IANA Considerations

<cref>TODO IANA Considerations: register HTTP field name
`Require-PQ-Auth` as a Structured Header (Dictionary) per {{!RFC9651}}.</cref>


--- back

# The Migration to PQ-Secure Authentication in TLS {#migration}

This appendix is informative. It situates the `Require-PQ-Auth` header
in the long-term public Web authentication migration (with notes on
enterprise use). The normative behavior defined by this document is the
near-term HSTS-like mechanism in {{ua-behavior}} and {{syntax}}. An
industry roadmap for the same migration, including the role of an
HSTS-like opt-in and later PKI-only stages, is described in
{{ChromiumPQAuthRoadmap}}.

<cref>TODO Appendix material still missing relative to the drafting plan:
brief comparison with {{?I-D.sheffer-tls-pqc-continuity}} beyond
{{other-work}} if needed; pointer to mixed-path prohibition /
separate path-validation draft if that work is split out of this
document.</cref>

## Problem Framing

Some motivations for this work are widely shared in industry; others are
more subtle. The subsections below state the assumptions used in this
appendix so that the migration discussion is explicit and easier to
debate.

### Acceptable authentication algorithms versus credentials in use

Under active attack, security is determined by the client's set of
acceptable authentication algorithms, not by whether a post-quantum
credential is merely available at the origin.
Deploying a post-quantum certificate while classical trust anchors remain
accepted does not make the origin post-quantum secure. An attacker who can
forge a certificate under a classical CA can strip the post-quantum
credential and present a classical one; the client will accept it as if the
origin had never upgraded.

### Adoption S-curves and break budget

General-purpose clients must wait on essentially the whole server
population before removing classical trust anchors from the client's
set of acceptable authentication algorithms. Combined with a very small
fraction of breakage that operators will
tolerate, that implies timelines measured in years or even
decades if nothing accelerates the program. Specialized clients that talk
to a small, controlled server set have a much tighter curve.

### Key agreement proceeds in parallel

Post-quantum key agreement (usually hybrid with a classical algorithm)
continues to roll out independently.
It does not fix classical trust-anchor authentication downgrade. Under
`Require-PQ-Auth`, this document requires CRQC-resistant key
agreement for pinned hosts so that the origin's asserted posture covers
confidentiality as well as authentication.

### Public Web versus enterprise PKI

Long-term credential forms differ by deployment:

- Public Web PKI is expected to move toward MTC
  {{?I-D.ietf-plants-merkle-tree-certs}}.
- Enterprise PKI is expected to include X.509 post-quantum certificate
  chains (pure PQ and/or composite) under CRQC-resistant trust anchors.

The PQ policy header is stated using a "trust anchor" abstraction so both
can use `Require-PQ-Auth`. The chronological stages below focus on the
public Web PKI, where industry-wide coordination is the hard problem.
Enterprise operators migrate on their own schedules; this document does
not attempt to set or enforce those schedules.

### Dual complete paths, not mixed chains

A path anchored at a CRQC-resistant trust anchor carries post-quantum
(or composite) signatures. Classical-only clients cannot verify those
signatures, so a mixed construction such as "PQ CA + classical
end-entity" does not provide legacy interoperability. Origins that need
both audiences provision two complete paths—an all-classical path and an
all-CRQC-resistant path—and select between them per connection (for
example using what the client advertises in `signature_algorithms`).

Selecting among individual trust anchors
{{?I-D.ietf-tls-trust-anchor-ids}} is a separate problem and is out of
scope here.

Certificate authorities are expected not to mint mixed
classical/CRQC-resistant paths. Clients are expected to reject mixed
paths.
<cref>TODO: is a separate draft needed to forbid CAs from issuing mixed
chains, or should client rejection alone suffice?</cref>

### Why an HSTS-like header is only a near-term lever

An HSTS-like pin is attractive: non-participating origins are not broken,
and each participating client and server gains clear security value. It is
also inherently limited. Sticky UA state, TOFU, incomplete preload list
coverage of the Web, painful rollback, and private-browsing modes that do
not retain durable sticky policy state all constrain reach. Performance costs (CPU
and network bandwidth for CRQC-resistant credentials and key agreement)
may further discourage adoption by individual servers. True legacy
single-certificate origins never opt in. Voluntary adoption can keep
growing, but too slowly to meet industry post-quantum timelines. A more
aggressive program is needed for the remainder of the Web.

### PQ-secure signal embedded in classical certificates

A modern client that prefers post-quantum authentication cannot tell, when
an unknown origin presents only a classical credential, whether the origin
has no post-quantum path or an attacker stripped it. Sticky
`Require-PQ-Auth` helps only after opt-in or preload.

A proposed long-term answer is a credential that classical clients can
still verify as usual, while carrying an embedded PQ-secure indication
that no post-quantum certificate is available for this end entity—that
is, that classical authentication is required for this origin. Modern
clients that verify that signal may accept classical credentials only
when so assured; otherwise they insist on CRQC-resistant authentication.
The wire encoding of that signal is not specified in this document.

That construction unlocks the ecosystem as follows:

- Implementation effort is concentrated on certificate authorities (a
  small number of issuers) and on clients (a small number of major
  implementations, especially browsers). Because publicly trusted
  certificates have bounded lifetimes {{CABForumSC081v3}}, once all newly
  issued classical certificates carry the signal, remaining certificates
  without it age out on a predictable schedule. After that point, the
  only non-CRQC-resistant servers that remain are those that still
  present a single classical certificate.
- Strict client policy: accept classical authentication only with PQ
  assurance that classical is required for this origin; otherwise require
  CRQC-resistant authentication.
- Single-certificate servers: upgrade to multi-certificate / dual-path
  operation, or — when the legacy-client population is small enough — stop
  relying on classical-only issuance, which forces those origins to
  upgrade or lose modern-client connectivity.

`Require-PQ-Auth` remains the near-term, easy-to-deploy opt-in lever for
origins that already have a CRQC-resistant path. The PQ-secure signal in
classical certificates is how the long tail can be brought along without
weakening the security of origins that have already upgraded.

## Chronological Stages

Each stage summarizes expected CA (or trust-anchor operator), server, and
client behavior in the public Web PKI. The sequence is idealized:
large-scale adoption will be more uneven, with different parts of the
ecosystem moving at different rates. Enterprise deployments are out of
scope for this staged narrative; they may reuse `Require-PQ-Auth` but on
locally chosen timelines.

### Stage 0 — Today

| Role | State |
|---|---|
| CA | Classical issuance only (Web PKI). |
| Server | Classical certificates; HSTS common; no `Require-PQ-Auth`. Hybrid/PQ key agreement rolling out independently. |
| Client | Accepts classical authentication. Hybrid/PQ key agreement rolling out independently. |

### Stage 1 — Early PQ issuance, dual accept

| Role | State |
|---|---|
| CA | Some CAs begin minting CRQC-resistant credentials (public Web toward MTC); classical issuance continues. |
| Server | New servers can obtain CRQC-resistant credentials, support `Require-PQ-Auth`, and may dual-home all-classical and all-CRQC-resistant paths selected by trust-anchor type. Old servers remain classical-only and do not send `Require-PQ-Auth`. |
| Client | Most clients accept both classical and CRQC-resistant authentication. Dual accept means "PQ in use" is not yet PQ-secure against active attackers. Clients indicate PQ preference or capability via TLS `signature_algorithms` (and related mechanisms). Capable servers may begin asserting `Require-PQ-Auth`. |

This stage is gated on industry adoption of PQ-ready credential
infrastructure, expected for the public Web to center on MTC.

### Stage 2 — Opt-in pin spreads (this document)

| Role | State |
|---|---|
| CA | Growing CRQC-resistant issuance; classical credentials still widely available. |
| Server | More origins send `Require-PQ-Auth` once they reliably serve an all-CRQC-resistant path and complete PQ/hybrid key agreement; they may still dual-home for legacy clients. Old servers still never opt in. |
| Client | Still dual-accept by default; for Known PQ Hosts (including names learned via preload), reject classical trust anchors and classical-only key agreement. As with HSTS, preload is part of the deployment story—and for origins often used in private browsing, it is typically the only way to get the pin's protection. Coverage grows, but adoption remains too slow for industry post-quantum timelines. |

### Stage 3 — Accelerate PQ issuance and PQ-secure signal in classical certificates

| Role | State |
|---|---|
| CA | Broader CRQC-resistant issuance (no mixed chains). Begin issuing classical certificates with an embedded PQ-secure signal ("classical required for this end entity") instead of plain classical—encoding specified elsewhere. |
| Server | Dual-homed new servers: all-classical and/or all-CRQC-resistant by trust-anchor type. Single-certificate legacy servers can adopt classical certificates that carry the PQ-secure signal without multi-certificate support. |
| Client | Still largely dual-accept, but a path opens to strict policy once the PQ-secure signal is widely verifiable. Reject mixed paths. For pinned names: CRQC-resistant trust-anchor path and CRQC-resistant key agreement. |

### Stage 4 — Strict clients and CA shift

| Role | State |
|---|---|
| CA | Stop plain classical issuance; classical-with-PQ-signal and/or all-CRQC-resistant products serve both old and new clients. |
| Server | Single-certificate origins stay on classical-with-PQ-signal, upgrade to dual-path, or—as legacy clients shrink—switch to CRQC-resistant only. Dual-homed origins prefer CRQC-resistant paths to modern clients. |
| Client | Deploy strict policy: classical only with PQ assurance that classical is required for this origin; otherwise CRQC-resistant only. Opt-in `Require-PQ-Auth` still helps early PQ origins; the PQ-secure signal covers the long tail. |

### Stage 5 — Remove classical trust anchors

| Role | State |
|---|---|
| CA | Classical Web PKI trust anchors are removed from relying-party trust stores. Plain classical issuance is gone. |
| Server | Serve CRQC-resistant credentials. Residual classical-with-PQ-signal credentials may linger only while last classical-only verifiers remain (deployment-dependent). |
| Client | Successful authentication uses CRQC-resistant trust anchors. Classical credentials without PQ assurance are rejected. |

### Stage 6 — Retire `Require-PQ-Auth`

| Role | State |
|---|---|
| CA | CRQC-resistant-only trust for the Web PKI. |
| Server | Stop sending `Require-PQ-Auth`; HSTS may remain. |
| Client | Clear `Require-PQ-Auth` state (including preload) and eventually remove enforcement; the pin is redundant. The mechanism succeeds by becoming unnecessary. |

# Acknowledgments
{:numbered="false"}

<cref>TODO acknowledge.</cref>

