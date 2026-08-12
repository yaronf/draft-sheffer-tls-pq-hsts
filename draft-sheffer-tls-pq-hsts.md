---
title: "An HSTS Extension for Secure PQ Migration"
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
  IANA.TLS-Parameters:
    title: "Transport Layer Security (TLS) Parameters"
    target: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
    author:
      org: IANA

...

--- abstract

This document extends HTTP Strict Transport Security (HSTS) {{!RFC6797}}
with a new `Strict-Transport-Security` directive, `require-pq-ta`. When a
user agent (UA) has noted that policy for a host, it MUST authenticate the
host using a post-quantum (PQ)
trust anchor and MUST negotiate a PQ (pure post-quantum or
hybrid) key agreement.

The directive is a near-term, origin-opt-in lever for the dual-trust-store
phase of Web and enterprise PKI migration. It is designed to become
unnecessary once classical trust anchors are retired. The document also
describes, informatively, the longer authentication migration program in
which this lever sits.


--- middle

# Introduction

Migrating TLS authentication to post-quantum cryptography cannot be done
by flipping a single switch. For a long period, relying parties will keep
classical trust anchors in their trust stores alongside
cryptographically relevant quantum computer (CRQC)-resistant ones, and
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
for that host. Therefore, when `require-pq-ta` is enforced, this document
also requires CRQC-resistant key agreement for that host.

This document extends HSTS {{!RFC6797}}: it adds a directive on the
existing `Strict-Transport-Security` header field and reuses the Known
HSTS Host storage model, `max-age`, `includeSubDomains`, and preload
lifecycle. It does not define a parallel header. Hosts that send the
directive must already satisfy HSTS's HTTPS requirements; UAs that do not
understand the new directive continue to apply ordinary HSTS.

The normative contribution of this document is the near-term opt-in
`require-pq-ta` pin and the associated user-agent behavior.

## PQ-HSTS in the Broader Migration Context

This mechanism addresses a specific, comparatively well-understood threat:
classical trust-anchor downgrade during the dual-trust-store period, and
classical-only key-agreement downgrade once a host has asserted a
post-quantum posture.

The harder problem is coordinating a three-sided ecosystem of clients,
servers, and certificate authorities (or other trust-anchor operators)
from today's accept set to a CRQC-resistant one on a compressed timeline.
<cref>TODO: add references to government post-quantum migration
directives.</cref>

This document defines one near-term, origin-opt-in lever within an
incremental migration program. Other parts of that program are still
being designed. {{migration}} states the problem and sketches a proposed
plan, including why voluntary opt-in alone is too slow for industry
timelines and how later mechanisms (such as a PQ-secure signal embedded
in classical certificates, specified elsewhere) can unlock a strict
client accept policy afterward.

## Relation to Other Work

{{?I-D.sheffer-tls-pqc-continuity}} defines a TLS-layer commitment that a
server will present a PQC or composite end-entity certificate for a period
of time. This document instead extends HSTS to pin CRQC-resistant trust
anchors (and key agreement when the pin is enforced). The two approaches
address related downgrade problems at different layers.

Physically large post-quantum certificates motivate new certificate
distribution mechanisms. This document is intended to work with that
evolution, including Merkle Tree Certificates (MTC)
{{?I-D.ietf-plants-merkle-tree-certs}} for the public Web PKI, without
depending on a single encoding.

- Public Web PKI is assumed to move toward MTC. MTC remains evolving;
  normative text in this document stays abstract about trust-anchor
  encoding.
- Enterprise PKI is assumed to include X.509 post-quantum certificate
  chains (pure PQ and/or composite under CRQC-resistant trust anchors),
  not MTC alone.

Both forms of CRQC-resistant trust anchor can satisfy `require-pq-ta`.


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
: This document uses Known HSTS Host, HSTS Policy, Note,
  `max-age`, `includeSubDomains`, and related terminology as in
  {{!RFC6797}}.

PQ policy bit / `require-pq-ta`:
: An additional boolean associated with a Known HSTS Host
  policy indicating that the `require-pq-ta` directive is in effect for
  that host until the policy expires or is superseded.


# Threat Model

This document addresses the following threats during the dual-trust-store
migration period:

- Classical trust-anchor MitM: An active attacker forges a classical
  certificate (or otherwise obtains acceptance under a classical trust
  anchor) for a name whose operator intends to use only CRQC-resistant
  authentication, and presents that credential to a dual-accepting UA.
- Classical-only key-agreement downgrade after pin: Once a host has
  asserted post-quantum posture via `require-pq-ta`, an attacker that can
  force classical-only key agreement would undermine confidentiality for
  subsequent visits even if authentication remains CRQC-resistant.

Trust-on-first-use (TOFU) limits apply as for HSTS: the first successful
HTTPS visit that delivers the policy is not itself protected by the pin.
Preload semantics (to be specified in a later revision of this document) close
that gap for configured names in the same way HSTS preload does today.

# User Agent Behavior {#ua-behavior}

This section specifies the UA processing rules associated with
`require-pq-ta`. Syntax for emitting the directive on
`Strict-Transport-Security`, server commitment rules, and preload
delivery are left to a subsequent revision of this document; the rules
below assume the directive has been conveyed as part of an HSTS Policy.

## Noting the directive

When a UA notes an HSTS Policy for a host per {{!RFC6797}} and that policy
includes `require-pq-ta`, the UA MUST record that the PQ policy bit is set
for the Known HSTS Host, with the same expiry and domain scope
(`includeSubDomains`) as the rest of that HSTS Policy.

If a subsequent valid HSTS Policy for the host omits `require-pq-ta`, the
UA MUST clear the PQ policy bit (while applying any updated `max-age` and
other HSTS directives as usual). UAs that do not implement this document
ignore the unknown directive and apply ordinary HSTS.

## Enforcement

When establishing a connection to a Known HSTS Host whose noted policy
includes `require-pq-ta`, the UA MUST:

1. Apply all UA requirements of {{!RFC6797}} unchanged (including HTTPS-only
   behavior and failure handling).
2. Authenticate the server such that the trust anchor that caused
   acceptance is CRQC-resistant (pure post-quantum or composite per local
   policy), whether that trust anchor is an X.509 trust anchor or an MTC
   trust base / cosigner.
3. Ensure the accepted certification path is not mixed: every hop is
   classical, or every hop is CRQC-resistant, consistent with local
   policy. (Detailed mixed-path rejection may be refined here or by
   reference to a dedicated path-validation document.)
4. Negotiate a CRQC-resistant key agreement (hybrid or pure
   post-quantum per local policy). Classical-only key agreement MUST cause
   failure of the connection attempt.

If any of the above checks fail, the UA MUST fail the connection in a
manner consistent with HSTS hard failure (no click-through bypass).

This document does not impose separate end-entity signature-algorithm
requirements beyond the trust-anchor class and path-consistency rules
above. It does not enumerate TLS NamedGroup codepoints or MTC validation
procedures; those remain matters for TLS/IANA policy and
{{?I-D.ietf-plants-merkle-tree-certs}}, respectively.

Absent `require-pq-ta`, behavior is ordinary HSTS, including whatever key
agreement the UA would negotiate for that connection.

Once classical trust anchors are no longer part of the relevant accept
set (Stage 6 of {{migration}}), `require-pq-ta` is redundant. UAs MAY
clear the PQ policy bit for Known HSTS Hosts (including any preloaded
equivalent) when local policy determines that the pin is obsolete.
Servers SHOULD stop sending the directive in that environment. Base HSTS
policy MAY remain.


# Security Considerations

<cref>TODO Security Considerations (HSTS inheritance; trust-anchor and
key-agreement downgrade; unknown-directive UAs; enterprise interception;
MTC evolving).</cref>


# Privacy Considerations

<cref>TODO Privacy Considerations (sticky state equivalent to HSTS; private
browsing alignment; preload privacy profile; no additional tracking
surface beyond the HSTS PQ policy bit).</cref>


# IANA Considerations

<cref>TODO IANA Considerations (`Strict-Transport-Security` directive
registration for `require-pq-ta`).</cref>


--- back

# The Migration Program {#migration}

This appendix is informative. It situates the `require-pq-ta` directive
in the long-term Web and enterprise authentication migration. The only
normative artifact defined by this document is the near-term HSTS
extension ({{ua-behavior}} and later sections).

## Problem Framing

### Accept-set versus credentials in use

Under active attack, security is determined by the client's accept set,
not by whether a post-quantum credential is merely available at the origin.
Deploying a post-quantum certificate while classical trust anchors remain
accepted does not make the origin post-quantum secure: the attacker forges
via a classical CA and the client treats the name as un-updated.

### Adoption S-curves and break budget

General-purpose clients must wait on essentially the whole server
population before removing classical trust anchors from the global accept
set. Combined with a very small fraction of breakage that operators will
tolerate, that implies timelines measured in years—often described as
decades if nothing accelerates the program. Specialized clients that talk
to a small, controlled server set have a much tighter curve.

### Key agreement proceeds in parallel

Hybrid and post-quantum key agreement continue to roll out independently.
They do not fix classical trust-anchor authentication downgrade. Under
`require-pq-ta`, this document nonetheless requires CRQC-resistant key
agreement for pinned hosts so that the origin's asserted posture covers
confidentiality as well as authentication.

### Public Web versus enterprise PKI

Long-term expectations differ by deployment:

- Public Web PKI is expected to move toward MTC
  {{?I-D.ietf-plants-merkle-tree-certs}}.
- Enterprise PKI is expected to include X.509 post-quantum certificate
  chains (pure PQ and/or composite) under CRQC-resistant trust anchors.

The HSTS directive is written against the abstract CRQC-resistant trust-
anchor property so both can comply.

### Dual complete paths, not mixed chains

A path anchored at a CRQC-resistant trust anchor carries post-quantum
(or composite) signatures. Classical-only clients cannot verify those
signatures, so a mixed construction such as "PQ CA + classical end-entity"
does not provide legacy interop. Origins that need both audiences provision
two complete paths—an all-classical path and an all-CRQC-resistant
path—and select between them by trust-anchor type (for example using
what the client advertises in `signature_algorithms`). Selecting among
individual trust anchors within a type is a separate problem and is out
of scope here.

Certificate authorities are expected not to mint mixed
classical/CRQC-resistant paths. Clients are expected to reject mixed
paths; detailed validation algorithms may appear in this document or in
a dedicated path-validation specification.

### Why HSTS-shaped opt-in is only a near-term lever

An HSTS-style pin is attractive because non-participating origins are not
broken. It is also inherently limited: sticky UA state, TOFU, incomplete
preload coverage, painful rollback, and private-browsing modes that do not
retain durable HSTS state. True legacy single-certificate origins never
opt in. Voluntary adoption can keep growing, but too slowly to meet
industry post-quantum timelines. A longer program is needed for the
remainder of the Web.

### PQ-secure signal embedded in classical certificates

A modern client that prefers post-quantum authentication cannot tell, when
an unknown origin presents only a classical credential, whether the origin
has no post-quantum path or an attacker stripped it. Sticky
`require-pq-ta` helps only after opt-in or preload.

The long-term answer discussed in the community is a credential that
classical clients can still verify as usual, while carrying an embedded
PQ-secure indication that no post-quantum certificate is available for
this end entity / that classical authentication is required for this
origin. Modern clients that verify that signal may accept classical
credentials only when so assured; otherwise they insist on
CRQC-resistant authentication. The wire encoding of that signal is
not specified in this document.

That construction unlocks the ecosystem as follows:

- Strict client policy: Accept classical authentication only with PQ
  assurance that classical is required for this origin; otherwise require
  CRQC-resistant authentication.
- CA incentive: Once clients are strict, plain classical certificates
  (no PQ-secure signal) fail for modern clients. CAs are pushed to stop
  issuing plain classical certificates and to issue classical certificates
  that carry the PQ-secure signal, and/or all-CRQC-resistant credentials—
  serving both legacy clients (outer classical) and modern clients (signal
  or PQ path).
- Single-certificate servers: Upgrade to multi-certificate / dual-path
  operation, or—when the legacy-client population is small enough—drop
  classical and serve only CRQC-resistant credentials.

`require-pq-ta` remains the near-term opt-in lever for origins that
already have a CRQC-resistant path. The PQ-secure signal in classical
certificates is how the long tail becomes compatible with a strict accept
set without waiting solely on unaided S-curves.

### What this document specifies versus only narrates

| In this migration narrative (informative) | Normative in this document |
|---|---|
| Accept-set logic, S-curves, dual paths by trust-anchor type, mixed-path prohibition, role of the PQ-secure signal in classical certificates, ecosystem endgame, retirement | `require-pq-ta` opt-in; UA note and enforce of trust-anchor class and key-agreement class; fail closed; retirement behavior |
| Wire encoding of the PQ-secure signal; individual trust-anchor selection | Out of scope (other documents) |

## Chronological Stages

Each stage summarizes expected CA (or trust-anchor operator),
server, and client behavior.

### Stage 0 — Today

| Role | State |
|---|---|
| CA | Classical issuance only (Web PKI). |
| Server | Classical certificates; HSTS common; no `require-pq-ta`. |
| Client | Accepts classical authentication; hybrid/PQ key agreement rolling out independently. |

### Stage 1 — Early PQ issuance, dual accept

| Role | State |
|---|---|
| CA | Some CAs begin minting CRQC-resistant credentials (public Web toward MTC; enterprise X.509 PQ chains); classical issuance continues. |
| Server | New servers can obtain CRQC-resistant credentials, support `require-pq-ta`, and may dual-home all-classical and all-CRQC-resistant paths selected by trust-anchor type. Old servers remain classical-only and do not send `require-pq-ta`. |
| Client | Most clients accept both classical and CRQC-resistant authentication. Dual accept means "PQ in use" is not yet PQ-secure against active attackers. Clients indicate PQ preference or capability via TLS `signature_algorithms` (and related mechanisms). Capable servers may begin asserting `require-pq-ta`. |

### Stage 2 — Opt-in pin spreads (this document)

| Role | State |
|---|---|
| CA | Growing CRQC-resistant issuance; classical credentials still widely available. |
| Server | More origins send STS including `require-pq-ta` once they reliably serve an all-CRQC-resistant path and complete PQ/hybrid key agreement; they may still dual-home for legacy clients. Old servers still never opt in. |
| Client | Still dual-accept by default; for Known HSTS Hosts with `require-pq-ta`, reject classical trust anchors and classical-only key agreement. Optional preload semantics. Coverage grows, but adoption remains too slow for industry post-quantum timelines. |

### Stage 3 — Accelerate PQ issuance and PQ-secure signal in classical certificates

| Role | State |
|---|---|
| CA | Broader all-CRQC-resistant issuance under CRQC-resistant trust anchors (no mixed chains). Begin issuing classical certificates with an embedded PQ-secure signal ("no PQ / classical required for this end entity") instead of plain classical—encoding specified elsewhere. |
| Server | Dual-homed new servers: all-classical and/or all-CRQC-resistant by trust-anchor type. Single-certificate legacy servers can adopt classical certificates that carry the PQ-secure signal without multi-certificate support. |
| Client | Still largely dual-accept, but a path opens to strict policy once the PQ-secure signal is widely verifiable. Reject mixed paths. For pinned names: CRQC-resistant trust-anchor path and CRQC-resistant key agreement. |

### Stage 4 — Strict clients and CA shift

| Role | State |
|---|---|
| CA | Stop plain classical issuance; classical-with-PQ-signal and/or all-CRQC-resistant products serve both old and new clients. |
| Server | Single-certificate origins stay on classical-with-PQ-signal, upgrade to dual-path, or—as legacy clients shrink—switch to CRQC-resistant only. Dual-homed origins prefer CRQC-resistant paths to modern clients. |
| Client | Deploy strict policy: classical only with PQ assurance that classical is required for this origin; otherwise CRQC-resistant only. Opt-in `require-pq-ta` still helps early PQ origins; the PQ-secure signal covers the long tail. |

### Stage 5 — Remove classical trust anchors / plain classical

| Role | State |
|---|---|
| CA | Classical Web PKI trust anchors (and classical-only MTC trust) removed; plain classical gone. |
| Server | CRQC-resistant only (or residual classical-with-PQ-signal only while last classical verifiers remain—deployment-dependent). |
| Client | Every successful acceptance uses CRQC-resistant authentication; classical without PQ assurance is rejected. |

### Stage 6 — Retire `require-pq-ta`

| Role | State |
|---|---|
| CA | CRQC-resistant-only trust world (for this PKI). |
| Server | Stop sending `require-pq-ta`; base HSTS may remain. |
| Client | The PQ policy bit is redundant and may be cleared (including any preloaded equivalent). The extension succeeds by becoming unnecessary. |

When classical trust anchors are no longer part of the relevant accept
set, `require-pq-ta` is obsolete.

# Acknowledgments
{:numbered="false"}

<cref>TODO acknowledge.</cref>
