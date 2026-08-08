# Finishing the set: verdicts on the remaining protocols

Written 2026-08-06, while adding `scorpion-protocol` as the thirteenth crate.
Recorded because a decision *not* to implement something needs a reason on
file as much as a decision to implement it does; otherwise the same candidate
gets re-researched every few months.

The rule applied throughout: **a crate ships only where a wire specification
exists to be faithful to.** Where a protocol has no spec, guessing its wire
format would produce something that looks like an implementation and
interoperates with nothing.

## Mercury — will not implement

Not a protocol. Solderpunk sketched it in a gemlog post as a hypothetical
simpler-than-Gemini design, and the Gemini FAQ §6 is explicit about the
intent: it was written *"purely to illustrate something which could exist in
principle, not with the intent that anybody actually implement it"* — a
"philosophical navigation aid" for arguing about where Gemini should sit on
the complexity axis.

Some people have implemented it anyway, but there is no specification to be
faithful to, and there is no authority to be faithful to it. Implementing
Mercury would mean picking one of those third-party interpretations and
calling it the protocol.

Note the near-miss: `text-protocol` already has a port named "Mercury" (1961).
That is Text Protocol's own spec naming a port, and is unrelated to this.

## Molerat — deferred, not refused

Real, with a published specification at <https://molerat.trinket.icu/>,
mandatory TLS, a get/put/del request model, and a markdown-ish document format
called `mtxt`. It is a genuine candidate.

The reason to wait is the version: **v0.1.0-alpha**. Publishing a crate
against an alpha spec means either pinning to a moving target or breaking
consumers each time the spec moves. Revisit when there is a stable version, or
if a consumer actually needs it — at which point the alpha is a deliberate
cost rather than an accident.

## Demarkus — probably out of scope

Real, and interesting, but a different animal: versioned markdown over
**QUIC**, with capability-based access tokens and full version history. That
is much closer to a content-management protocol than to the smolweb's
"one request, one response, no state" shape, and none of this workspace's
existing structure would fit it.

Not a no, but it does not belong beside these twelve without a deliberate
decision that the workspace's scope now includes QUIC-based document systems.

## SuperTXT — not investigated in depth

Named as a candidate earlier in the same sweep and not chased down, because
the three above accounted for the actual gap. Left here so it is not forgotten
rather than presented as a verdict.

## What "the set" actually is

Worth recording, because it reframes the question. The
[smolnet-portal](https://deepwiki.com/michael-lazar/smolnet-portal/4-protocol-support)
— a real portal serving real traffic — supports seven protocols: gemini,
gopher, scroll, finger, spartan, text, and nex. This workspace had all seven
before Scorpion, plus guppy, kepler, dict, fsp, and misfin.

So the set was already complete by the practical measure of what anyone
serves. Scorpion was the real remaining gap: a substantial protocol, actively
maintained by its author, with a specification detailed enough to implement
faithfully and a shape genuinely unlike the others.
