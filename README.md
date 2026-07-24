# smolweb

Spec-faithful Rust implementations of small-web protocols. Each crate is an
embeddable library plus, where it makes sense, a CLI. None of them is the
reference implementation of its protocol, and none of them speaks for its
protocol's author.

| Crate | Protocol |
|---|---|
| [`misfin`](crates/misfin) | [Misfin](https://misfin.org) mail: identities, gemmail, sending client, receive server. |
| [`spartan-protocol`](crates/spartan-protocol) | Spartan (`spartan://`): plaintext smolweb with uploads via the `=:` prompt. |
| [`nex-protocol`](crates/nex-protocol) | Nex (`nex://`): the minimal one — plaintext TCP, no TLS, no status codes. |
| [`guppy-protocol`](crates/guppy-protocol) | Guppy v0.4.4 (`guppy://`): smolweb over UDP, with chunking, acks, and retransmission. |

All four are MIT licensed, published to crates.io, and usable without anything
else in this workspace.

## Stewardship

These crates hold names that belong, morally, to the protocols' communities
rather than to this workspace. `misfin` in particular is held in stewardship:
the crate name transfers to the protocol's author on request, no conditions.
The same offer stands for the others.

## Where the engines live

This workspace is the wire layer only. The client integration that composes
these protocols (`errand`) and the engine that renders their capsules as
documents (`nematic`) are components of
[genet](https://github.com/mark-ik/genet), which consumes these crates from
crates.io like any other dependency.

## History

`misfin` arrived from its own repository with history intact. The three
protocol crates were published from standalone repositories in July 2026,
adopted into genet on 2026-07-10, and moved here on 2026-07-23; their
commit history for that period lives in
[genet](https://github.com/mark-ik/genet) under
`components/errand/protocols/`.
