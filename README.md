# misfin

An embeddable Rust implementation of the [Misfin](https://misfin.org) mail
protocol: identities, gemmail, a sending client, a receive server, and a small
CLI.

## Stewardship of this name

Misfin is [lem's](https://github.com/JCLemme/misfin) protocol. This crate is an
independent implementation of the specification (prototype B), **not** the
reference implementation, and it is not affiliated with the protocol's author.
The `misfin` name on crates.io is held in stewardship: **if the protocol's
author wants it, it will be transferred on request** (open an issue here or
mail the address in the commit log), and this crate will move to a qualified
name.

## What Misfin is

Mail for the small internet, heavily influenced by Gemini. A message is one
TLS transaction: the client connects (port 1958), both sides present
self-signed x509 certificates, the client sends a single CRLF-terminated
request of at most 2048 bytes —

```
misfin://mailbox@hostname <message>
```

— and the server answers with a gemini-shaped `<status> <meta>` line. A
sender's identity *is* its certificate fingerprint; trust is
trust-on-first-use. Messages are gemtext plus three metadata line types
(sender `<`, recipients `:`, timestamp `@`).

## Library

```rust
use misfin::{MisfinAddress, SendOptions, send};

let recipient = MisfinAddress::parse("friend@example.com")?;
let receipt = send(&recipient, "What's up?", &SendOptions {
    identity: Some(my_identity),           // strongly recommended
    expected_fingerprint: pinned,           // TOFU pin, once known
    ..Default::default()
}).await?;
println!("{} {}", receipt.status, receipt.meta);
```

Identities can be minted randomly and persisted
(`ensure_identity_with_root`) or derived deterministically from a 32-byte seed
(`deterministic_identity` — nothing to back up; the same seed always
reproduces the same certificate and fingerprint).

Feature flags:

| feature  | adds |
|----------|------|
| *(none)* | addresses, gemmail parse/compose, status codes, identity minting/storage |
| `client` | `send` — async TLS delivery (tokio + rustls) |
| `server` | `MisfinServer` + redb `MailboxStore`, sender-identity extraction, 63 on changed fingerprints |
| `cli`    | the `misfin` binary |

## CLI

```
cargo install misfin --features cli

misfin id mark@example.com --blurb "Mark"
misfin serve mark@example.com --listen 0.0.0.0:1958
misfin send friend@other.com "hello over misfin" --from mark@example.com
misfin inbox mark@example.com
```

## Spec coverage (prototype B, 2023-05-11)

| Spec section | State |
|---|---|
| §1.1 transaction shape (single request/response, CRLF, close-notify) | client + server |
| §1.2 request scheme, 2048-byte ceiling | enforced both sides (client refuses to build; server answers 59) |
| §1.3 / §2 status codes | full typed vocabulary (`MisfinStatus`), all 19 defined codes |
| §3 TLS ≥ 1.2 | rustls, TLS 1.2/1.3 |
| §3.1 identity certificates (USER_ID / COMMON_NAME / SAN, SHA-256 fingerprints) | minting and parsing |
| §3.2 TOFU validation | client: fingerprint pinning; server: per-identity pins, 63 on change |
| §4 gemmail (sender/recipients/timestamp lines, subject) | parse + compose + reply-set helper (§4.2 dedupe rules) |
| Multi-domain hosting, CA-signed mailbox certs (§3.1 advanced) | not implemented (single-domain; self-signed leaf only) |
| CGI (42), proxying (43), rate limiting (44), hashcash (64) | status codes surfaced; server does not implement the behaviors |

Redirects (30/31) and retryable failures (4x) are reported to the caller, not
acted on — per the best-practices document, resending is the user's decision.

## License

MIT, matching how the protocol's own repository licenses its reference
implementation (the protocol itself is declared public domain there, and the
spec documents are CC-BY-SA 4.0). Originally extracted from the
[Mere](https://github.com/mark-ik/mere) browser workspace, which now consumes
this crate.
