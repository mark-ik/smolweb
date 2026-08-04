# gemini-protocol

[Gemini](https://geminiprotocol.net/) (`gemini://`, port 1965) in Rust, with
the things its specification defines alongside it: the **gemtext** document
grammar, trust-on-first-use certificate pinning, and the **titan://** upload
companion.

They share a crate because they share a spec. Gemtext is not a separate format
that happens to travel over gemini; it is the format gemini defines, and titan
is the write half of the same document space.

This is not the reference implementation of Gemini, and it does not speak for
the protocol's community.

## Three layers, three costs

| Layer | Feature | Pulls | What it gives you |
|---|---|---|---|
| gemtext | always on | nothing | the document grammar |
| client | `client` | tokio, url | the exchange over *any* stream |
| fetch, TOFU, titan | `tls` *(default)* | rustls, ring | the ordinary internet client |

The split is not ceremony. **Five other smolweb protocols serve `text/gemini`
bodies** (spartan, guppy, scroll, misfin, and titan itself), so the grammar is
the piece most consumers actually want, and it should never drag in a TLS
stack to get it:

```toml
gemini-protocol = { version = "0.1", default-features = false }
```

And the request/response is transport-independent, so gemini over an
already-encrypted carrier, such as a [Reticulum](https://reticulum.network/)
link where the destination hash *is* the peer identity and there is no
certificate to pin, wants `client` without `tls`.

## Trust is real TOFU

The host's pinned fingerprint is checked *during* the handshake, a first
contact is pinned once it completes, and a changed certificate surfaces as
`CertificateChanged` before the request is ever sent, so nothing is disclosed
to whoever answered. Install a store with `set_trust_store`; the default is
permissive, which is a deliberate choice a host must override rather than a
silent one.

## Status classes stay apart

Temporary (`4x`) and permanent (`5x`) failure are distinct, because retrying
one is reasonable and retrying the other is not. The literal two-digit code
stays on `Response::code`, since the second digit carries detail the class
does not.

## Known gap

Client certificates are recognised but not answerable: a `6x` response parses
correctly and reports itself, but this crate cannot yet present a client
certificate to satisfy it.

## License

MIT.
