# text-protocol

An implementation of the [Text Protocol](https://textprotocol.org/)
(`text://`) in Rust: the deliberately minimal one.

This is not the reference implementation, and it does not speak for the
protocol's community.

## The whole protocol fits here

```text
request  = IRI CRLF                      (UTF-8, NFC, absolute)
response = "20" SP mimetype CRLF body    (success)
         / "30" SP IRI CRLF              (redirect)
         / "40" SP description CRLF      (error)
```

Three status codes; every document is `text/plain;charset=utf-8`; the only
structure in a body is the optional link line
(`=> text://example.org/a.txt rel=license CC0-1.0`), whose `key=value` tokens
are attributes and whose remaining tokens are the label.

## Three transports, named like flight programs

The spec advertises its transports over DNS Service Discovery:

| Port | Name | Carrier | This crate |
|---|---|---|---|
| 1961 | Mercury | plain TCP | `fetch` (feature `client`, default) |
| 1965 | Gemini | TLS | `fetch_tls` (feature `tls`) |
| 1968 | Apollo | Noise XX (Curve25519, ChaCha20-Poly1305, BLAKE2b) | **not implemented** |

The Noise transport would pull a Noise stack this crate does not otherwise
need; the port and pattern are recorded so nobody rediscovers them. TLS
certificates are accepted without verification, stated rather than hidden:
the protocol's own plain-TCP transport shows encryption is optional here, so
TLS is confidentiality, not peer authentication.

The grammar is dependency-free (`default-features = false`), and `exchange`
runs over any stream, so an already-encrypted carrier needs no TLS of its own.

## License

MIT.
