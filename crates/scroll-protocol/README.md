# scroll-protocol

An implementation of the Scroll protocol (`scroll://`, port 5699) and its
**scrolltext** document format (`text/scroll`), by Christian Lee Seibold, in
Rust.

This is not the reference implementation, and it does not speak for the
protocol's author.

## What scroll adds over gemini

- The request names the client's **acceptable languages** (BCP47,
  most-preferred first), and the server serves the best match.
- A success response carries **document metadata**: author, publish date,
  modification date.
- The second digit of a success code is a **Universal Decimal Classification
  class** — scroll is the only small-web protocol whose responses classify
  their own subject matter.
- A `+` on the language list requests a resource's **abstract** instead of its
  body.

Scrolltext is richer than gemtext on purpose: five heading levels forming
numbered sections, nested quotes and lists with verbatim ordered markers,
tagged code blocks, input links (`=:`), link relations (`[Citation]`, `[+]`),
inline strong/emphasis/code with precise toggle rules, and a linetype escape.
The parser is dependency-free.

## Provenance, stated plainly

The specification's own host (`scrollprotocol.us.to`) is offline. This crate
is written against the spec text vendored by
[michael-lazar/smolnet-portal](https://github.com/michael-lazar/smolnet-portal)
(`docs/scroll_spec.txt`, modification date 2024-08-03), cross-checked against
that portal's working proxy, which interoperates with live scroll servers.
The spec titles itself *speculative*; expect revisions.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire grammar + scrolltext | always on | nothing |
| `exchange` over any stream | `client` | tokio |
| `fetch` with TLS + TOFU | `tls` *(default)* | gemini-protocol |

The TLS half deliberately rides `gemini_protocol::tofu_connect`: scroll's spec
says "TOFU is used, similarly to Gemini", so the two protocols share one trust
seam, and a host that installs a `TofuStore` has installed it for both.

## Not implemented

A server; client certificates (including the spec's misfin-certificate
convention); and the inline-toggle exception between two **non-ASCII** symbols,
which needs Unicode category tables this crate does not carry — the ASCII cases
are honoured and the limitation is recorded in the docs.

## License

MIT.
