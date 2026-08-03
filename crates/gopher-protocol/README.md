# gopher-protocol

An implementation of [Gopher](https://datatracker.ietf.org/doc/html/rfc1436)
(`gopher://`, port 70) in Rust: an async client and an RFC 1436 menu parser
with RFC 4266 URL synthesis.

This is not the reference implementation of Gopher, and it does not speak for
the protocol's community.

## Two halves, separately usable

The menu parser has no dependencies and is always compiled. A consumer that
only renders gophermaps takes the crate without the client and pulls no async
runtime:

```toml
gopher-protocol = { version = "0.1", default-features = false }
```

The client rides the default `client` feature.

## Example

```rust,no_run
# async fn run() -> Result<(), gopher_protocol::ClientError> {
let reply = gopher_protocol::fetch("gopher://gopher.floodgap.com/1/").await?;
for item in gopher_protocol::parse_menu(&String::from_utf8_lossy(&reply.body)) {
    println!("{:?} {}", item.kind, item.display);
}
# Ok(())
# }
```

## Scope

A client and a parser. It does not serve gopher, and it holds no document or
render model: how a `Search` or `Image` item should look is the consumer's
decision.

Gopher carries no status line and no MIME type, so `Response::mime` is a
best-effort inference from the item type, documented as a client convention
rather than part of the RFC.

## License

MIT.
