# fsp-protocol

An implementation of [FSP](https://fsp.sourceforge.net/) (File Service
Protocol, `fsp://`, port 21) in Rust: anonymous file transfer over UDP.

This is not the reference implementation, and it does not speak for the
protocol's community.

## The outlier of the family

Everything else in this workspace is a TCP stream. FSP is **UDP with its own
reliability**, and it is deliberately simple enough to run without a transport
at all: the header carries both a checksum and a payload size, so in the
specification's words it "can be used as very simple raw-protocol (for example
for sending data over serial line). This makes it very popular in embedded
devices area."

That self-sufficiency is why FSP is awkward to carry over an already-reliable
link: you would be running two reliability layers.

## The detail that breaks implementations

**The checksum is computed differently in each direction.** Server to client
starts from zero; client to server starts from the packet's own size.

Get it wrong and every packet you send is rejected while every packet you
receive validates — which reads like a network fault rather than a bug. There
is a test asserting the two differ by exactly the packet size.

## Reliability

FSP sequences itself, and this client honours it: the client chooses the
sequence and the server echoes it, so a **stale reply is discarded and the read
continues** rather than being handed up as an answer to a question nobody
asked. The client also echoes the server's last key on every request, as the
spec requires.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire format | always on | nothing |
| client | `client` *(default)* | tokio |

## Not implemented

The write half (`CC_UP_LOAD`, `CC_INSTALL`, `CC_DEL_FILE`, `CC_MAKE_DIR` and
friends), password protection, and a server. Every command code is defined and
`Session::request` will send any of them, so the wire work is done even where a
convenience method is not.

## License

MIT.
