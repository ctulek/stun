stun
====

A go library for STUN protocol that provides both client and server implementations

It is still in its infancy and only provides a very basic client. To install the client run the following command:

`go get github.com/ctulek/stun/stun-client`

If you just need the client library, import as "github.com/ctulek/stun" and use the stun.Call function.
An example usage of it is available in [stun-client/main.go](stun-client/main.go)

Server implementation is not started, yet.

TODO
====
- [ ] Documentation
- [ ] Finger Print and Message Integrity
- [ ] Initial Server Implementation
- [ ] Support for authentication
