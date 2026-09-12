# Application API port decisions

The unicast core of `qtak`'s `qlinq.h` and `qlinq.c` is now available in
`libqlinq.a`. See [Native application API](application-api.md) for usage,
ownership, timing and compatibility rules.

The port retains contexts, endpoints, named publish/subscribe streams,
delivery modes, bounded owned events, writable notifications, service polling,
reconnect, credential reload, endpoint shutdown and statistics. It exposes the
current transport's configurable cache and reliable-stream allocation limits.

It omits multicast and listener-initiated mesh configuration and the excluded
finite-transfer stream lifecycle. FEC DATA records use the existing transport
format instead of the qtak wrapper's private metadata envelope, preserving
interoperability with `transport.h` applications. The wrapper does not strip
payload bytes that resemble that envelope.
