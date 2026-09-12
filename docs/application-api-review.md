# Review of the qtak application API

The existing public API remains `src/common/transport.h`. The `qtak` versions
of `src/common/qlinq.h` and `qlinq.c` have not been ported.

The wrapper contains useful unicast concepts: a bounded queue of owned events,
a service loop for multiple endpoints, named stream handles, delivery-mode
selection and writable notifications. These form a new application-facing API,
rather than independent fixes to the existing transport API.

A selective adaptation would need to define event ownership and queue-pressure
behavior, preserve existing payload compatibility, and decide how stream
handles map onto the current track API. In particular, the wrapper inserts its
own metadata envelope into FEC data records and removes it on receive. Importing
it unchanged would introduce another record format. Its endpoint configuration
and event dispatch also include multicast settings, outgoing mesh connections,
and finite-transfer finish/drain/abort state.

Keep the existing transport API for this generic port. If an application needs
owned events or a common service loop, design that addition around its unicast
requirements and existing record format. The qlinq-cast application and
finite-transfer lifecycle remain outside this port.
