# Feedback on Revised UMSH CLI Plan

This version is much better. It addresses the main structural issues from the previous draft:

- `alloc` is now mandatory rather than optional.
- `service()` is unconditional after every top-level loop turn.
- the local public key is passed into `CliSession::new(...)`.
- text interop through `umsh-text` is explicit.
- avoiding a new `PeerConnection::send_mac_command` API is the right call.

Also, I checked the current tree: `umsh_node::mac_command::encode` is already `pub`, so the "possibly modify node" step probably will not be needed.

I would still push on a few things before calling the plan implementation-ready.

## Remaining Suggestions

1. **Callback event queue needs interior mutability.**

   The plan says callbacks push into:

   ```rust
   events: heapless::Deque<CliEvent, N_EVENTS>
   ```

   but node callbacks are `'static` closures. They cannot borrow `&mut self.events` from the session.

   The event queue probably needs to be something like:

   ```rust
   Rc<RefCell<heapless::Deque<CliEvent, N_EVENTS>>>
   ```

   or a small cloneable `EventSink` wrapper around that. The same applies to stats if callbacks mutate stats directly.

2. **`pump()` has an internal contradiction.**

   The plan says:

   > Commands that need to send packets stash work into the event queue; nothing in this call path blocks on the MAC.

   But later `/msg`, `/ping`, `/pfs`, etc. are described as sending directly.

   Pick one model:

   - `pump()` only parses input and enqueues outbound work; `service()` performs all async sends.
   - Or `pump()` executes commands directly and may await sends.

   I slightly prefer the first model because it keeps the `select!` cancellation story cleaner after a line has been read.

3. **If `pump()` awaits sends, cancellation safety is broader than `read_line()`.**

   The plan correctly covers cancellation-safe line reads, but if `pump()` reads a complete line and then starts an async send, the whole `pump()` future can still be dropped by `select!` while the send is in progress.

   Enqueueing outbound command events avoids this ambiguity.

4. **`OwnedMacCommand` is not really bounded.**

   `OwnedMacCommand::EchoRequest` and `OwnedMacCommand::EchoResponse` use `alloc::Vec<u8>`.

   That is allowed under the plan's `alloc` constraint, but it cuts against the bounded-event-queue story. For CLI events, I would store bounded command-specific variants instead, such as:

   ```rust
   EchoReply {
       peer: PublicKey,
       data: heapless::Vec<u8, 64>,
   }
   ```

   and avoid a generic:

   ```rust
   MacCommandIn {
       from: PublicKey,
       cmd: OwnedMacCommand,
   }
   ```

   unless it is only for display/debug and bounded before insertion.

5. **`/channel send` should use text framing too.**

   The plan fixes unicast text interop via `UnicastTextChatWrapper`, but `/channel send <name> <text>` still says `BoundChannel::send_all`.

   If this is meant to be chat-compatible, it should use `MulticastTextChatWrapper` or otherwise encode `PayloadType::TextMessage`.

6. **`TracingLogger` needs example dependencies.**

   The current workspace does not appear to have `tracing` dependencies.

   If `cli_udp` includes a tracing-backed logger, `umsh/Cargo.toml` needs `tracing` and possibly `tracing-subscriber` as optional deps/features, or the example should use a simpler stdout logger.

## Overall Assessment

I would call this a solid revised plan.

The biggest remaining design correction is making `service()` the single place that drains both inbound callback events and outbound command work, with callbacks and `pump()` both feeding a shared queue or sink. That would make the async story cleaner and much easier to reason about.
