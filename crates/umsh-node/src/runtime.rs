use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::RefCell;

use umsh_mac::LocalIdentityId;

use crate::dispatch::{EventDispatcher, EventSink};
use crate::mac::MacBackend;
use crate::node::{LocalNode, NodeMembership};

/// Owns the event dispatcher and creates `LocalNode` handles.
///
/// `NodeRuntime` is the entry point for the new API. Create it with a
/// `MacBackend` implementation, then call `create_node()` to get
/// `LocalNode` handles for each registered identity.
///
/// The runtime owns the shared `EventDispatcher`. When integrated with
/// the MAC event loop (via `poll_cycle` or `next_event`), the dispatcher
/// updates ticket state and delivers `NodeEvent`s to registered sinks.
pub struct NodeRuntime<M: MacBackend> {
    mac: M,
    dispatcher: Rc<RefCell<EventDispatcher>>,
}

impl<M: MacBackend> NodeRuntime<M> {
    /// Create a new runtime wrapping the given MAC backend.
    pub fn new(mac: M) -> Self {
        Self {
            mac,
            dispatcher: Rc::new(RefCell::new(EventDispatcher::new())),
        }
    }

    /// Create a `LocalNode` for an identity slot already registered with the MAC.
    ///
    /// The `sink` receives `NodeEvent`s dispatched from the MAC event loop.
    /// Channel-scoped events are filtered by the node's membership set.
    pub fn create_node(
        &self,
        identity_id: LocalIdentityId,
        sink: Box<dyn EventSink>,
    ) -> LocalNode<M> {
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        self.dispatcher.borrow_mut().register_node(
            identity_id,
            membership.clone(),
            sink,
        );
        LocalNode::new(
            identity_id,
            self.mac.clone(),
            self.dispatcher.clone(),
            membership,
        )
    }

    /// Create a `LocalNode` without an event sink.
    ///
    /// The node can still send and track tickets, but won't receive
    /// `NodeEvent`s. Useful for send-only nodes or when the application
    /// handles MAC events directly.
    pub fn create_node_without_sink(
        &self,
        identity_id: LocalIdentityId,
    ) -> LocalNode<M> {
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        LocalNode::new(
            identity_id,
            self.mac.clone(),
            self.dispatcher.clone(),
            membership,
        )
    }

    /// Dispatch a MAC event through the runtime.
    ///
    /// Updates ticket state and delivers `NodeEvent`s to registered sinks.
    /// Call this from the MAC event loop callback:
    ///
    /// ```ignore
    /// let runtime = NodeRuntime::new(mac_handle.clone());
    /// let node = runtime.create_node(id, sink);
    ///
    /// mac.poll_cycle(|identity_id, event| {
    ///     runtime.dispatch(identity_id, &event);
    /// }).await?;
    /// ```
    pub fn dispatch(
        &self,
        identity_id: LocalIdentityId,
        event: &umsh_mac::MacEventRef<'_>,
    ) {
        self.dispatcher
            .borrow_mut()
            .dispatch_ticket_state(identity_id, event);
    }
}
