//! Explicit external storage for single-task, non-atomic protocol data.
//! The global heap, radio buffers, stacks, and executor stay internal.
//! The communicator's tasks are the exception: what they allocate comes
//! from here (see [`crate::heap`]).
#[cfg(feature = "communicator")]
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
#[cfg(feature = "communicator")]
use core::sync::atomic::{AtomicUsize, Ordering};
use esp_alloc::{EspHeap, HeapRegion, MemoryCapability};
use esp_hal::psram::{Psram, PsramConfig};

static EXTERNAL: EspHeap = EspHeap::empty();

/// Where PSRAM lies, so that a freed allocation is returned to the heap it
/// came from. Empty until [`init`].
#[cfg(feature = "communicator")]
static START: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "communicator")]
static END: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "bridge-client")]
pub fn used() -> usize {
    EXTERNAL.used()
}

pub fn init(peripheral: esp_hal::peripherals::PSRAM<'static>) {
    let ram = Psram::new(
        peripheral,
        // Quad or octal is how the part is wired, and esp-hal's
        // autodetection of it is documented as unreliable, so the board
        // says.
        PsramConfig {
            mode: crate::board::PSRAM_MODE,
            ..Default::default()
        },
    );
    let (base, size) = ram.raw_parts();
    assert!(size >= 1024 * 1024, "board PSRAM initialization failed");
    // The controller is retained for the complete firmware lifetime.
    core::mem::forget(ram);
    unsafe {
        EXTERNAL.add_region(HeapRegion::new(
            base,
            size,
            MemoryCapability::External.into(),
        ));
    }
    #[cfg(feature = "communicator")]
    {
        START.store(base as usize, Ordering::Relaxed);
        END.store(base as usize + size, Ordering::Relaxed);
    }
}

/// An allocation for a communicator task.
#[cfg(feature = "communicator")]
pub(crate) unsafe fn alloc(layout: Layout) -> *mut u8 {
    unsafe { EXTERNAL.alloc_caps(MemoryCapability::External.into(), layout) }
}

/// Whether `ptr` was allocated here.
#[cfg(feature = "communicator")]
pub(crate) fn holds(ptr: *mut u8) -> bool {
    (START.load(Ordering::Relaxed)..END.load(Ordering::Relaxed)).contains(&(ptr as usize))
}

#[cfg(feature = "communicator")]
pub(crate) unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    unsafe { GlobalAlloc::dealloc(&EXTERNAL, ptr, layout) }
}

// Private: callers cannot accidentally put synchronization/DMA objects here.
unsafe fn storage<T>() -> *mut T {
    let ptr = unsafe { EXTERNAL.alloc_caps(MemoryCapability::External.into(), Layout::new::<T>()) }
        .cast::<T>();
    assert!(!ptr.is_null(), "external protocol storage exhausted");
    ptr
}

pub fn session(
    config: umsh_ulcp_device::SessionConfig,
    boot_reason: umsh_ulcp::Status,
) -> &'static mut super::Session {
    // Audited Session holds owned plain arrays/tables and references to the
    // internal duty/stats ledgers; it contains no atomics or DMA buffers.
    unsafe {
        let ptr = storage::<super::Session>();
        ptr.write(super::Session::new(
            config,
            boot_reason,
            umsh_crypto::CryptoEngine::new(super::SoftwareAes, super::SoftwareSha256),
        ));
        &mut *ptr
    }
}

pub fn snapshot() -> &'static mut [u8; umsh_ulcp_device::SNAPSHOT_MAX] {
    unsafe {
        let ptr = storage::<[u8; umsh_ulcp_device::SNAPSHOT_MAX]>();
        ptr.write_bytes(0, 1);
        &mut *ptr
    }
}

#[cfg(feature = "bridge-client")]
pub fn bridge_buffers() -> &'static mut super::bridge::Buffers {
    // Plain byte arrays; socket state, TLS atomics, and synchronization stay internal.
    unsafe {
        let ptr = storage::<super::bridge::Buffers>();
        ptr.write_bytes(0, 1);
        &mut *ptr
    }
}

#[cfg(feature = "bridge-client")]
pub fn bridge_queues() -> &'static mut super::bridge::Queues {
    unsafe {
        let ptr = storage::<super::bridge::Queues>();
        ptr.write(super::bridge::Queues::new());
        &mut *ptr
    }
}

#[cfg(feature = "lan-bearer")]
pub fn lan_buffers() -> &'static mut super::lan::Buffers {
    // Socket buffers and scratch: plain data. The sockets themselves, and
    // the stack's state, stay internal.
    unsafe {
        let ptr = storage::<super::lan::Buffers>();
        ptr.write(super::lan::Buffers::new());
        &mut *ptr
    }
}

#[cfg(feature = "display-dcs")]
pub fn display_frame() -> &'static mut [u8; crate::board::display::FRAME_BYTES] {
    unsafe {
        let ptr = storage::<[u8; crate::board::display::FRAME_BYTES]>();
        ptr.write_bytes(0, 1);
        &mut *ptr
    }
}

/// Erase what another firmware left in the chat partition, if anything,
/// yielding after each sector: over the whole partition the erase takes
/// seconds, and the executor—the watchdog's feed among it—has to run
/// throughout. A partition already this store's, or never used, is left
/// as it is. On failure, the mount after it clears the partition itself.
#[cfg(feature = "communicator")]
pub async fn claim_chat_partition(
    flash: &'static umsh_bsp_esp32::flash_store::Flash,
    partition: core::ops::Range<u32>,
) {
    let started = embassy_time::Instant::now();
    let mut bounced = umsh_bsp_esp32::flash_store::Bounced::new(flash);
    match umsh_communicator::claim_partition(&mut bounced, partition, embassy_futures::yield_now)
        .await
    {
        Ok(false) => {}
        Ok(true) => esp_println::println!(
            "chats: erased another firmware's data in {} ms",
            started.elapsed().as_millis()
        ),
        Err(e) => esp_println::println!("chats: could not erase another firmware's data: {e:?}"),
    }
}

/// The communicator's node: its handles and queues, touched only by the
/// communicator's tasks. The settings it caches and its chats grow on the
/// heap, and its messages' text is kept here. Its chats are read from
/// `partition` of `flash`, which is cleared if it holds no chats a store
/// can read. Never inlined, as [`communicator`] is not.
#[cfg(feature = "communicator")]
#[inline(never)]
pub fn communicator_node(
    seeds: umsh_communicator::Seeds,
    flash: &'static umsh_bsp_esp32::flash_store::Flash,
    partition: core::ops::Range<u32>,
) -> &'static super::communicator::Node {
    use super::communicator::{CLOCK, Node, port};
    use umsh_bsp_esp32::flash_store::Bounced;
    use umsh_communicator::{FlashMap, FlashMapStore, Quota};

    // Where items are laid out on their way to and from flash: the
    // largest, a message's record, is about 1.8 KB.
    let buffer = alloc::boxed::Box::leak(alloc::vec![0u8; 2048].into_boxed_slice());
    let started = embassy_time::Instant::now();
    let range = partition.clone();
    let store = FlashMapStore::mount_or_clear(
        FlashMap::new(Bounced::new(flash), partition, buffer),
        Quota::DEFAULT,
    )
    .unwrap_or_else(|e| panic!("chat store: {e:?}"));
    let usage = umsh_communicator::ChatStore::usage(&store);
    esp_println::println!(
        "chats: 0x{:06x}..0x{:06x} mounted in {} ms, {} chats, {} messages, {} B",
        range.start,
        range.end,
        started.elapsed().as_millis(),
        usage.chats,
        usage.messages,
        usage.bytes,
    );
    unsafe {
        let ptr = storage::<Node>();
        ptr.write(Node::new(
            port(),
            store,
            umsh_communicator::ChannelCrypto::software(),
            &EXTERNAL,
            &CLOCK,
            seeds,
        ));
        (*ptr).set_model(super::MODEL_ID);
        &*ptr
    }
}

/// The communicator's Buoyant app: its state, view, and render trees.
/// Plain data, touched only by the communicator task. Generic only because
/// the view type cannot be named.
///
/// `build` initializes the app in the place given, since it is too large to
/// build aside and copy. Never inlined, so that what building needs is in
/// this frame, which is gone once it returns; built in the task, it would
/// widen the task's frame on every poll.
#[cfg(feature = "communicator")]
#[inline(never)]
pub fn communicator<T>(
    build: impl FnOnce(&'static mut core::mem::MaybeUninit<T>) -> &'static mut T,
) -> &'static mut T {
    unsafe { build(&mut *storage::<core::mem::MaybeUninit<T>>()) }
}

#[cfg(feature = "meshcore-forwarder")]
pub fn meshcore_storage(
    public_key: [u8; 32],
    seed: [u8; 32],
) -> &'static mut umsh_ulcp_runtime::meshcore::MeshCoreStorage {
    // A duplicate table, frame copies, and a generator: plain data,
    // touched only by the forwarder's task.
    unsafe {
        let ptr = storage::<umsh_ulcp_runtime::meshcore::MeshCoreStorage>();
        ptr.write(umsh_ulcp_runtime::meshcore::MeshCoreStorage::new(
            public_key, seed,
        ));
        &mut *ptr
    }
}

pub fn node_mac_arena()
-> &'static mut umsh_ulcp_runtime::device_node::DeviceNodeMacArena<super::NodeCounterStore> {
    // The device node's MAC: peer and channel tables, crypto state, queues,
    // and a radio adapter that holds only references to the internal mux
    // channels, duty ledger, and reseed state. Borrow tracking is
    // `RefCell`/`Cell`, with no atomics, and only executor tasks touch it.
    // Left uninitialized: `MaybeUninit` by type, written once at bring-up.
    unsafe { &mut *storage() }
}
