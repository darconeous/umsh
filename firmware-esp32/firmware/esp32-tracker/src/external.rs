//! Explicit external storage for single-task, non-atomic protocol data.
//! The global heap, radio buffers, stacks, and executor stay internal.
use core::alloc::Layout;
use esp_alloc::{EspHeap, HeapRegion, MemoryCapability};
use esp_hal::psram::{Psram, PsramConfig, PsramMode};

static EXTERNAL: EspHeap = EspHeap::empty();

#[cfg(feature = "bridge-client")]
pub fn used() -> usize {
    EXTERNAL.used()
}

pub fn init(peripheral: esp_hal::peripherals::PSRAM<'static>) {
    let ram = Psram::new(
        peripheral,
        PsramConfig {
            mode: PsramMode::QuadSpi,
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
}

// Private: callers cannot accidentally put synchronization/DMA objects here.
unsafe fn storage<T>() -> *mut T {
    let ptr = unsafe { EXTERNAL.alloc_caps(MemoryCapability::External.into(), Layout::new::<T>()) }
        .cast::<T>();
    assert!(!ptr.is_null(), "external protocol storage exhausted");
    ptr
}

pub fn session(boot_reason: umsh_ulcp::Status) -> &'static mut super::Session {
    // Audited Session holds owned plain arrays/tables and references to the
    // internal duty/stats ledgers; it contains no atomics or DMA buffers.
    unsafe {
        let ptr = storage::<super::Session>();
        ptr.write(super::Session::new(
            super::session_config(),
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

#[cfg(feature = "board-t-lora-pager")]
pub fn display_frame() -> &'static mut [u8; umsh_pager_peripherals::display::FRAME_BYTES] {
    unsafe {
        let ptr = storage::<[u8; umsh_pager_peripherals::display::FRAME_BYTES]>();
        ptr.write_bytes(0, 1);
        &mut *ptr
    }
}
