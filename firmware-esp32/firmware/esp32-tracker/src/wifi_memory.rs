//! Optional qualification measurements. Enabled by wifi + ble-debug.
use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};

static STACK_MARK_END: AtomicUsize = AtomicUsize::new(0);
static MIN_FREE: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_REPORT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    static _stack_end: u8;
    static _stack_start: u8;
}

pub fn init() {
    let sp: usize;
    unsafe {
        core::arch::asm!("mov {sp}, a1", sp = out(reg) sp);
    }
    // Skip the stack protector word and leave the current frame plus a
    // generous margin alone. The firmware uses only this CPU's executor.
    let start = unsafe { core::ptr::addr_of!(_stack_end).add(64) } as usize;
    let end = sp.saturating_sub(2048);
    assert!(end > start);
    unsafe {
        core::ptr::write_bytes(start as *mut u8, 0xa5, end - start);
    }
    STACK_MARK_END.store(end, Ordering::Relaxed);
}

pub fn sample() {
    let free = esp_alloc::HEAP.free();
    MIN_FREE.fetch_min(free, Ordering::Relaxed);
    let now = embassy_time::Instant::now().as_secs() as usize;
    let last = LAST_REPORT.load(Ordering::Relaxed);
    if now < last + 30 {
        return;
    }
    LAST_REPORT.store(now, Ordering::Relaxed);
    let start = unsafe { core::ptr::addr_of!(_stack_end).add(64) } as usize;
    let end = STACK_MARK_END.load(Ordering::Relaxed);
    let mut untouched = start;
    while untouched < end && unsafe { (untouched as *const u8).read_volatile() } == 0xa5 {
        untouched += 1;
    }
    // A bounded allocation probe uses the real allocator's alignment and
    // overhead. Interrupts cannot observe its transient reservation, and
    // every successful probe is immediately freed without touching data.
    let largest = CriticalSectionRawMutex::new().lock(|| {
        let mut low = 0;
        let mut high = free / 16 + 1;
        while high - low > 1 {
            let mid = (low + high) / 2;
            let layout = Layout::from_size_align(mid * 16, 16).unwrap();
            let ptr = unsafe { GlobalAlloc::alloc(&esp_alloc::HEAP, layout) };
            if ptr.is_null() {
                high = mid;
            } else {
                unsafe {
                    GlobalAlloc::dealloc(&esp_alloc::HEAP, ptr, layout);
                }
                low = mid;
            }
        }
        low * 16
    });
    let stack_top = core::ptr::addr_of!(_stack_start) as usize;
    super::debug_log(format_args!(
        "wifi memory: free={} sampled_min={} largest={} stack_used={} stack_margin={}",
        free,
        MIN_FREE.load(Ordering::Relaxed),
        largest,
        stack_top - untouched,
        untouched - start
    ));
}
