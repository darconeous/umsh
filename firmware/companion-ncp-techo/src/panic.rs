//! Panic handler for the companion-ncp-techo firmware.
//!
//! Wires together three BSP pieces that are each unit-testable in
//! isolation but must be glued together in the binary:
//!
//! - `umsh_bsp_nrf52840::panic_persist::SyncNoinit` — the `.uninit`
//!   retained-RAM static that survives warm resets.
//! - `umsh_bsp_nrf52840::panic_persist::{PanicSlot, SliceWriter}` —
//!   framing and formatting over that region.
//! - `umsh_bsp_nrf52840::gpregret::reset_to_app` (GPREGRET=0, then
//!   `SCB::sys_reset`) — ensures the bootloader boots the app on the
//!   next start so the panic message is visible over USB-CDC.
//!
//! The `#[panic_handler]` attribute is permitted only in binary crates;
//! library crates cannot define one without causing a duplicate-symbol
//! link error. Everything else in this file could in principle live in the
//! BSP, but the handler itself cannot.

use umsh_bsp_nrf52840::panic_persist::{PanicSlot, SliceWriter, SyncNoinit};

/// Retained-RAM region for panic messages.
///
/// Placed in the `.uninit` section so cortex-m-rt does not zero it at
/// startup, allowing the previous boot's panic message to survive a warm
/// reset and be read on the next boot.
#[unsafe(link_section = ".uninit")]
pub static PANIC_REGION: SyncNoinit<[u8; 1024]> = SyncNoinit::uninit();

/// Return a mutable byte slice over [`PANIC_REGION`].
///
/// # Safety
/// Must not be called while any other reference to `PANIC_REGION` is live.
/// In practice: called once at boot (before tasks start) to read + clear
/// a previous panic, and once more from the panic handler (after the
/// executor has stopped and no other code is running).
pub fn panic_region() -> &'static mut [u8] {
    unsafe { PANIC_REGION.as_bytes_mut() }
}

/// Boot-progress breadcrumb, retained across warm resets.
///
/// TEMPORARY diagnostic instrumentation for the post-DFU first-boot
/// watchdog freeze: boot stages write a marker here, and the next boot
/// reads the previous boot's last marker (surfaced through the NCP
/// version string as `crumb=N`). A watchdog reset preserves RAM, so the
/// marker tells us exactly which stage the frozen boot last completed.
#[unsafe(link_section = ".uninit")]
static BREADCRUMB_REGION: SyncNoinit<[u8; 8]> = SyncNoinit::uninit();

const BREADCRUMB_MAGIC: [u8; 4] = *b"UCRM";

/// Read the previous boot's last marker and heartbeat count (0, 0 if
/// none were recorded) and re-arm the region for this boot.
///
/// Call once, at the very top of `main`, before the first
/// [`breadcrumb_mark`].
pub fn breadcrumb_take() -> (u8, u16) {
    let region = unsafe { BREADCRUMB_REGION.as_bytes_mut() };
    let (previous, beats) = if region[..4] == BREADCRUMB_MAGIC {
        (
            region[4],
            u16::from_le_bytes([region[5], region[6]]),
        )
    } else {
        (0, 0)
    };
    region[..4].copy_from_slice(&BREADCRUMB_MAGIC);
    region[4] = 0;
    region[5] = 0;
    region[6] = 0;
    (previous, beats)
}

/// Record that boot progress reached `stage`. Preserves the heartbeat
/// count.
///
/// Calls are sequential (boot code and executor tasks on one core), so
/// the short-lived `&mut` regions never overlap in practice — the same
/// discipline as [`panic_region`].
pub fn breadcrumb_mark(stage: u8) {
    let region = unsafe { BREADCRUMB_REGION.as_bytes_mut() };
    region[..4].copy_from_slice(&BREADCRUMB_MAGIC);
    region[4] = stage;
}

/// Record one heartbeat-loop iteration (~50 ms each). Distinguishes a
/// frozen executor (count stops with the boot stage) from ineffective
/// watchdog pets (count keeps climbing until the reset).
pub fn breadcrumb_beat() {
    let region = unsafe { BREADCRUMB_REGION.as_bytes_mut() };
    if region[..4] != BREADCRUMB_MAGIC {
        return;
    }
    let beats = u16::from_le_bytes([region[5], region[6]]).saturating_add(1);
    region[5..7].copy_from_slice(&beats.to_le_bytes());
}

/// Retained capture of the exception frame taken by the watchdog
/// TIMEOUT interrupt, which hardware fires two LFCLK ticks (~61 µs)
/// before the watchdog reset. TEMPORARY freeze diagnostics: the stacked
/// PC names the code the CPU was executing when the watchdog expired,
/// and the stacked xPSR's exception number distinguishes a thread-mode
/// spin (0) from an interrupt storm (the storming IRQ's number).
#[unsafe(link_section = ".uninit")]
static WDT_CAPTURE: SyncNoinit<[u8; 184]> = SyncNoinit::uninit();

const WDT_CAPTURE_MAGIC: [u8; 4] = *b"UWDT";

/// Words of interrupted-context stack retained beyond the exception
/// frame, for a host-side return-address scan.
pub const WDT_STACK_WORDS: usize = 32;

/// Decoded previous-boot watchdog capture.
#[derive(Clone, Copy, Debug)]
pub struct WdtCapture {
    pub pc: u32,
    pub lr: u32,
    pub xpsr: u32,
    pub exc_return: u32,
    pub sp: u32,
    /// CLOCK peripheral state at death: HFCLKSTAT, LFCLKSTAT, INTENSET,
    /// EVENTS_HFCLKSTARTED, EVENTS_LFCLKSTARTED, EVENTS_DONE,
    /// EVENTS_CTTO, LFCLKSRC.
    pub clock: [u32; 8],
    pub stack: [u32; WDT_STACK_WORDS],
}

/// Read and clear the previous boot's watchdog capture, if one exists.
/// Call once at the top of `main`.
pub fn wdt_capture_take() -> Option<WdtCapture> {
    let region = unsafe { WDT_CAPTURE.as_bytes_mut() };
    if region[..4] != WDT_CAPTURE_MAGIC {
        return None;
    }
    region[..4].copy_from_slice(&[0; 4]);
    let word = |index: usize| {
        u32::from_le_bytes(
            region[index * 4..index * 4 + 4]
                .try_into()
                .expect("4-byte slice"),
        )
    };
    let mut capture = WdtCapture {
        pc: word(1),
        lr: word(2),
        xpsr: word(3),
        exc_return: word(4),
        sp: word(5),
        clock: [0; 8],
        stack: [0; WDT_STACK_WORDS],
    };
    for (index, slot) in capture.clock.iter_mut().enumerate() {
        *slot = word(6 + index);
    }
    for (index, slot) in capture.stack.iter_mut().enumerate() {
        *slot = word(14 + index);
    }
    Some(capture)
}

/// Rust half of the WDT TIMEOUT handler. `frame` is the exception frame
/// of the interrupted context: [r0, r1, r2, r3, r12, lr, pc, xPSR].
/// The watchdog reset follows unconditionally ~61 µs after the event,
/// so this only records and returns.
#[unsafe(no_mangle)]
extern "C" fn wdt_timeout_capture(frame: *const u32, exc_return: u32) {
    let region = unsafe { WDT_CAPTURE.as_bytes_mut() };
    let sp = frame as u32;
    // Only dereference a frame pointer that lies in nRF52840 data RAM
    // with room for the frame plus the extra stack window.
    let readable = (0x2000_0000..=0x2003_FF00).contains(&sp);
    let word = |offset: usize| {
        if readable {
            unsafe { frame.add(offset).read_volatile() }
        } else {
            0
        }
    };
    let clock_register = |offset: u32| unsafe {
        ((0x4000_0000u32 + offset) as *const u32).read_volatile()
    };
    let mut write = |index: usize, value: u32| {
        region[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    write(1, word(6)); // stacked PC
    write(2, word(5)); // stacked LR
    write(3, word(7)); // stacked xPSR
    write(4, exc_return);
    write(5, sp);
    for (index, offset) in [
        0x40Cu32, // HFCLKSTAT
        0x418,    // LFCLKSTAT
        0x304,    // INTENSET (read returns enabled set)
        0x100,    // EVENTS_HFCLKSTARTED
        0x104,    // EVENTS_LFCLKSTARTED
        0x10C,    // EVENTS_DONE (calibration)
        0x110,    // EVENTS_CTTO (calibration timer)
        0x518,    // LFCLKSRC
    ]
    .into_iter()
    .enumerate()
    {
        write(6 + index, clock_register(offset));
    }
    for index in 0..WDT_STACK_WORDS {
        write(14 + index, word(8 + index));
    }
    region[..4].copy_from_slice(&WDT_CAPTURE_MAGIC);
}

// The WDT TIMEOUT vector. Naked so the exception frame location is not
// disturbed by a compiler prologue: EXC_RETURN bit 2 selects which stack
// pointer held the interrupted context's frame.
core::arch::global_asm!(
    ".section .text.WDT, \"ax\"",
    ".global WDT",
    ".type WDT, %function",
    ".thumb_func",
    "WDT:",
    "tst lr, #4",
    "ite eq",
    "mrseq r0, msp",
    "mrsne r0, psp",
    "mov r1, lr",
    "b wdt_timeout_capture",
);

/// Retained ring of interrupted-context PCs sampled at 1 kHz by TIMER2
/// (priority 1). TEMPORARY freeze diagnostics: unlike the one-shot WDT
/// capture, samples accumulate through the whole freeze, so the ring
/// holds either the frozen spin itself or the last code executed before
/// interrupts were masked. Layout: magic(4) | index(4) | 64 PCs.
#[unsafe(link_section = ".uninit")]
static PC_RING: SyncNoinit<[u8; 8 + PC_RING_ENTRIES * 4]> = SyncNoinit::uninit();

const PC_RING_MAGIC: [u8; 4] = *b"UPCR";
/// Entries in the PC sample ring (last 64 ms of interruptible execution).
pub const PC_RING_ENTRIES: usize = 64;

/// Read and re-arm the PC sample ring. Returns the sample count and the
/// samples in oldest-to-newest order. Call once at the top of `main`,
/// before the sampler starts.
pub fn pc_ring_take(out: &mut [u32; PC_RING_ENTRIES]) -> usize {
    let region = unsafe { PC_RING.as_bytes_mut() };
    let count = if region[..4] == PC_RING_MAGIC {
        let index = u32::from_le_bytes(region[4..8].try_into().expect("4-byte slice")) as usize;
        let valid = index.min(PC_RING_ENTRIES);
        let start = if index > PC_RING_ENTRIES {
            index % PC_RING_ENTRIES
        } else {
            0
        };
        for slot in 0..valid {
            let entry = (start + slot) % PC_RING_ENTRIES;
            out[slot] = u32::from_le_bytes(
                region[8 + entry * 4..12 + entry * 4]
                    .try_into()
                    .expect("4-byte slice"),
            );
        }
        valid
    } else {
        0
    };
    region[..4].copy_from_slice(&PC_RING_MAGIC);
    region[4..8].copy_from_slice(&0u32.to_le_bytes());
    count
}

/// Rust half of the TIMER2 sampler: clear the compare event, then store
/// the interrupted context's stacked PC into the retained ring.
#[unsafe(no_mangle)]
extern "C" fn pc_sample_capture(frame: *const u32, _exc_return: u32) {
    // TIMER2 EVENTS_COMPARE[0]
    unsafe { (0x4000_A140 as *mut u32).write_volatile(0) };
    let region = unsafe { PC_RING.as_bytes_mut() };
    if region[..4] != PC_RING_MAGIC {
        return;
    }
    let sp = frame as u32;
    let pc = if (0x2000_0000..=0x2003_FFE0).contains(&sp) {
        unsafe { frame.add(6).read_volatile() }
    } else {
        0
    };
    let index = u32::from_le_bytes(region[4..8].try_into().expect("4-byte slice"));
    let entry = (index as usize) % PC_RING_ENTRIES;
    region[8 + entry * 4..12 + entry * 4].copy_from_slice(&pc.to_le_bytes());
    region[4..8].copy_from_slice(&index.wrapping_add(1).to_le_bytes());
}

// The TIMER2 vector: same naked frame-recovery shim as WDT.
core::arch::global_asm!(
    ".section .text.TIMER2, \"ax\"",
    ".global TIMER2",
    ".type TIMER2, %function",
    ".thumb_func",
    "TIMER2:",
    "tst lr, #4",
    "ite eq",
    "mrseq r0, msp",
    "mrsne r0, psp",
    "mov r1, lr",
    "b pc_sample_capture",
);

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut slot = PanicSlot::new(panic_region());

    let mut msg = [0u8; 1000];
    let msg_len = {
        let mut w = SliceWriter {
            buf: &mut msg,
            pos: 0,
        };
        let _ = core::fmt::write(&mut w, format_args!("{}", info));
        // Raw stack words above the current SP (older frames), for
        // offline symbolization of return addresses with addr2line.
        let sp = cortex_m::register::msp::read();
        let _ = core::fmt::write(&mut w, format_args!(" sp={sp:#010x} stack:"));
        let mut addr = sp & !3;
        let mut words = 0;
        while words < 48 && addr < 0x2004_0000 {
            let word = unsafe { (addr as *const u32).read_volatile() };
            // Only code-plausible words earn the space: flash addresses
            // are candidate return addresses.
            if (0x0002_0000..0x000F_5000).contains(&word) {
                let _ = core::fmt::write(&mut w, format_args!(" {word:#x}"));
                words += 1;
            }
            addr += 4;
        }
        w.pos
    };
    slot.capture(&msg[..msg_len]);

    // Clear GPREGRET so the bootloader boots the app on next start,
    // letting the captured message be printed over USB-CDC.
    umsh_bsp_nrf52840::gpregret::reset_to_app();
}

/// Capture hard faults the same way panics are captured: fault status
/// registers plus the faulting PC/LR into the retained slot, then reset
/// to the app so the next boot prints the report over USB-CDC. Without
/// this, cortex-m-rt's default handler parks in an infinite loop and
/// the only trace is a watchdog reset with no message.
#[cortex_m_rt::exception(trampoline = true)]
unsafe fn HardFault(frame: &cortex_m_rt::ExceptionFrame) -> ! {
    let mut slot = PanicSlot::new(panic_region());

    let scb = 0xE000_ED00 as *const u32;
    // CFSR @ +0x28, HFSR @ +0x2C, BFAR @ +0x38, MMFAR @ +0x34.
    let (cfsr, hfsr, mmfar, bfar) = unsafe {
        (
            scb.add(0x28 / 4).read_volatile(),
            scb.add(0x2C / 4).read_volatile(),
            scb.add(0x34 / 4).read_volatile(),
            scb.add(0x38 / 4).read_volatile(),
        )
    };

    let mut msg = [0u8; 504];
    let msg_len = {
        let mut w = SliceWriter {
            buf: &mut msg,
            pos: 0,
        };
        let _ = core::fmt::write(
            &mut w,
            format_args!(
                "HARDFAULT pc={:#010x} lr={:#010x} cfsr={:#010x} hfsr={:#010x} mmfar={:#010x} bfar={:#010x} r0={:#010x} r1={:#010x} r2={:#010x} r3={:#010x} xpsr={:#010x}",
                frame.pc(),
                frame.lr(),
                cfsr,
                hfsr,
                mmfar,
                bfar,
                frame.r0(),
                frame.r1(),
                frame.r2(),
                frame.r3(),
                frame.xpsr(),
            ),
        );
        w.pos
    };
    slot.capture(&msg[..msg_len]);

    umsh_bsp_nrf52840::gpregret::reset_to_app();
}
