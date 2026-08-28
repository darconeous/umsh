//! lora-phy-backed LoRa radio driver implementing `umsh_hal::Radio`.
//!
//! Works with any chip that implements `lora_phy::mod_traits::RadioKind`
//! (SX126x, LR11xx, etc.). Per-board parameters (frequency, modulation,
//! preamble, TCXO, RF switch) are supplied by the caller — this crate
//! only owns the RX/TX state machine.
//!
//! # Architecture
//!
//! Two concurrent actors share a [`Channels`] bundle:
//!
//! 1. **[`runner`]** — an Embassy task that owns the `lora_phy::LoRa` instance.
//!    It loops between continuous RX and TX: when a TX request arrives on the
//!    TX channel it exits RX, transmits, signals the result, then re-enters RX.
//!    A request that arrives while a frame is being received is refused with
//!    [`TxError::CadTimeout`] (up to [`RX_GATE_MAX_STRIKES`] times) instead of
//!    tearing down the reception — the channel is busy either way, and the MAC
//!    already backs off and retries on that error.
//!
//! 2. **[`LoraphyRadio`]** — a lightweight handle used by the MAC coordinator.
//!    It borrows `&'static Channels` for `transmit()` (sends request, awaits
//!    result signal) and `poll_receive()` (non-blocking probe of the RX channel
//!    with waker registration via `AtomicWaker`).
//!
//! # Usage
//!
//! ```ignore
//! use umsh_radio_loraphy::{Channels, LoraphyRadio};
//! use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
//!
//! static RADIO_CH: Channels<ThreadModeRawMutex, 4, 2> = Channels::new();
//! // Spawn runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, power_dbm).
//! // Pass LoraphyRadio::new(&RADIO_CH, t_frame_ms) to the MAC.
//! ```

#![no_std]
#![allow(async_fn_in_trait)]

use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::RawMutex, channel::Channel, signal::Signal, waitqueue::AtomicWaker,
};
use heapless::Vec;
use lora_phy::{
    LoRa, RxMode,
    mod_params::{
        Bandwidth, CodingRate, DutyCycleParams, ModulationParams, PacketParams, RadioError,
        SpreadingFactor,
    },
    mod_traits::{IrqState, RadioKind},
};
pub use umsh_hal::{CadPolicy, TxError};
use umsh_hal::{RxInfo, RxOrigin, Snr, TxOptions};
/// The vetted PHY profiles, re-exported so a board crate that depends
/// only on this one can name a profile without a manifest entry.
pub use umsh_ulcp::profiles;
use umsh_ulcp::profiles::PhyProfile;

/// Maximum SX1262 LoRa payload: 255 bytes.
pub const MAX_PAYLOAD: usize = 255;

// ─── Frame types ─────────────────────────────────────────────────────────────

/// A received frame plus signal metadata.
pub struct RxFrame {
    pub data: Vec<u8, MAX_PAYLOAD>,
    pub info: RxInfo,
}

/// A queued transmit request from the MAC to the runner task.
pub struct TxRequest {
    pub data: Vec<u8, MAX_PAYLOAD>,
    /// Per-frame TX power override in dBm; `None` uses the runner's
    /// configured power.
    pub power_dbm: Option<i32>,
    /// Channel-activity-detection policy applied by the runner before
    /// keying up. A busy channel completes the request with
    /// [`TxError::CadTimeout`] instead of transmitting.
    pub cad: CadPolicy,
}

// ─── Channels ────────────────────────────────────────────────────────────────

/// Shared state between [`LoraphyRadio`] and [`runner`]. Place in a `static`.
///
/// - `M`: raw mutex type (e.g. `ThreadModeRawMutex` for single-core Embassy).
/// - `RX`: depth of the receive queue.
/// - `TX`: depth of the transmit-request queue.
pub struct Channels<M: RawMutex, const RX: usize, const TX: usize> {
    pub rx: Channel<M, RxFrame, RX>,
    pub tx: Channel<M, TxRequest, TX>,
    pub tx_done: Signal<M, Result<(), TxError<RadioError>>>,
    pub rx_waker: AtomicWaker,
}

impl<M: RawMutex, const RX: usize, const TX: usize> Channels<M, RX, TX> {
    pub const fn new() -> Self {
        Self {
            rx: Channel::new(),
            tx: Channel::new(),
            tx_done: Signal::new(),
            rx_waker: AtomicWaker::new(),
        }
    }
}

// ─── LoraphyRadio ────────────────────────────────────────────────────────────

/// Implements `umsh_hal::Radio` over the shared [`Channels`].
///
/// The actual TX power and modulation params live on the `runner` side (it
/// owns the `LoRa` driver). This handle only carries:
///   - the channel pair used to talk to the runner,
///   - a precomputed worst-case airtime so the MAC's scheduler doesn't have
///     to recompute it.
pub struct LoraphyRadio<M: RawMutex + 'static, const RX: usize, const TX: usize> {
    ch: &'static Channels<M, RX, TX>,
    t_frame_ms: u32,
}

impl<M: RawMutex + 'static, const RX: usize, const TX: usize> LoraphyRadio<M, RX, TX> {
    /// Use [`airtime_ms`] with your modulation settings to compute `t_frame_ms`.
    pub fn new(ch: &'static Channels<M, RX, TX>, t_frame_ms: u32) -> Self {
        Self { ch, t_frame_ms }
    }
}

impl<M: RawMutex + 'static, const RX: usize, const TX: usize> umsh_hal::Radio
    for LoraphyRadio<M, RX, TX>
{
    type Error = RadioError;

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        let mut frame_data: Vec<u8, MAX_PAYLOAD> = Vec::new();
        frame_data
            .extend_from_slice(data)
            .map_err(|_| TxError::Io(RadioError::PayloadSizeUnexpected(data.len())))?;
        self.ch
            .tx
            .send(TxRequest {
                data: frame_data,
                power_dbm: None,
                cad: options.cad,
            })
            .await;
        self.ch.tx_done.wait().await
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        // Fast path: frame already in queue.
        if let Ok(frame) = self.ch.rx.try_receive() {
            return Poll::Ready(Ok(copy_frame(frame, buf)));
        }
        // Register waker then double-check to close the TOCTOU race between
        // the try_receive above and the runner pushing a frame.
        self.ch.rx_waker.register(cx.waker());
        if let Ok(frame) = self.ch.rx.try_receive() {
            return Poll::Ready(Ok(copy_frame(frame, buf)));
        }
        Poll::Pending
    }

    fn max_frame_size(&self) -> usize {
        MAX_PAYLOAD
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
    }
}

/// Copy a received frame into a caller-provided buffer, truncating if the
/// caller's buffer is smaller than the frame.
fn copy_frame(frame: RxFrame, buf: &mut [u8]) -> RxInfo {
    let n = frame.data.len().min(buf.len());
    buf[..n].copy_from_slice(&frame.data[..n]);
    frame.info
}

// ─── Runner ──────────────────────────────────────────────────────────────────

/// Maximum consecutive TX requests refused with [`TxError::CadTimeout`] while
/// a reception appears to be in progress (preamble seen, frame not finished).
///
/// Refusing without touching the radio keeps the in-flight frame receivable —
/// tearing down RX for the CAD gate would lose it, and the gate would report
/// busy anyway. The chip raises no IRQ when a detected preamble turns out to
/// be noise, so the flag can go stale; after this many refusals the next
/// request falls through to the radio's own CAD, which either confirms the
/// channel is busy or clears the way (the TX path re-prepares RX afterwards,
/// resetting the gate).
pub const RX_GATE_MAX_STRIKES: u8 = 3;

/// Execute one transmit request: CAD gate (listen-before-talk) per the
/// request's [`CadPolicy`], then transmit.
///
/// `CadPolicy::RetryFor` is intentionally handled as a single gate, like
/// `Gate`: the runner has no time source, and the MAC coordinator already
/// owns retry pacing by backing off on [`TxError::CadTimeout`] and
/// re-queueing the frame.
///
/// NOT cancel-safe (`cad`, `prepare_for_tx`, and `tx` must all run to
/// completion) — call outside any `select` branch, like the TX arm it
/// replaces.
async fn perform_tx<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
    mdltn: &ModulationParams,
    tx_pkt: &mut PacketParams,
    default_power_dbm: i32,
    tx_req: &TxRequest,
) -> Result<(), TxError<RadioError>>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    if !matches!(tx_req.cad, CadPolicy::Skip) {
        let busy = async {
            lora.prepare_for_cad(mdltn).await?;
            lora.cad(mdltn).await
        }
        .await
        .map_err(TxError::Io)?;
        if busy {
            return Err(TxError::CadTimeout);
        }
    }
    let power = tx_req.power_dbm.unwrap_or(default_power_dbm);
    async {
        lora.prepare_for_tx(mdltn, tx_pkt, power, &tx_req.data)
            .await?;
        lora.tx().await
    }
    .await
    .map_err(TxError::Io)
}

/// Background loop: owns the `lora_phy::LoRa` instance, switches between
/// continuous RX and TX as requests arrive. Never returns.
///
/// Wrap this in a `#[embassy_executor::task]` in the binary crate so the
/// concrete monomorphisation is visible to the linker.
///
/// # Cancellation safety
///
/// `wait_for_irq` is the only `await` point that may be cancelled (it just
/// awaits a DIO edge and is safe to drop). `process_irq_event`,
/// `prepare_for_tx`, and `tx` all run to completion outside any `select`
/// branch — cancelling those leaves the radio in a wedged state from which
/// `prepare_for_tx` will hang forever (lora-phy explicitly warns against
/// dropping `process_irq_event` futures). The convenience `lora.rx()`
/// helper internally calls `complete_rx`/`process_irq_event`, so it is
/// **not** safe inside a `select` either; we hand-roll the IRQ loop here
/// to keep cancellation pinned to `wait_for_irq`.
pub async fn runner<RK, DLY, M, const RX: usize, const TX: usize>(
    mut lora: LoRa<RK, DLY>,
    ch: &'static Channels<M, RX, TX>,
    mdltn: ModulationParams,
    rx_pkt: PacketParams,
    mut tx_pkt: PacketParams,
    power_dbm: i32,
) -> !
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
    M: RawMutex,
{
    let mut rx_buf = [0u8; MAX_PAYLOAD];

    'outer: loop {
        if lora
            .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
            .await
            .is_err()
        {
            continue;
        }
        if lora.start_rx().await.is_err() {
            continue;
        }

        // Inner loop: stay in continuous RX, handling partial-packet IRQs
        // (PreambleReceived) without re-preparing. Break back to the outer
        // loop to re-prepare RX after a completed frame, an error, or a TX.
        let mut rx_in_progress = false;
        let mut rx_gate_strikes: u8 = 0;
        loop {
            match select(lora.wait_for_irq(), ch.tx.receive()).await {
                Either::First(Ok(())) => {
                    // process_irq_event is NOT cancel-safe — it MUST run to
                    // completion. The public method passes clear_interrupts=false
                    // (unlike complete_rx's internal call), so we explicitly
                    // clear afterwards or DIO1 stays latched high on LR1110.
                    let irq_result = lora.process_irq_event().await;
                    let _ = lora.clear_irq_status().await;

                    match irq_result {
                        Ok(Some(IrqState::Done)) => {
                            if let Ok((len, status)) =
                                lora.get_rx_result(&rx_pkt, &mut rx_buf).await
                            {
                                let mut data: Vec<u8, MAX_PAYLOAD> = Vec::new();
                                let _ = data.extend_from_slice(&rx_buf[..len as usize]);
                                let info = RxInfo {
                                    len: len as usize,
                                    rssi: status.rssi,
                                    snr: Snr::from_decibels(status.snr as i8),
                                    lqi: None,
                                    origin: RxOrigin::Air,
                                };
                                if ch.rx.try_send(RxFrame { data, info }).is_ok() {
                                    ch.rx_waker.wake();
                                }
                            }
                            continue 'outer; // re-prepare RX for the next frame
                        }
                        Ok(Some(IrqState::PreambleReceived)) => {
                            rx_in_progress = true; // gate TX until the frame resolves
                            continue;
                        }
                        Ok(_) => continue, // no-op IRQ: stay in RX
                        // A failed payload CRC lands here, and this is the
                        // only place it can be caught: repeaters cannot check
                        // a MIC or a signature, so a corrupt frame that gets
                        // past this point is forwarded, and its damaged bytes
                        // give it a duplicate-cache identity no node in the
                        // mesh has seen. The frame is dropped and RX
                        // re-prepared; the bytes are left unread.
                        Err(_) => continue 'outer,
                    }
                }
                Either::First(Err(_)) => continue 'outer,
                Either::Second(tx_req) => {
                    // A reception is in flight: refuse instead of tearing down
                    // RX for the CAD gate (which would lose the frame and
                    // report busy anyway). The MAC treats this like any other
                    // busy verdict and retries after backoff.
                    if rx_in_progress && rx_gate_strikes < RX_GATE_MAX_STRIKES {
                        rx_gate_strikes += 1;
                        ch.tx_done.signal(Err(TxError::CadTimeout));
                        continue;
                    }
                    // TX is also NOT cancel-safe — run the CAD gate and
                    // prepare_for_tx + tx to completion outside any select.
                    let result =
                        perform_tx(&mut lora, &mdltn, &mut tx_pkt, power_dbm, &tx_req).await;
                    ch.tx_done.signal(result);
                    continue 'outer; // chip is left in standby — re-prepare RX
                }
            }
        }
    }
}

// ─── ULCP device runner ──────────────────────────────────────────────────────

/// Radio settings applied at runtime by the ULCP session.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DeviceSettings {
    pub enabled: bool,
    pub freq_hz: u32,
    pub sf: SpreadingFactor,
    pub bw: Bandwidth,
    pub cr: CodingRate,
    pub power_dbm: i32,
}

/// Control handle for [`device_runner`]: latest-wins settings updates and
/// on-demand instantaneous-RSSI sampling. Place in a `static` next to the
/// [`Channels`].
pub struct DeviceControl<M: RawMutex> {
    settings: Signal<M, DeviceSettings>,
    rssi_req: Signal<M, ()>,
    rssi_resp: Signal<M, Result<i16, ()>>,
    shutdown: AtomicBool,
}

impl<M: RawMutex> DeviceControl<M> {
    pub const fn new() -> Self {
        Self {
            settings: Signal::new(),
            rssi_req: Signal::new(),
            rssi_resp: Signal::new(),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Put the radio into chip sleep and stop the runner.
    ///
    /// Terminal, and meant for the board's own power-off path: the
    /// runner parks forever once it observes this, so nothing after it
    /// can transmit or receive. The SX1262 keeps its own supply while
    /// the host MCU is in deep sleep, so skipping this would leave the
    /// chip receiving and dominate the sleeping board's current draw.
    ///
    /// The flag is what the runner acts on; the settings signal only
    /// exists to break it out of RX so it can look.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.settings.signal(DeviceSettings {
            enabled: false,
            freq_hz: profiles::DEFAULT.freq_khz * 1_000,
            sf: SpreadingFactor::_7,
            bw: Bandwidth::_125KHz,
            cr: CodingRate::_4_5,
            power_dbm: 0,
        });
    }

    /// Apply new settings. The runner picks them up at its next await
    /// point and rebuilds modulation/packet params.
    pub fn apply(&self, settings: DeviceSettings) {
        self.settings.signal(settings);
    }

    /// Request an instantaneous-RSSI sample from the runner. Pair with
    /// [`wait_rssi`](Self::wait_rssi). Only meaningful while the radio is in RX
    /// (i.e. enabled); the caller is responsible for that gating.
    pub fn request_rssi(&self) {
        self.rssi_resp.reset();
        self.rssi_req.signal(());
    }

    /// Await the RSSI sample requested via [`request_rssi`](Self::request_rssi),
    /// in dBm. `Err(())` means the read failed at the radio.
    pub async fn wait_rssi(&self) -> Result<i16, ()> {
        self.rssi_resp.wait().await
    }
}

impl<M: RawMutex> Default for DeviceControl<M> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RX strategy ─────────────────────────────────────────────────────────────

/// How the runner keeps the radio listening between frames.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RxStrategy {
    /// The chip sits in continuous RX. Works on every supported radio;
    /// costs the chip's full RX current around the clock.
    Continuous,
    /// SX126x-style `SetRxDutyCycle` preamble sniffing: the chip's own
    /// sequencer alternates short RX windows with sleep, sized against
    /// the sender's TX preamble so no frame is missed (see
    /// [`duty_cycle_rx_mode`] for the sizing rule). The MCU sees exactly
    /// the same DIO1 IRQs as in continuous mode.
    ///
    /// Only for chips whose driver implements `RxMode::DutyCycle`
    /// (SX126x, LR11xx). An SX127x rejects it with
    /// `DutyCycleUnsupported` at RX setup, which the runner's
    /// prepare-retry loop turns into a busy spin — SX127x boards must
    /// pass [`RxStrategy::Continuous`].
    PreambleDutyCycle,
}

/// One `SetRxDutyCycle` timer unit is 15.625 µs (24-bit registers).
const DUTY_CYCLE_UNIT_NS: u64 = 15_625;

/// Time the SX126x spends restarting its TCXO on each duty-cycle wake,
/// mirroring lora-phy's `BRD_TCXO_WAKEUP_TIME` (10 ms, not exported).
/// Each RX window is inflated by this much so the sniff window survives
/// even if the chip bills the TCXO settling time against `rx_time`; if
/// the chip instead settles before starting the window timer, the extra
/// is a small power cost, never a missed frame.
const TCXO_WAKEUP_NS: u64 = 10_000_000;

/// Pick the RX mode for a strategy at the given modulation settings.
///
/// The duty-cycle windows treat `rx_preamble` (the receiver's configured
/// acquisition length) as the number of preamble symbols that must land
/// inside a single RX window for reliable detection. With
/// `rx = rx_preamble + 1` symbols awake and
/// `sleep = tx_preamble - 2*rx_preamble - 1` symbols asleep, the worst
/// preamble alignment still puts `rx_preamble` symbols in one window
/// with a symbol to spare: a preamble that starts too late in one
/// window meets the next one after `sleep + rx` symbols, leaving
/// `tx_preamble - sleep - rx - 1 >= rx_preamble` symbols of it to hear.
/// (The chip's detector actually fires on fewer symbols than the full
/// acquisition length, so the real margin is wider.)
///
/// Falls back to continuous RX when the TX preamble is too short to
/// leave any sleep (`tx_preamble < 2*rx_preamble + 2` — the LR1110's
/// 16-symbol acquisition against the 32-symbol MeshCore preamble lands
/// here) or when a window overflows the chip's 24-bit timers.
pub fn duty_cycle_rx_mode(
    sf: SpreadingFactor,
    bw: Bandwidth,
    rx_preamble: u16,
    tx_preamble: u16,
) -> RxMode {
    let det = rx_preamble as u64;
    let tx = tx_preamble as u64;
    if tx < 2 * det + 2 {
        return RxMode::Continuous;
    }
    let rx_syms = det + 1;
    let sleep_syms = tx - 2 * det - 1;

    // Symbol duration in nanoseconds: t_sym = 2^SF / BW.
    let t_sym_ns = (1u64 << sf_value(sf)) * 1_000_000_000 / bw_value_hz(bw) as u64;
    let rx_time = (rx_syms * t_sym_ns + TCXO_WAKEUP_NS) / DUTY_CYCLE_UNIT_NS;
    let sleep_time = sleep_syms * t_sym_ns / DUTY_CYCLE_UNIT_NS;
    if rx_time > 0x00FF_FFFF || sleep_time > 0x00FF_FFFF || sleep_time == 0 {
        return RxMode::Continuous;
    }
    RxMode::DutyCycle(DutyCycleParams {
        rx_time: rx_time as u32,
        sleep_time: sleep_time as u32,
    })
}

/// Convert a bandwidth in Hz (the ULCP representation)
/// to the lora-phy enum. Returns `None` for unsupported values.
pub fn bandwidth_from_hz(hz: u32) -> Option<Bandwidth> {
    Some(match hz {
        7_810 => Bandwidth::_7KHz,
        10_420 => Bandwidth::_10KHz,
        15_630 => Bandwidth::_15KHz,
        20_830 => Bandwidth::_20KHz,
        31_250 => Bandwidth::_31KHz,
        41_670 => Bandwidth::_41KHz,
        62_500 => Bandwidth::_62KHz,
        125_000 => Bandwidth::_125KHz,
        250_000 => Bandwidth::_250KHz,
        500_000 => Bandwidth::_500KHz,
        _ => return None,
    })
}

/// Convert a numeric spreading factor (5-12) to the lora-phy enum.
pub fn spreading_factor_from_u8(sf: u8) -> Option<SpreadingFactor> {
    Some(match sf {
        5 => SpreadingFactor::_5,
        6 => SpreadingFactor::_6,
        7 => SpreadingFactor::_7,
        8 => SpreadingFactor::_8,
        9 => SpreadingFactor::_9,
        10 => SpreadingFactor::_10,
        11 => SpreadingFactor::_11,
        12 => SpreadingFactor::_12,
        _ => return None,
    })
}

/// Convert a coding-rate denominator (5 for 4/5 .. 8 for 4/8) to the
/// lora-phy enum.
pub fn coding_rate_from_denom(cr: u8) -> Option<CodingRate> {
    Some(match cr {
        5 => CodingRate::_4_5,
        6 => CodingRate::_4_6,
        7 => CodingRate::_4_7,
        8 => CodingRate::_4_8,
        _ => return None,
    })
}

/// Device variant of [`runner`]: same RX/TX state machine, but the
/// modulation parameters, frequency, and power come from an
/// [`DeviceControl`] at runtime instead of being fixed at spawn.
///
/// The radio starts idle (in standby) until the first enabled settings
/// arrive. While disabled, TX requests stay queued — the ULCP session
/// rejects transmits with `STATUS_INVALID_STATE` before they reach
/// this queue, so nothing accumulates in practice.
///
/// `rx_strategy` picks how the radio listens between frames; the
/// duty-cycle windows are recomputed from each new set of modulation
/// settings (see [`duty_cycle_rx_mode`]).
///
/// Cancellation-safety analysis is identical to [`runner`]: only
/// `wait_for_irq` and the two channel/signal waits are cancelled by the
/// select; IRQ processing and TX always run to completion.
pub async fn device_runner<RK, DLY, M, const RX: usize, const TX: usize>(
    mut lora: LoRa<RK, DLY>,
    ch: &'static Channels<M, RX, TX>,
    ctl: &'static DeviceControl<M>,
    rx_preamble: u16,
    tx_preamble: u16,
    rx_strategy: RxStrategy,
) -> !
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
    M: RawMutex,
{
    use embassy_futures::select::{Either4, select4};

    let mut rx_buf = [0u8; MAX_PAYLOAD];
    let mut settings: Option<DeviceSettings> = None;

    // Wait for new settings while idle, failing any RSSI request that
    // arrives meanwhile so the requester never hangs. The session gates
    // RSSI reads on `enabled`, but enable→RX is asynchronous (and the
    // params-failure path below idles while the session still believes
    // the radio is enabled), so a request can race into an idle window.
    async fn wait_settings_while_idle<M: RawMutex>(ctl: &DeviceControl<M>) -> DeviceSettings {
        loop {
            match select(ctl.settings.wait(), ctl.rssi_req.wait()).await {
                Either::First(new_settings) => return new_settings,
                Either::Second(()) => ctl.rssi_resp.signal(Err(())),
            }
        }
    }

    'reconfigure: loop {
        // Idle until we have an enabled configuration.
        let active = loop {
            // Checked here rather than in the selects below because every
            // path that observes new settings passes through this loop:
            // `shutdown` wakes an RX-parked runner with a settings signal,
            // and an already-idle one leaves `wait_settings_while_idle`
            // for the same reason.
            if ctl.shutdown.load(Ordering::Acquire) {
                let _ = lora.sleep(false).await;
                loop {
                    core::future::pending::<()>().await;
                }
            }
            match settings {
                Some(current) if current.enabled => break current,
                _ => settings = Some(wait_settings_while_idle(ctl).await),
            }
        };

        // Build params for the active settings. The session validates
        // values before applying, so failures here indicate a
        // chip-level rejection: drop back to idle until new settings
        // arrive rather than hot-looping.
        let params = (|| {
            let mdltn =
                lora.create_modulation_params(active.sf, active.bw, active.cr, active.freq_hz)?;
            let rx_pkt = lora.create_rx_packet_params(
                rx_preamble,
                false, // explicit header
                MAX_PAYLOAD as u8,
                true,  // CRC on
                false, // IQ normal
                &mdltn,
            )?;
            let tx_pkt = lora.create_tx_packet_params(tx_preamble, false, true, false, &mdltn)?;
            Ok::<_, RadioError>((mdltn, rx_pkt, tx_pkt))
        })();
        let Ok((mdltn, rx_pkt, mut tx_pkt)) = params else {
            settings = Some(wait_settings_while_idle(ctl).await);
            continue 'reconfigure;
        };

        let rx_mode = match rx_strategy {
            RxStrategy::Continuous => RxMode::Continuous,
            RxStrategy::PreambleDutyCycle => {
                duty_cycle_rx_mode(active.sf, active.bw, rx_preamble, tx_preamble)
            }
        };

        'rx: loop {
            if lora.prepare_for_rx(rx_mode, &mdltn, &rx_pkt).await.is_err() {
                continue;
            }
            if lora.start_rx().await.is_err() {
                continue;
            }

            let mut rx_in_progress = false;
            let mut rx_gate_strikes: u8 = 0;
            loop {
                match select4(
                    lora.wait_for_irq(),
                    ch.tx.receive(),
                    ctl.settings.wait(),
                    ctl.rssi_req.wait(),
                )
                .await
                {
                    Either4::First(Ok(())) => {
                        // Same discipline as `runner`: process_irq_event
                        // must run to completion, then clear interrupts.
                        let irq_result = lora.process_irq_event().await;
                        let _ = lora.clear_irq_status().await;

                        match irq_result {
                            Ok(Some(IrqState::Done)) => {
                                if let Ok((len, status)) =
                                    lora.get_rx_result(&rx_pkt, &mut rx_buf).await
                                {
                                    let mut data: Vec<u8, MAX_PAYLOAD> = Vec::new();
                                    let _ = data.extend_from_slice(&rx_buf[..len as usize]);
                                    let info = RxInfo {
                                        len: len as usize,
                                        rssi: status.rssi,
                                        snr: Snr::from_decibels(status.snr as i8),
                                        lqi: None,
                                        origin: RxOrigin::Air,
                                    };
                                    if ch.rx.try_send(RxFrame { data, info }).is_ok() {
                                        ch.rx_waker.wake();
                                    }
                                }
                                continue 'rx;
                            }
                            Ok(Some(IrqState::PreambleReceived)) => {
                                rx_in_progress = true; // gate TX until the frame resolves
                                continue;
                            }
                            Ok(_) => continue,
                            Err(_) => continue 'rx,
                        }
                    }
                    Either4::First(Err(_)) => continue 'rx,
                    Either4::Second(tx_req) => {
                        // Same RX gate as `runner`: don't tear down an
                        // in-flight reception for the CAD gate.
                        if rx_in_progress && rx_gate_strikes < RX_GATE_MAX_STRIKES {
                            rx_gate_strikes += 1;
                            ch.tx_done.signal(Err(TxError::CadTimeout));
                            continue;
                        }
                        let result =
                            perform_tx(&mut lora, &mdltn, &mut tx_pkt, active.power_dbm, &tx_req)
                                .await;
                        ch.tx_done.signal(result);
                        continue 'rx;
                    }
                    Either4::Third(new_settings) => {
                        settings = Some(new_settings);
                        continue 'reconfigure;
                    }
                    Either4::Fourth(()) => {
                        // Sample the instantaneous channel RSSI. Like TX,
                        // `get_rssi` runs to completion outside the select
                        // (only `wait_for_irq` and the channel/signal waits are
                        // cancel-safe). In continuous RX the read does not
                        // disturb reception, so we stay in the inner loop. In
                        // duty-cycled RX the SPI traffic wakes the chip out of
                        // its sniff sequence (and the sample is only
                        // meaningful if it caught an RX window), so re-arm RX
                        // afterwards.
                        let sample = lora.get_rssi().await.map_err(|_| ());
                        ctl.rssi_resp.signal(sample);
                        if rx_mode != RxMode::Continuous {
                            continue 'rx;
                        }
                    }
                }
            }
        }
    }
}

// ─── Parameter builders ───────────────────────────────────────────────────────

/// Build modulation and packet parameters for a vetted PHY profile.
///
/// The private sync word the profiles specify is not set here: it is
/// fixed at `LoRa::new` time by `enable_public_network = false`. CRC is
/// on and IQ normal, matching what MeshCore transmits.
///
/// `rx_preamble_symbols` stays a caller decision because it is a
/// property of the receiving chip rather than the profile: 8 suffices on
/// an SX126x, while the LR1110 needs the full transmitted length to
/// detect reliably.
///
/// Returns `(ModulationParams, rx_PacketParams, tx_PacketParams)`.
pub fn profile_params<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
    profile: &PhyProfile,
    rx_preamble_symbols: u16,
) -> Result<(ModulationParams, PacketParams, PacketParams), RadioError>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    let sf = spreading_factor_from_u8(profile.sf).ok_or(RadioError::UnavailableSpreadingFactor)?;
    let bw = bandwidth_from_hz(profile.bw_hz).ok_or(RadioError::UnavailableBandwidth)?;
    let cr = coding_rate_from_denom(profile.cr_denom).ok_or(RadioError::InvalidConfiguration)?;
    build_params(
        lora,
        sf,
        bw,
        cr,
        profile.freq_khz * 1_000,
        rx_preamble_symbols,
        profile.tx_preamble_symbols,
    )
}

/// Shared helper: build modulation + RX/TX packet params.
///
/// `rx_preamble`: LoRa preamble length configured for RX packet parameters.
/// `tx_preamble`: LoRa preamble length configured for TX packet parameters.
fn build_params<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
    sf: SpreadingFactor,
    bw: Bandwidth,
    cr: CodingRate,
    frequency_hz: u32,
    rx_preamble: u16,
    tx_preamble: u16,
) -> Result<(ModulationParams, PacketParams, PacketParams), RadioError>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    let mdltn = lora.create_modulation_params(sf, bw, cr, frequency_hz)?;

    let rx_pkt = lora.create_rx_packet_params(
        rx_preamble,
        false, // explicit (variable-length) header
        MAX_PAYLOAD as u8,
        true,  // CRC on
        false, // IQ normal
        &mdltn,
    )?;

    let tx_pkt = lora.create_tx_packet_params(
        tx_preamble,
        false, // explicit header
        true,  // CRC on
        false, // IQ normal
        &mdltn,
    )?;

    Ok((mdltn, rx_pkt, tx_pkt))
}

// ─── Airtime estimate ─────────────────────────────────────────────────────────

/// Conservative upper bound on LoRa on-air time in milliseconds.
///
/// Uses the standard LoRa airtime formula: explicit header, CRC on, CR 4/5,
/// auto-LDRO. Call this with `MAX_PAYLOAD` to get the worst-case figure for
/// `t_frame_ms`.
pub fn airtime_ms(sf: SpreadingFactor, bw: Bandwidth, payload_bytes: usize) -> u32 {
    let sf_val: u32 = sf_value(sf);
    let bw_hz: u64 = bw_value_hz(bw) as u64;

    // Symbol duration in microseconds: t_sym = 2^SF / BW.
    let t_sym_us: u64 = (1u64 << sf_val) * 1_000_000 / bw_hz;

    // LDRO required when t_sym > 16 ms (SF11/BW125 or SF12/BW125 or BW250).
    let ldro: u64 = if t_sym_us > 16_000 { 1 } else { 0 };

    // Number of payload symbols (LoRa spec, CR=4/5, explicit header, CRC on).
    let sf = sf_val as i64;
    let pl = payload_bytes as i64;
    let num = (8 * pl - 4 * sf + 44 + 20 - 16 * ldro as i64).max(0);
    let denom = 4 * (sf - 2 * ldro as i64);
    // Manual ceiling division for i64 (div_ceil is still nightly-only).
    let ceil = (num + denom - 1) / denom;
    let n_pay_sym = 8 + ceil * 5; // CR 4/5 → 5 coding overhead per ceiling block

    // Total: preamble (8 symbols + 4.25, approximated as 12) + payload.
    let total_sym = 12 + n_pay_sym as u64;

    ((total_sym * t_sym_us) / 1_000) as u32
}

/// The spreading factor as its numeric value (5–12).
fn sf_value(sf: SpreadingFactor) -> u32 {
    match sf {
        SpreadingFactor::_5 => 5,
        SpreadingFactor::_6 => 6,
        SpreadingFactor::_7 => 7,
        SpreadingFactor::_8 => 8,
        SpreadingFactor::_9 => 9,
        SpreadingFactor::_10 => 10,
        SpreadingFactor::_11 => 11,
        SpreadingFactor::_12 => 12,
    }
}

/// The bandwidth in Hz.
fn bw_value_hz(bw: Bandwidth) -> u32 {
    match bw {
        Bandwidth::_7KHz => 7_810,
        Bandwidth::_10KHz => 10_420,
        Bandwidth::_15KHz => 15_630,
        Bandwidth::_20KHz => 20_830,
        Bandwidth::_31KHz => 31_250,
        Bandwidth::_41KHz => 41_670,
        Bandwidth::_62KHz => 62_500,
        Bandwidth::_125KHz => 125_000,
        Bandwidth::_250KHz => 250_000,
        Bandwidth::_500KHz => 500_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_duty_cycle(mode: RxMode) -> DutyCycleParams {
        match mode {
            RxMode::DutyCycle(params) => params,
            _ => panic!("expected duty-cycle RX mode"),
        }
    }

    /// The shipping SX1262 configuration: 8-symbol acquisition against
    /// the 32-symbol MeshCore TX preamble at SF7/125 kHz.
    #[test]
    fn duty_cycle_sf7_bw125() {
        let params = expect_duty_cycle(duty_cycle_rx_mode(
            SpreadingFactor::_7,
            Bandwidth::_125KHz,
            8,
            32,
        ));
        // t_sym = 1.024 ms. RX window: 9 symbols + the 10 ms TCXO
        // wake = 19.216 ms; sleep: 15 symbols = 15.36 ms — in units of
        // 15.625 µs.
        assert_eq!(params.rx_time, 1229);
        assert_eq!(params.sleep_time, 983);
    }

    /// Worst-case preamble alignment still lands a full acquisition
    /// window inside one RX slot, across the whole parameter space.
    #[test]
    fn duty_cycle_worst_case_alignment_is_covered() {
        for (det, tx) in [(4u64, 16u64), (8, 32), (8, 20), (12, 32)] {
            if tx < 2 * det + 2 {
                continue;
            }
            let rx_syms = det + 1;
            let sleep_syms = tx - 2 * det - 1;
            // A preamble that starts too late for one window (more than
            // `rx - det` symbols in) meets the next window after
            // `sleep + rx` symbols and must still have `det` symbols
            // left to hear. The sizing is boundary-exact: the two
            // coverage paths overlap by the one extra RX symbol, and
            // the real-world margin comes from the chip's detector
            // firing on fewer than `det` symbols plus the TCXO
            // inflation of the RX window.
            assert!(sleep_syms + rx_syms + det <= tx);
        }
    }

    /// The LR1110's 16-symbol acquisition leaves no sleep budget
    /// against a 32-symbol preamble: fall back to continuous RX.
    #[test]
    fn duty_cycle_falls_back_when_preamble_too_short() {
        assert!(matches!(
            duty_cycle_rx_mode(SpreadingFactor::_7, Bandwidth::_125KHz, 16, 32),
            RxMode::Continuous
        ));
    }

    /// The slowest vetted modulation must not overflow the chip's
    /// 24-bit window timers.
    #[test]
    fn duty_cycle_slowest_modulation_fits_timers() {
        let params = expect_duty_cycle(duty_cycle_rx_mode(
            SpreadingFactor::_12,
            Bandwidth::_7KHz,
            8,
            32,
        ));
        assert!(params.rx_time <= 0x00FF_FFFF);
        assert!(params.sleep_time <= 0x00FF_FFFF);
        assert!(params.sleep_time > 0);
    }
}
