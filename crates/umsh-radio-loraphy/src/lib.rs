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

use core::task::{Context, Poll};

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::RawMutex,
    channel::Channel,
    signal::Signal,
    waitqueue::AtomicWaker,
};
use heapless::Vec;
use lora_phy::{
    LoRa, RxMode,
    mod_params::{
        Bandwidth, CodingRate, ModulationParams, PacketParams, RadioError, SpreadingFactor,
    },
    mod_traits::{IrqState, RadioKind},
};
use umsh_hal::{RxInfo, Snr, TxError, TxOptions};

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
}

// ─── Channels ────────────────────────────────────────────────────────────────

/// Shared state between [`Sx1262Radio`] and [`runner`]. Place in a `static`.
///
/// - `M`: raw mutex type (e.g. `ThreadModeRawMutex` for single-core Embassy).
/// - `RX`: depth of the receive queue.
/// - `TX`: depth of the transmit-request queue.
pub struct Channels<M: RawMutex, const RX: usize, const TX: usize> {
    pub rx:       Channel<M, RxFrame, RX>,
    pub tx:       Channel<M, TxRequest, TX>,
    pub tx_done:  Signal<M, Result<(), RadioError>>,
    pub rx_waker: AtomicWaker,
}

impl<M: RawMutex, const RX: usize, const TX: usize> Channels<M, RX, TX> {
    pub const fn new() -> Self {
        Self {
            rx:       Channel::new(),
            tx:       Channel::new(),
            tx_done:  Signal::new(),
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
        _options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        let mut frame_data: Vec<u8, MAX_PAYLOAD> = Vec::new();
        frame_data
            .extend_from_slice(data)
            .map_err(|_| TxError::Io(RadioError::PayloadSizeUnexpected(data.len())))?;
        self.ch.tx.send(TxRequest { data: frame_data }).await;
        self.ch.tx_done.wait().await.map_err(TxError::Io)
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
                                };
                                if ch.rx.try_send(RxFrame { data, info }).is_ok() {
                                    ch.rx_waker.wake();
                                }
                            }
                            continue 'outer; // re-prepare RX for the next frame
                        }
                        Ok(_) => continue, // PreambleReceived / no-op: stay in RX
                        Err(_) => continue 'outer, // CRC / header error: full re-prepare
                    }
                }
                Either::First(Err(_)) => continue 'outer,
                Either::Second(tx_req) => {
                    // TX is also NOT cancel-safe — run prepare_for_tx + tx
                    // to completion outside any select.
                    let result = async {
                        lora.prepare_for_tx(&mdltn, &mut tx_pkt, power_dbm, &tx_req.data)
                            .await?;
                        lora.tx().await
                    }
                    .await;
                    ch.tx_done.signal(result);
                    continue 'outer; // tx() leaves the chip in standby — re-prepare RX
                }
            }
        }
    }
}

// ─── Parameter builders ───────────────────────────────────────────────────────

/// Frequency used by default for UMSH in the 915 MHz ISM band.
pub const UMSH_FREQUENCY_HZ: u32 = 915_000_000;

/// Build the default modulation and packet parameters for UMSH bringup.
///
/// SF7 / BW125 / CR4-5 at 915 MHz.
///
/// Returns `(ModulationParams, rx_PacketParams, tx_PacketParams)`.
pub fn default_params<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
) -> Result<(ModulationParams, PacketParams, PacketParams), RadioError>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    build_params(lora, SpreadingFactor::_7, Bandwidth::_125KHz, UMSH_FREQUENCY_HZ, 8, 8)
}

/// MeshCore US band frequency (confirmed from MeshCore source).
pub const MESHCORE_US_FREQUENCY_HZ: u32 = 910_525_000;

/// Build modulation + packet parameters matching MeshCore US (915 MHz band).
///
/// Sourced from MeshCore's `CustomSX1262.h` and `platformio.ini`:
///   - 910.525 MHz / SF7 / BW62.5 kHz / CR4/5
///   - 16-symbol TX preamble (matched against MeshCore nodes in the field)
///   - Private sync word 0x1424 (via `enable_public_network = false` in LoRa::new)
///   - CRC enabled, IQ normal
///
/// Returns `(ModulationParams, rx_PacketParams, tx_PacketParams)`.
pub fn meshcore_us_params<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
) -> Result<(ModulationParams, PacketParams, PacketParams), RadioError>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    // RX preamble detection uses 8 symbols (MeshCore TX sends 16; the SX1262
    // starts decoding after detecting the minimum threshold, so setting 8 here
    // is correct and robust against slight timing variations).
    build_params(lora, SpreadingFactor::_7, Bandwidth::_62KHz, MESHCORE_US_FREQUENCY_HZ, 8, 16)
}

/// Shared helper: build modulation + RX/TX packet params.
///
/// `rx_preamble`: minimum preamble symbols for RX detection.
/// `tx_preamble`: preamble symbols emitted on TX.
fn build_params<RK, DLY>(
    lora: &mut LoRa<RK, DLY>,
    sf: SpreadingFactor,
    bw: Bandwidth,
    frequency_hz: u32,
    rx_preamble: u16,
    tx_preamble: u16,
) -> Result<(ModulationParams, PacketParams, PacketParams), RadioError>
where
    RK: RadioKind,
    DLY: embedded_hal_async::delay::DelayNs,
{
    let mdltn = lora.create_modulation_params(sf, bw, CodingRate::_4_5, frequency_hz)?;

    let rx_pkt = lora.create_rx_packet_params(
        rx_preamble,
        false,         // explicit (variable-length) header
        MAX_PAYLOAD as u8,
        true,          // CRC on
        false,         // IQ normal
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
    let sf_val: u32 = match sf {
        SpreadingFactor::_5  =>  5,
        SpreadingFactor::_6  =>  6,
        SpreadingFactor::_7  =>  7,
        SpreadingFactor::_8  =>  8,
        SpreadingFactor::_9  =>  9,
        SpreadingFactor::_10 => 10,
        SpreadingFactor::_11 => 11,
        SpreadingFactor::_12 => 12,
    };
    let bw_hz: u64 = match bw {
        Bandwidth::_7KHz   =>    7_810,
        Bandwidth::_10KHz  =>   10_420,
        Bandwidth::_15KHz  =>   15_630,
        Bandwidth::_20KHz  =>   20_830,
        Bandwidth::_31KHz  =>   31_250,
        Bandwidth::_41KHz  =>   41_670,
        Bandwidth::_62KHz  =>   62_500,
        Bandwidth::_125KHz =>  125_000,
        Bandwidth::_250KHz =>  250_000,
        Bandwidth::_500KHz =>  500_000,
    };

    // Symbol duration in microseconds: t_sym = 2^SF / BW.
    let t_sym_us: u64 = (1u64 << sf_val) * 1_000_000 / bw_hz;

    // LDRO required when t_sym > 16 ms (SF11/BW125 or SF12/BW125 or BW250).
    let ldro: u64 = if t_sym_us > 16_000 { 1 } else { 0 };

    // Number of payload symbols (LoRa spec, CR=4/5, explicit header, CRC on).
    let sf = sf_val as i64;
    let pl = payload_bytes as i64;
    let num   = (8 * pl - 4 * sf + 44 + 20 - 16 * ldro as i64).max(0);
    let denom = 4 * (sf - 2 * ldro as i64);
    // Manual ceiling division for i64 (div_ceil is still nightly-only).
    let ceil = (num + denom - 1) / denom;
    let n_pay_sym = 8 + ceil * 5; // CR 4/5 → 5 coding overhead per ceiling block

    // Total: preamble (8 symbols + 4.25, approximated as 12) + payload.
    let total_sym = 12 + n_pay_sym as u64;

    ((total_sym * t_sym_us) / 1_000) as u32
}
