//! The panel: the menu, the shared renderer, and the attention policy
//! that decides when the panel is lit.
//!
//! A board with no panel builds `ui_headless.rs` in its place. Both give
//! the rest of the firmware the same few calls—[`gesture`],
//! [`farewell`], [`boot_gesture`]—so the button and the power-off path
//! need no feature gates of their own.

use super::*;
use board::display::{Brightness, Display, brightness_from_permille};
use umsh_ulcp::stats::Counter;
use umsh_ulcp_runtime::driver::Setting;
use umsh_ux_display_tracker::attention::{
    Attention, AttentionConfig, DisplayKind, HoldReason, Transition,
};
use umsh_ux_display_tracker::menu::{MenuItem, MenuItems, ToggleId, UiEffect, UiModel};

// ─── What the rest of the firmware sees ──────────────────────────────────

/// Hand a resolved gesture to the menu: single advances, double selects,
/// a released long hold goes back.
#[cfg(not(feature = "input-gate"))]
pub(crate) async fn gesture(event: ButtonEvent) {
    let input = match event {
        ButtonEvent::Single => UiInput::Forward,
        ButtonEvent::Double => UiInput::Select,
        ButtonEvent::Long => UiInput::Backward,
        ButtonEvent::VeryLong | ButtonEvent::Triple | ButtonEvent::Quad => return,
    };
    UI_INPUT_CH.send(input).await;
}

/// Say goodbye on the panel and switch it off, dropping `Vext` where the
/// display task owns it. Bounded, so a wedged panel cannot strand a board
/// that is turning off.
// The Pager begins and ends it apart.
#[cfg_attr(feature = "board-tlora-pager", allow(dead_code))]
pub(crate) async fn farewell(cause: ShutdownCause) {
    begin_farewell(cause);
    end_farewell().await;
}

/// Starts the panel's farewell, so that it says what is happening while
/// the rest of the board shuts down.
pub(crate) fn begin_farewell(cause: ShutdownCause) {
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(cause);
}

/// Waits for the farewell begun to finish with the panel off.
pub(crate) async fn end_farewell() {
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;
}

/// The pairing window is on the menu here, so holding the button through
/// boot asks for nothing.
#[cfg(not(feature = "board-tlora-pager"))]
pub(crate) async fn boot_gesture(_button: &mut Input<'static>) -> bool {
    false
}

/// Motion has its own notification and never extends an active/dim timeout.
async fn motion_wake() {
    #[cfg(all(feature = "board-tlora-pager", not(feature = "motion-qualification")))]
    loop {
        let wake = pager::motion::SERVICE.display_wake.wait().await;
        if pager::motion::SERVICE.accept(wake, Instant::now().as_millis()) {
            return;
        }
    }
    #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
    core::future::pending::<()>().await;
}

/// Completes when the battery indicator has moved far enough to redraw.
/// Never completes on a board that cannot read its battery.
async fn battery_ui_changed() {
    #[cfg(feature = "battery-telemetry")]
    BATTERY_UI_CHANGED.wait().await;
    #[cfg(not(feature = "battery-telemetry"))]
    core::future::pending::<()>().await
}

// ─── The menu and its renderer ───────────────────────────────────────────

/// What this board's menu can do.
///
/// Everything the class defines—minus the receiver entries on a board
/// with no GNSS fitted, where both come out and the submenu that led to
/// them goes with them. Clearing bonds is a menu item rather than a
/// bare gesture because the confirmation page in front of it is what
/// makes it safe.
fn board_menu_items() -> MenuItems {
    #[allow(unused_mut)]
    let mut items = MenuItems::all();
    #[cfg(not(feature = "board-tlora-pager"))]
    {
        items = items.without(MenuItem::Battery);
    }
    #[cfg(not(feature = "gnss"))]
    {
        items = items
            .without(MenuItem::GnssToggle)
            .without(MenuItem::ShareLocation);
    }
    #[cfg(not(feature = "wifi"))]
    {
        items = items
            .without(MenuItem::WifiToggle)
            .without(MenuItem::WifiNetworks);
    }
    #[cfg(not(feature = "ble"))]
    {
        items = items
            .without(MenuItem::BluetoothToggle)
            .without(MenuItem::StartPairing)
            .without(MenuItem::ClearBonds);
    }
    #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
    {
        items = items.without(MenuItem::MotionWake);
    }
    items
}

/// Which device-domain switch a menu toggle names.
const fn ulcp_setting(id: ToggleId) -> Setting {
    match id {
        ToggleId::Radio => Setting::Radio,
        ToggleId::Wifi => Setting::Wifi,
        ToggleId::Bluetooth => Setting::Bluetooth,
        ToggleId::Gnss => Setting::Gnss,
        ToggleId::MotionWake => Setting::MotionWake,
        ToggleId::ShareLocation => Setting::ShareLocation,
        ToggleId::Forwarding => Setting::Forwarding,
    }
}

/// Backing store for the identity page's two strings, which
/// [`screen::StatusModel`] only borrows.
#[derive(Default)]
struct IdentityText {
    hint: heapless::String<8>,
    address: heapless::String<{ umsh_core::base58::ENCODED_LEN }>,
}

impl IdentityText {
    /// The running node's address, or empty before bring-up.
    fn current() -> Self {
        use core::fmt::Write as _;
        let Some(key) = device_node::node_key() else {
            return Self::default();
        };
        let mut text = Self::default();
        let _ = write!(
            text.hint,
            "{}",
            umsh_core::NodeHint::from_public_key(&umsh_core::PublicKey(key))
        );
        for digit in umsh_core::base58::encode(&key) {
            let _ = text.address.push(digit as char);
        }
        text
    }

    fn model(&self) -> Option<screen::IdentityModel<'_>> {
        if self.address.is_empty() {
            return None;
        }
        Some(screen::IdentityModel {
            hint: &self.hint,
            address: &self.address,
        })
    }
}

/// Everything the shared renderer draws that is not menu state.
///
/// The device name is passed in rather than read here: reading it is
/// async and the model borrows it, so the display task snapshots it once
/// per frame and lends it to this.
fn ui_status<'a>(name: &'a DeviceName, identity: &'a IdentityText) -> screen::StatusModel<'a> {
    #[cfg(feature = "wifi")]
    let wifi = Some(wifi::ui_snapshot());
    #[cfg(not(feature = "wifi"))]
    let wifi: Option<umsh_ux_display_tracker::wifi::WifiMenu> = None;
    // Zero is "never sampled", which is also all a board that cannot read
    // its battery ever has to say.
    #[cfg(feature = "battery-telemetry")]
    let mv = BATTERY_MV.load(Ordering::Acquire);
    #[cfg(not(feature = "battery-telemetry"))]
    let mv = 0;
    // No charger telemetry reaches the MCU on the ADC boards, so their
    // charge stays unknown and the indicator says nothing about charging
    // rather than asserting the pack is discharging; the PMIC boards know
    // which way current flows, and unknown (no cell, or before the first
    // sample) draws nothing rather than a guess.
    #[cfg(not(feature = "battery-telemetry"))]
    let battery = screen::BatteryIndicator {
        level_percent: None,
        charge: None,
    };
    #[cfg(feature = "battery-telemetry")]
    let battery = {
        let level = BATTERY_LEVEL.load(Ordering::Acquire);
        screen::BatteryIndicator {
            level_percent: (level != 0xFF).then_some(level),
            charge: match BATTERY_CHARGE.load(Ordering::Acquire) {
                1 => Some(ChargeClass::Discharging),
                2 => Some(ChargeClass::Charging),
                3 => Some(ChargeClass::Charged),
                4 => Some(ChargeClass::NotCharging),
                _ => None,
            },
        }
    };
    let bluetooth = ble::panel();
    screen::StatusModel {
        wifi,
        pairing_highlight: (Instant::now().as_millis() / screen::PAIRING_BLINK_MS) % 2 == 0,
        firmware_version: env!("GIT_DESCRIBE"),
        device_name: core::str::from_utf8(name).unwrap_or(DEFAULT_DEVICE_NAME),
        // Boards with no receiver report nothing on both positioning
        // switches rather than a guess—and neither is on their menu.
        settings: screen::SettingsModel {
            radio: device_node::radio_enabled(),
            #[cfg(all(feature = "board-tlora-pager", not(feature = "motion-qualification")))]
            motion_wake: Some(pager::motion::SERVICE.control().display()),
            #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
            motion_wake: None,
            wifi: wifi.map(|wifi| wifi.enabled),
            bluetooth: bluetooth.enabled,
            #[cfg(not(feature = "gnss"))]
            gnss: None,
            #[cfg(not(feature = "gnss"))]
            share_location: None,
            #[cfg(feature = "gnss")]
            gnss: Some(umsh_ulcp_runtime::gnss::enabled()),
            #[cfg(feature = "gnss")]
            share_location: Some(umsh_ulcp_runtime::gnss::policy().update_identity),
            forwarding: Some(device_node::repeater_enabled()),
        },
        #[cfg(feature = "gnss")]
        gnss_fix: umsh_ulcp_runtime::gnss::has_fix(),
        #[cfg(not(feature = "gnss"))]
        gnss_fix: false,
        identity: identity.model(),
        battery,
        battery_mv: (mv != 0).then_some(mv),
        #[cfg(feature = "board-tlora-pager")]
        battery_details: pager::battery_diagnostics(),
        #[cfg(not(feature = "board-tlora-pager"))]
        battery_details: None,
        queued: Some(QUEUED_FRAMES.load(Ordering::Acquire)),
        link: bluetooth.link,
        bonds: bluetooth.bonds,
        pairing: bluetooth.pairing,
        stats: ui_stats(),
        // Boards without `CAP_TIME` never know what time it is and must
        // not indicate one. On the rest, `None` whenever the device does
        // not know, which the renderer draws as nothing at all—there
        // is deliberately no fallback, because a placeholder would be an
        // indication of the current time.
        #[cfg(not(feature = "wall-clock"))]
        clock: None,
        #[cfg(feature = "wall-clock")]
        clock: umsh_hal::wall_clock::local_hhmm().map(|(hour, minute)| screen::ClockModel {
            hour,
            minute,
            hour24: umsh_hal::wall_clock::hour24(),
        }),
    }
}

/// Radio activity for the stats page.
///
/// Sampled when a frame is drawn rather than pushed: the counters move
/// with every frame on the air, and a redraw per frame would burn the
/// panel's power budget reporting numbers nobody is looking at.
fn ui_stats() -> screen::StatsModel {
    // The same ledger the host reads over ULCP, so a reset from the phone
    // clears this page too. `rx_frames` is everything the radio handed up,
    // UMSH or not, which is what the page has always meant.
    screen::StatsModel {
        tx_frames: STATS.get(Counter::TxPackets),
        rx_frames: STATS.get(Counter::RxPackets) + STATS.get(Counter::RxNonUmsh),
        rx_accepted: STATS.get(Counter::RxAccepted),
        forwarded: STATS.get(Counter::Forwarded),
        tx_power_dbm: device_node::tx_power_dbm(),
        // The ledger's scale is 0-65535 for 0-100%; the page shows tenths
        // of a percent, which is the range a tracker lives in.
        duty_permille: (u32::from(DUTY_LEDGER.usage(Instant::now().as_millis())) * 1_000 / 65_535)
            as u16,
    }
}

#[cfg(feature = "display-st7796")]
const DISPLAY_LAYOUT: screen::Layout = screen::Layout::TFT_480X222;
#[cfg(feature = "display-st7789")]
const DISPLAY_LAYOUT: screen::Layout = screen::Layout::TFT_320X240;
#[cfg(any(feature = "display-ssd1306", feature = "display-sh1106"))]
const DISPLAY_LAYOUT: screen::Layout = screen::Layout::OLED_128X64;

/// The communicator's splash, drawn in the frame's full color: the logo in
/// its orange, and the version in the face the interface sets body text in,
/// which is already in flash.
#[cfg(all(feature = "communicator", feature = "display-st7796"))]
const SPLASH: &umsh_splash::Splash = &umsh_splash::Splash::TFT_480X222;
#[cfg(all(feature = "communicator", feature = "display-st7789"))]
const SPLASH: &umsh_splash::Splash = &umsh_splash::Splash::TFT_320X240;

/// Render the current page. Best-effort—a display error just leaves the
/// panel stale; it never blocks the protocol paths.
async fn render_frame(display: &mut Display, model: &UiModel, status: &screen::StatusModel<'_>) {
    screen::render_frame(display, &DISPLAY_LAYOUT, model, status);
    let _ = display.flush().await;
}

/// Center a short message, keeping the header so the battery stays
/// readable while the board is busy saying something else.
async fn render_message(
    display: &mut Display,
    status: &screen::StatusModel<'_>,
    title: &str,
    detail: &str,
) {
    screen::render_message(display, &DISPLAY_LAYOUT, status, title, detail);
    let _ = display.flush().await;
}

/// Completes when the receiver gains or loses a fix, so the panel can
/// redraw its position glyph. Never completes on a board without GNSS.
async fn gnss_ui_changed() {
    #[cfg(feature = "gnss")]
    umsh_ulcp_runtime::gnss::fix_ui_changed().await;
    #[cfg(not(feature = "gnss"))]
    core::future::pending::<()>().await
}

/// Redraw an awake panel at the next clock or pairing animation boundary.
/// A sleeping panel never arms a timer and catches up when woken.
async fn display_tick(awake: bool, pairing_delay: Option<u64>) {
    if !awake {
        core::future::pending::<()>().await;
    }
    let clock_delay = umsh_hal::wall_clock::millis_to_next_minute().map(u64::from);
    match clock_delay.into_iter().chain(pairing_delay).min() {
        Some(millis) => Timer::after_millis(millis).await,
        None => core::future::pending().await,
    }
}

/// Draw the boot-only artwork without needing journals, identity, or radio.
/// Return its original visible deadline so later ownership handoff cannot
/// blank the panel or restart the splash dwell.
pub(crate) async fn show_boot_splash(
    display: &mut Display,
) -> umsh_ux_display_tracker::boot::BootSplash {
    // The color panels' backlights provide immediate startup feedback,
    // including while the panel resets and its first frame is being drawn.
    #[cfg(not(feature = "display-dcs"))]
    let _ = display.set_display_on(false).await;
    let _ = display.set_brightness(Brightness::NORMAL).await;
    let mut splash = umsh_ux_display_tracker::boot::BootSplash::new();
    #[cfg(feature = "communicator")]
    SPLASH.render(
        display.color(),
        umsh_ux_communicator::font::MEDIUM.face(communicator::BOARD.metrics.body),
        env!("GIT_DESCRIBE"),
    );
    #[cfg(not(feature = "communicator"))]
    screen::render_splash(display, &DISPLAY_LAYOUT, env!("GIT_DESCRIBE"));
    for attempt in 1..=3 {
        match display.flush().await {
            Ok(()) => {
                if display.set_display_on(true).await.is_ok() {
                    let now = Instant::now().as_millis();
                    splash.shown(now);
                    println!("display: boot logo visible at {now} ms (attempt {attempt})");
                    return splash;
                }
            }
            Err(error) => {
                debug_log(format_args!(
                    "display: boot splash transfer failed: {error:?}"
                ));
            }
        }
        Timer::after_millis(20).await;
    }
    // Never time a partially written frame as a successful splash.
    splash.dismiss();
    BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
    splash
}

/// Owns the OLED, the `Vext` rail that powers it (where one exists—
/// on a PMIC board the panel's rail drops in the shutdown path
/// instead), and the display attention policy.
///
/// The panel is emissive, so attention lapsing actually turns it off:
/// full brightness for 20 s, a second-long fall into the dim warning,
/// dark at 30 s. It stays lit for as long as a pairing window is open,
/// because its PIN is the only place that number is shown.
#[embassy_executor::task]
pub(crate) async fn display_task(
    mut display: Display,
    #[cfg(feature = "board-tlora-pager")] mut splash: umsh_ux_display_tracker::boot::BootSplash,
    #[cfg(feature = "vext")] mut vext: Vext,
) {
    #[cfg(feature = "board-tlora-pager")]
    let pager_capture_epoch = input_gate::interactive().await;
    let mut model = UiModel::new(board_menu_items());
    #[cfg(not(feature = "board-tlora-pager"))]
    let mut splash = show_boot_splash(&mut display).await;
    if !splash.is_active() {
        render_frame(
            &mut display,
            &model,
            &ui_status(&device_name_snapshot().await, &IdentityText::current()),
        )
        .await;
        let _ = display.set_display_on(true).await;
    }
    let mut attention = Attention::new(
        DisplayKind::Emissive,
        AttentionConfig::EMISSIVE,
        Instant::now().as_millis(),
    );
    #[cfg(feature = "board-tlora-pager")]
    input_gate::shown(pager_capture_epoch);

    #[cfg(feature = "board-tlora-pager")]
    let mut was_alerting = false;

    loop {
        #[cfg(feature = "board-tlora-pager")]
        pager::set_battery_details_visible(
            attention.accepts_redraw()
                && !splash.is_active()
                && !pager::alert::active()
                && matches!(
                    model.page(),
                    umsh_ux_display_tracker::menu::Page::Detail(
                        MenuItem::BatteryCharge
                            | MenuItem::BatteryCapacity
                            | MenuItem::BatteryGauge
                    )
                ),
        );
        // The name changes rarely but every frame this pass might draw
        // needs it, so it is snapshotted once and lent out; the rest of
        // the status is rebuilt at each draw. The identity is rendered
        // the same way, and is empty until node bring-up runs.
        let name = device_name_snapshot().await;
        let identity = IdentityText::current();

        // Asserting the hold is itself a wake, and on a dark panel that
        // wake is the whole event: a pairing window a host opened has no
        // press behind it. So the transition is carried into this pass
        // rather than dropped. Dropping it leaves the policy believing the
        // panel is lit while the glass stays dark, and every later wake is
        // then a no-op against an already-active state—the panel cannot
        // be brought back at all until a lapse puts the two back in
        // agreement.
        let now = Instant::now().as_millis();
        let mut transition =
            attention.set_hold(HoldReason::Pairing, ble::pairing_window_open(), now);
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            transition = attention
                .set_hold(HoldReason::Alert, active, now)
                .or(transition);
            if active && splash.dismiss() {
                BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            }
            if was_alerting && !active {
                transition = attention.wake(now).or(transition);
            }
        }
        SCREEN_FADED.store(attention.is_faded(), Ordering::Release);

        // A panel about to be powered on needs a frame drawn into it
        // first, whether or not an arm below asks for one.
        let mut redraw = transition.is_some();

        let lapse = async {
            match splash.next_deadline().or_else(|| attention.next_deadline()) {
                // A hold pins the panel awake, so there is no deadline to
                // wait for—but a wake it just produced still has to be
                // applied. Falling through to the arm below is what gets
                // this pass to the power-on; blocking here would hold it
                // until some unrelated event arrived.
                None if transition.is_some() => {}
                Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                None => core::future::pending().await,
            }
        };
        match select4(
            UI_INPUT_CH.receive(),
            select3(
                // All three are "content moved, redraw if the panel is
                // already lit"; they differ only in what they do to the
                // model, so they share an arm.
                select3(
                    UI_REFRESH.wait(),
                    select(battery_ui_changed(), gnss_ui_changed()),
                    display_tick(
                        attention.accepts_redraw(),
                        if splash.is_active() {
                            None
                        } else {
                            screen::pairing_animation_delay_ms(
                                &model,
                                &ui_status(&name, &identity),
                                Instant::now().as_millis(),
                            )
                        },
                    ),
                ),
                async {
                    #[cfg(feature = "board-tlora-pager")]
                    {
                        match select(UI_NOTICE.wait(), pager::alert::DISPLAY_CHANGED.wait()).await {
                            Either::First(notice) => Some(notice),
                            Either::Second(()) => None,
                        }
                    }
                    #[cfg(not(feature = "board-tlora-pager"))]
                    Some(UI_NOTICE.wait().await)
                },
                select(UI_WAKE.wait(), motion_wake()),
            ),
            DISPLAY_SHUTDOWN.wait(),
            select(UI_SPLASH_DISMISS.wait(), lapse),
        )
        .await
        {
            // Do not skip the rest of this pass: it may own the alert's
            // one-shot Woke transition and still need to light the panel.
            #[cfg(feature = "board-tlora-pager")]
            Either4::First(_) if pager::alert::active() => redraw = true,
            Either4::First(input) => {
                let now = Instant::now().as_millis();
                transition = attention.wake(now).or(transition);
                redraw = true;
                #[cfg(feature = "wifi")]
                let effect = model.apply_with_wifi(input, &wifi::ui_snapshot());
                #[cfg(not(feature = "wifi"))]
                let effect = model.apply(input);
                match effect {
                    Some(UiEffect::SelectWifiNetwork(name)) => {
                        #[cfg(feature = "wifi")]
                        {
                            let mut selected = umsh_ulcp_device::net::NetworkName::default();
                            if selected.set(name.as_bytes()).is_ok() {
                                INPUT_CH.send(InEvent::SelectWifiNetwork(selected)).await;
                                redraw = false;
                            }
                        }
                        #[cfg(not(feature = "wifi"))]
                        {
                            let _ = name;
                            model.set_notice(UiNotice::NetworkUnavailable);
                        }
                    }
                    Some(UiEffect::CheckIn) => {
                        device_node::request_beacon(device_node::BeaconTrigger::Button);
                        model.set_notice(UiNotice::CheckInRequested);
                    }
                    Some(UiEffect::StartPairing) => ble::request_pairing(),
                    Some(UiEffect::ClearBonds) => ble::request_clear_bonds(),
                    Some(UiEffect::Toggle(id)) => {
                        // Applied by the ULCP session, so the property, an
                        // attached host and the saved snapshot all see the
                        // same flip.
                        //
                        // Which is also why the frame is *not* drawn here.
                        // The session runs in another task and has not
                        // moved the value yet, so a redraw on this pass
                        // would push the old state back onto the panel and
                        // call it fresh. The frame that shows the flip is
                        // the one `UI_REFRESH` will drive out of
                        // `publish_dev_domain`. Nothing else on screen
                        // needed this press: a notice only ever lives on
                        // the status page, and a toggle entry never does.
                        INPUT_CH.send(InEvent::Toggle(ulcp_setting(id))).await;
                        redraw = false;
                    }
                    None => {}
                }
            }
            Either4::Second(event) => match event {
                // Content the user did not ask for: redraw if the panel
                // is already lit, but never light it. That rule is what
                // keeps a battery sample from waking a board left on a
                // desk every minute.
                Either3::First(_) => redraw = true,
                Either3::Second(None) => redraw = true,
                Either3::Second(Some(notice)) => {
                    model.set_notice(notice);
                    transition = attention.wake(Instant::now().as_millis()).or(transition);
                    redraw = true;
                }
                // A wake on its own changes no content—a lit panel is
                // already showing the truth, and the events that do
                // change something raise `UI_REFRESH` alongside this.
                Either3::Third(Either::First(())) => {
                    transition = attention.wake(Instant::now().as_millis()).or(transition);
                    redraw = transition.is_some();
                }
                Either3::Third(Either::Second(())) => {
                    if attention.is_lapsed() {
                        transition = attention
                            .wake_from_motion(Instant::now().as_millis())
                            .or(transition);
                        redraw = transition.is_some();
                        debug_log(format_args!("motion: display wake"));
                    } else {
                        debug_log(format_args!(
                            "motion: consumed while {:?}",
                            attention.state()
                        ));
                    }
                }
            },
            Either4::Third(_) => {
                render_message(
                    &mut display,
                    &ui_status(&name, &identity),
                    "Powering off",
                    if cfg!(feature = "board-tlora-pager") {
                        ""
                    } else {
                        "hold to wake"
                    },
                )
                .await;
                let _ = display.set_display_on(true).await;
                Timer::after_millis(1_200).await;
                let _ = display.set_display_on(false).await;
                #[cfg(feature = "vext")]
                vext.disable();
                DISPLAY_SHUTDOWN_DONE.signal(());
                core::future::pending::<()>().await;
            }
            Either4::Fourth(event) => {
                if matches!(event, Either::First(())) && splash.dismiss() {
                    redraw = true;
                } else {
                    transition = attention.poll(Instant::now().as_millis()).or(transition);
                }
            }
        }

        redraw |= splash.poll(Instant::now().as_millis());
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            let now = Instant::now().as_millis();
            transition = attention
                .set_hold(HoldReason::Alert, active, now)
                .or(transition);
            if active {
                splash.dismiss();
                BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            } else if was_alerting {
                transition = attention.wake(now).or(transition);
            }
        }
        #[cfg(feature = "board-tlora-pager")]
        let pager_capture_epoch = if matches!(transition, Some(Transition::Woke)) {
            Some(input_gate::interactive().await)
        } else {
            None
        };
        match transition {
            Some(Transition::Lapsed) => {
                // Waking always lands on the status page rather than on
                // whatever was abandoned here.
                model.go_home();
                #[cfg(feature = "board-tlora-pager")]
                let before_display_off = input_gate::activity();
                let off = display.set_display_on(false).await;
                #[cfg(feature = "board-tlora-pager")]
                if off.is_ok() {
                    input_gate::dark(before_display_off);
                }
                #[cfg(not(feature = "board-tlora-pager"))]
                let _ = off;
                redraw = false;
            }
            // One step of the fall, not the whole of it: the policy sends
            // one of these per ramp step and says where between the
            // panel's two contrasts to sit. Nothing is redrawn—a
            // contrast write leaves the framebuffer alone, which is what
            // makes a fade affordable on a panel that redraws only on
            // events.
            Some(Transition::Dimming) => {
                let _ = display
                    .set_brightness(brightness_from_permille(attention.brightness_permille()))
                    .await;
                redraw = false;
            }
            Some(Transition::Woke) | None => {}
        }

        #[cfg(feature = "board-tlora-pager")]
        {
            redraw |= pager::alert::active() || was_alerting;
        }
        if redraw && !splash.is_active() && attention.accepts_redraw() {
            let status = ui_status(&name, &identity);
            if let Some(wifi) = &status.wifi {
                model.refresh_wifi(wifi);
            }
            #[cfg(feature = "board-tlora-pager")]
            if pager::alert::active() {
                screen::render_message(
                    &mut display,
                    &DISPLAY_LAYOUT,
                    &status,
                    "Locate alert",
                    "Press any key to stop.",
                );
                if pager::alert::bright() {
                    display.invert();
                }
                let _ = display.flush().await;
            } else {
                render_frame(&mut display, &model, &status).await;
            }
            #[cfg(not(feature = "board-tlora-pager"))]
            render_frame(&mut display, &model, &status).await;
            if BOOT_SPLASH_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = attention.wake(Instant::now().as_millis());
            }
        }
        // Ordered after the redraw so the panel never lights on a stale
        // frame.
        if matches!(transition, Some(Transition::Woke)) {
            let _ = display.set_brightness(Brightness::NORMAL).await;
            let on = display.set_display_on(true).await;
            #[cfg(feature = "board-tlora-pager")]
            if on.is_ok() {
                input_gate::shown(pager_capture_epoch.unwrap());
            }
            #[cfg(not(feature = "board-tlora-pager"))]
            let _ = on;
        }
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            if active || was_alerting {
                let _ = display
                    .set_brightness(if active && pager::alert::bright() {
                        Brightness::ALERT
                    } else {
                        Brightness::NORMAL
                    })
                    .await;
            }
            was_alerting = active;
        }
    }
}
