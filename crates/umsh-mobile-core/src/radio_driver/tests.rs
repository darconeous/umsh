//! The driver core against a soft device: the production device session
//! behind an HDLC-Lite link, with an explicit clock on both sides.

use tokio::sync::oneshot;
use umsh_ulcp::{Frame, hdlc, ids::prop};
use umsh_ulcp_device::{RadioRxInfo, TxOutcome};
use umsh_ulcp_simdev::soft::{SoftDevice, SoftPlatform};
use umsh_ulcp_simdev::{DutyLedger, SimulatedPlatform, full_config};

use super::core::{
    Command, DriverCore, Effect, Event, FATAL_FAULT_BUDGET_REFILL_MS, HOST_RELEASE_TIMEOUT_MS,
    MAXIMUM_FRAMES_AWAITING_MESH_SESSION, MAXIMUM_RAW_TRANSMIT_BUSY_RETRIES,
    MESH_FRAME_LIFETIME_MS, Now, RAW_TRANSMIT_BUSY_RETRY_MS, RAW_TRANSMIT_TIMEOUT_MS,
};
use super::{
    MobileRadioError, MobileRadioPhase, MobileRadioProblem, MobileRadioStateRecord,
    MobileRadioTransportPhase, MobileRadioTransportStateRecord,
};
use crate::{
    MobileMeshOutboundFrameRecord, MobileUlcpSession, UlcpDfuMode, UlcpHostOwnership,
    UlcpRadioSettingsRecord,
};

const HOST_KEY: [u8; 32] = [7; 32];
/// Any wall-clock reading will do; it only stamps.
const WALL_EPOCH_MS: u64 = 1_800_000_000_000;

/// A driver core and a soft device joined by a link that can be cut.
struct Bench {
    core: DriverCore,
    device: SoftDevice<SimulatedPlatform>,
    decoder: hdlc::Decoder<{ umsh_ulcp::gatt::MAX_FRAME }>,
    clock_ms: u64,
    /// Whether frames the core sends reach the device, and its answers
    /// come back.
    carrying: bool,
    /// Whether the device's answers are kept back until `deliver`, so a
    /// test can act while an exchange is still open.
    holding: bool,
    /// Everything the core asked for besides frames, in order.
    effects: Vec<Effect>,
    /// The raw transaction IDs of the frames the core sent, in order.
    raw_sends: Vec<u8>,
    /// The last frame the core sent, whether or not it reached the device.
    last_sent: Option<Vec<u8>>,
}

impl Bench {
    fn new() -> Self {
        let duty = Box::leak(Box::new(DutyLedger::new()));
        // A radio with a device identity of its own, as a provisioned one
        // has.
        let mut platform = SimulatedPlatform::new();
        platform.store_identity(Some(&[1; 32])).unwrap();
        Self {
            core: DriverCore::new(MobileUlcpSession::new()),
            device: SoftDevice::new(full_config(duty, None), platform),
            decoder: hdlc::Decoder::new(),
            clock_ms: 0,
            carrying: false,
            holding: false,
            effects: Vec::new(),
            raw_sends: Vec::new(),
            last_sent: None,
        }
    }

    /// A bench with this phone's key and a mesh session, attached to its
    /// radio as the phone's own.
    fn attached() -> Self {
        let mut bench = Self::new();
        bench.handle(Event::HostKey(Some(HOST_KEY)));
        bench.handle(Event::MeshSessionArrived);
        bench.connect(true);
        assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
        bench.effects.clear();
        bench
    }

    fn now(&self) -> Now {
        Now {
            monotonic_ms: self.clock_ms,
            wall_ms: WALL_EPOCH_MS + self.clock_ms,
        }
    }

    fn state(&self) -> &MobileRadioStateRecord {
        self.core.state()
    }

    fn handle(&mut self, event: Event) {
        let effects = self.core.handle(event, self.now());
        self.carry(effects);
    }

    fn report(&mut self, phase: MobileRadioTransportPhase) {
        self.handle(Event::Transport(MobileRadioTransportStateRecord {
            phase,
            name: Some("Bench radio".to_owned()),
            link_id: Some("bench".to_owned()),
            problem: None,
        }));
    }

    /// Connect the transport to the device and report the link ready.
    fn connect(&mut self, bound_radio: bool) {
        self.report(MobileRadioTransportPhase::Connecting);
        self.device.attach();
        self.carrying = true;
        // The device's session-reset notice, the first frame of a session.
        self.deliver();
        self.handle(Event::LinkReady { bound_radio });
    }

    /// Cut the link: nothing more reaches the device or comes back.
    fn cut(&mut self) {
        self.carrying = false;
        self.device.detach();
    }

    /// Run the clock forward, acting on each deadline as it passes.
    fn advance(&mut self, ms: u64) {
        let until = self.clock_ms + ms;
        while let Some(deadline) = self.core.next_deadline()
            && deadline <= until
        {
            self.clock_ms = self.clock_ms.max(deadline);
            let effects = self.core.tick(self.now());
            self.carry(effects);
        }
        self.clock_ms = until;
    }

    /// Carry out effects: frames go to the device, the rest are recorded,
    /// and whatever the device answers comes back, until both are quiet.
    fn carry(&mut self, effects: Vec<Effect>) {
        let mut batch = effects;
        loop {
            for effect in batch.drain(..) {
                match effect {
                    Effect::Send {
                        frame,
                        raw_transaction_id,
                    } => {
                        if let Some(id) = raw_transaction_id {
                            self.raw_sends.push(id);
                        }
                        self.last_sent = Some(frame.clone());
                        if self.carrying {
                            let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
                            let length = hdlc::encode_frame(&frame, &mut wire).unwrap();
                            self.device.ingest(&wire[..length], self.clock_ms).unwrap();
                        }
                    }
                    other => self.effects.push(other),
                }
            }
            if self.holding {
                return;
            }
            let answers = self.take_answers();
            if answers.is_empty() {
                return;
            }
            for frame in answers {
                batch.extend(self.core.handle(Event::LinkReceived(frame), self.now()));
            }
        }
    }

    /// Hand the core whatever the device has said since.
    fn deliver(&mut self) {
        let answers = self.take_answers();
        for frame in answers {
            let effects = self.core.handle(Event::LinkReceived(frame), self.now());
            self.carry(effects);
        }
    }

    fn take_answers(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(wire) = self.device.take_outbound() {
            if !self.carrying {
                continue;
            }
            for byte in wire {
                if let Some(frame) = self.decoder.push(byte) {
                    frames.push(frame.unwrap().to_vec());
                }
            }
        }
        frames
    }

    /// Send one mesh frame through the driver.
    fn transmit(&mut self, id: u64) {
        self.handle(Event::MeshOutbound(vec![MobileMeshOutboundFrameRecord {
            id,
            data: vec![0x40, 0x01, 0x02, 0x03, id as u8],
            nocca: false,
            power_dbm: None,
        }]));
    }

    /// What the device made of its transmission in flight.
    fn complete_tx(&mut self, outcome: TxOutcome) {
        self.device.complete_tx(outcome, self.clock_ms);
        self.deliver();
    }

    fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    fn completions(&mut self) -> Vec<(u64, bool)> {
        self.take_effects()
            .into_iter()
            .filter_map(|effect| match effect {
                Effect::MeshComplete {
                    frame_id,
                    transmitted,
                } => Some((frame_id, transmitted)),
                _ => None,
            })
            .collect()
    }

    fn invalidations(&self) -> Vec<bool> {
        self.effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Invalidate { retry } => Some(*retry),
                _ => None,
            })
            .collect()
    }

    /// Fault the link as a transport would, and report what the transport
    /// does about it.
    fn fault_and_report(&mut self, next: MobileRadioTransportPhase) -> bool {
        self.effects.clear();
        self.handle(Event::LinkFault(MobileRadioProblem::InvalidFrame));
        let retry = self.invalidations() == [true];
        self.cut();
        self.report(next);
        retry
    }

    fn command<T>(
        &mut self,
        command: impl FnOnce(oneshot::Sender<Result<T, MobileRadioError>>) -> Command,
    ) -> oneshot::Receiver<Result<T, MobileRadioError>> {
        let (reply, outcome) = oneshot::channel();
        self.handle(Event::Command(command(reply)));
        outcome
    }
}

fn outcome<T: std::fmt::Debug>(
    mut receiver: oneshot::Receiver<Result<T, MobileRadioError>>,
) -> Option<Result<T, MobileRadioError>> {
    receiver.try_recv().ok()
}

#[test]
fn attaching_claims_the_bound_radio_and_turns_its_transmitter_on() {
    let mut bench = Bench::new();
    bench.handle(Event::HostKey(Some(HOST_KEY)));
    bench.connect(true);
    let state = bench.state();
    assert_eq!(state.phase, MobileRadioPhase::Attached);
    assert_eq!(state.host, UlcpHostOwnership::Ours);
    assert!(state.provisioning.as_ref().unwrap().phy_enabled);
    assert_eq!(state.name.as_deref(), Some("Simulated test device"));
    assert!(state.device_key.is_some());
    assert!(state.battery.is_some() && state.battery_read_at_ms.is_some());
    assert_eq!(state.problem, None);
    let effects = bench.take_effects();
    assert!(effects.contains(&Effect::ResetFraming));
    assert_eq!(
        effects.iter().filter(|e| **e == Effect::DidAttach).count(),
        1,
        "the attach is announced once"
    );
    assert!(effects.contains(&Effect::DidReportName("Simulated test device".to_owned())));
}

#[test]
fn a_radio_the_app_is_not_bound_to_is_left_awaiting_a_host() {
    let mut bench = Bench::new();
    bench.handle(Event::HostKey(Some(HOST_KEY)));
    bench.connect(false);
    assert_eq!(bench.state().phase, MobileRadioPhase::AwaitingHost);
    assert_eq!(bench.state().host, UlcpHostOwnership::Unclaimed);
    assert!(
        !bench
            .take_effects()
            .iter()
            .any(|effect| matches!(effect, Effect::DidReportName(_))),
        "only the bound radio's name is the transport's to keep"
    );

    let claimed = bench.command(|reply| Command::Claim { reply });
    assert_eq!(outcome(claimed), Some(Ok(())));
    assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
    assert_eq!(bench.state().host, UlcpHostOwnership::Ours);
}

#[test]
fn a_host_key_that_arrives_after_the_attach_starts_it_again() {
    let mut bench = Bench::new();
    bench.connect(true);
    assert_eq!(bench.state().phase, MobileRadioPhase::AwaitingHost);
    let refused = bench.command(|reply| Command::Claim { reply });
    assert_eq!(
        outcome(refused),
        Some(Err(MobileRadioError::IdentityUnavailable))
    );

    bench.handle(Event::HostKey(Some(HOST_KEY)));
    assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
    assert_eq!(bench.state().host, UlcpHostOwnership::Ours);
}

#[test]
fn a_raw_transmit_completes_when_the_radio_reports_it() {
    let mut bench = Bench::attached();
    bench.device.defer_tx();
    bench.transmit(1);
    bench.transmit(2);
    assert_eq!(bench.raw_sends.len(), 1, "one transmit in flight at a time");
    assert!(
        bench.completions().is_empty(),
        "taking a frame is not sending it"
    );

    bench.complete_tx(TxOutcome::Sent);
    assert_eq!(bench.completions(), [(1, true)]);
    assert_eq!(
        bench.raw_sends.len(),
        2,
        "the next goes once the first is done"
    );
    bench.complete_tx(TxOutcome::Sent);
    assert_eq!(bench.completions(), [(2, true)]);
    assert_eq!(bench.device.take_transmitted().len(), 2);
}

#[test]
fn a_busy_radio_is_tried_again_after_a_pause_and_then_given_up() {
    let mut bench = Bench::attached();
    bench.device.defer_tx();
    bench.transmit(1);
    bench.complete_tx(TxOutcome::ChannelBusy);
    assert!(bench.completions().is_empty());
    assert_eq!(bench.raw_sends.len(), 1, "not again at once");
    bench.transmit(2);
    assert_eq!(bench.raw_sends.len(), 1, "nor because another frame came");
    bench.advance(RAW_TRANSMIT_BUSY_RETRY_MS - 1);
    assert_eq!(bench.raw_sends.len(), 1);
    bench.advance(1);
    assert_eq!(bench.raw_sends.len(), 2);
    bench.complete_tx(TxOutcome::Sent);
    assert_eq!(bench.completions(), [(1, true)]);

    // The second frame is in flight now, and never finds the channel free.
    assert_eq!(bench.raw_sends.len(), 3);
    for _ in 0..MAXIMUM_RAW_TRANSMIT_BUSY_RETRIES {
        bench.complete_tx(TxOutcome::ChannelBusy);
        bench.advance(RAW_TRANSMIT_BUSY_RETRY_MS);
    }
    bench.complete_tx(TxOutcome::ChannelBusy);
    assert_eq!(bench.completions(), [(2, false)]);
    assert_eq!(bench.state().problem, Some(MobileRadioProblem::RadioBusy));
    assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
}

#[test]
fn the_watchdog_fails_a_silent_transmit_and_its_late_answer_keeps_the_link() {
    let mut bench = Bench::attached();
    bench.device.defer_tx();
    bench.transmit(1);
    bench.advance(RAW_TRANSMIT_TIMEOUT_MS - 1);
    assert!(bench.completions().is_empty());
    bench.advance(1);
    assert_eq!(bench.completions(), [(1, false)]);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::TransmissionUnreported)
    );

    // The radio answers about the frame already given up on: late, not
    // wrong. The link stays, and the next frame goes.
    bench.complete_tx(TxOutcome::Sent);
    assert!(bench.invalidations().is_empty());
    assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
    assert!(bench.completions().is_empty());
    bench.transmit(2);
    bench.complete_tx(TxOutcome::Sent);
    assert_eq!(bench.completions(), [(2, true)]);
}

#[test]
fn a_failed_write_releases_the_mesh_session_and_keeps_the_link() {
    let mut bench = Bench::attached();
    bench.device.defer_tx();
    bench.transmit(1);
    let transaction = bench.raw_sends[0];
    let problem = MobileRadioProblem::Transport {
        domain: "bench".to_owned(),
        code: 14,
    };
    bench.handle(Event::LinkWritesFailed {
        raw_transaction_ids: vec![transaction],
        problem: problem.clone(),
    });
    assert!(bench.take_effects().contains(&Effect::MeshFailOutbound));
    assert_eq!(bench.state().problem, Some(problem));
    assert_eq!(bench.state().phase, MobileRadioPhase::Attached);

    // The radio's answer to the abandoned transmit is ignored, and the next
    // frame goes.
    bench.complete_tx(TxOutcome::Sent);
    assert!(bench.invalidations().is_empty());
    bench.transmit(2);
    assert_eq!(bench.raw_sends.len(), 2);
}

#[test]
fn frames_taken_while_the_link_is_down_wait_for_the_next_attach() {
    let mut bench = Bench::new();
    bench.handle(Event::HostKey(Some(HOST_KEY)));
    bench.handle(Event::MeshSessionArrived);
    bench.transmit(1);
    assert!(bench.raw_sends.is_empty());
    bench.connect(true);
    assert_eq!(bench.raw_sends.len(), 1);
    assert_eq!(bench.completions(), [(1, true)]);
}

#[test]
fn a_mesh_frame_waits_out_a_control_exchange() {
    let mut bench = Bench::attached();
    bench.holding = true;
    let refreshed = bench.command(|reply| Command::Refresh {
        call: Box::new(|session| session.refresh()),
        reply,
    });
    bench.transmit(1);
    assert!(
        bench.raw_sends.is_empty(),
        "nothing starts under a control exchange"
    );
    assert!(bench.completions().is_empty());

    bench.holding = false;
    bench.deliver();
    assert!(matches!(outcome(refreshed), Some(Ok(_))));
    assert_eq!(bench.raw_sends.len(), 1, "it goes once the exchange ends");
    assert_eq!(bench.completions(), [(1, true)]);
    assert_eq!(bench.state().problem, None);
}

#[test]
fn a_frame_the_mesh_session_gave_up_on_is_not_transmitted() {
    let mut bench = Bench::new();
    bench.handle(Event::HostKey(Some(HOST_KEY)));
    bench.handle(Event::MeshSessionArrived);
    bench.transmit(1);
    bench.advance(MESH_FRAME_LIFETIME_MS - 1);
    bench.transmit(2);
    bench.advance(1);
    bench.connect(true);
    assert_eq!(bench.raw_sends.len(), 1, "only the frame still waited for");
    assert_eq!(bench.completions(), [(2, true)]);
}

#[test]
fn a_write_failure_reported_after_the_link_went_changes_nothing() {
    let mut bench = Bench::attached();
    bench.handle(Event::LinkFault(MobileRadioProblem::InvalidFrame));
    bench.effects.clear();
    bench.handle(Event::LinkWritesFailed {
        raw_transaction_ids: vec![1],
        problem: MobileRadioProblem::Transport {
            domain: "bench".to_owned(),
            code: 14,
        },
    });
    assert!(bench.take_effects().is_empty());
    assert_eq!(bench.state().phase, MobileRadioPhase::Reconnecting);
    assert_eq!(bench.state().problem, None);
}

#[test]
fn a_silent_radio_fails_its_callers_and_the_link_at_the_deadline() {
    let mut bench = Bench::attached();
    bench.carrying = false;
    let refreshed = bench.command(|reply| Command::Refresh {
        call: Box::new(|session| session.refresh()),
        reply,
    });
    let joined = bench.command(|reply| Command::Refresh {
        call: Box::new(|session| session.refresh_positioning()),
        reply,
    });
    let configured = bench.command(|reply| Command::Configure {
        call: Box::new(|session| session.refresh()),
        reply,
    });
    assert_eq!(
        outcome(configured),
        Some(Err(MobileRadioError::OperationInProgress))
    );
    bench.advance(super::core::CONTROL_DEADLINE_MS - 1);
    assert!(bench.invalidations().is_empty());
    bench.advance(1);
    assert_eq!(outcome(refreshed), Some(Err(MobileRadioError::TimedOut)));
    assert_eq!(outcome(joined), Some(Err(MobileRadioError::TimedOut)));
    assert_eq!(bench.invalidations(), [true]);
    assert_eq!(bench.state().phase, MobileRadioPhase::Reconnecting);
    assert_eq!(bench.state().problem, None);
}

#[test]
fn the_fault_budget_runs_out_and_the_failure_outlasts_the_disconnect() {
    let mut bench = Bench::attached();
    for _ in 0..2 {
        assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
        assert_eq!(bench.state().phase, MobileRadioPhase::Reconnecting);
        bench.connect(true);
        assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
    }
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Disconnecting));
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::InvalidFrame)
    );
    bench.report(MobileRadioTransportPhase::Idle);
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::InvalidFrame),
        "the disconnect after a failure does not overwrite it"
    );

    // A new attempt clears it, and a deliberate one refills the budget.
    bench.handle(Event::ResetRecoveryBudget);
    bench.report(MobileRadioTransportPhase::Connecting);
    assert_eq!(bench.state().phase, MobileRadioPhase::Connecting);
    assert_eq!(bench.state().problem, None);
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
}

#[test]
fn a_transport_that_cannot_reconnect_shows_the_failure_and_spends_nothing() {
    let mut bench = Bench::attached();
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Idle));
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::InvalidFrame)
    );
    // Both retries are still there.
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Idle));
}

#[test]
fn a_transport_that_comes_straight_back_still_spends_a_retry() {
    let mut bench = Bench::attached();
    for retry in [true, true, false] {
        bench.effects.clear();
        bench.handle(Event::LinkFault(MobileRadioProblem::InvalidFrame));
        assert_eq!(bench.invalidations(), [retry]);
        // Ready again, with no report of the reconnect in between.
        bench.cut();
        bench.device.attach();
        bench.carrying = true;
        bench.deliver();
        bench.handle(Event::LinkReady { bound_radio: true });
        assert_eq!(bench.state().phase, MobileRadioPhase::Attached);
    }
}

#[test]
fn a_transport_with_a_failure_of_its_own_shows_that_and_spends_nothing() {
    let mut bench = Bench::attached();
    bench.handle(Event::LinkFault(MobileRadioProblem::InvalidFrame));
    bench.cut();
    let its_own = MobileRadioProblem::Transport {
        domain: "bench".to_owned(),
        code: 7,
    };
    bench.handle(Event::Transport(MobileRadioTransportStateRecord {
        phase: MobileRadioTransportPhase::Failed,
        name: Some("Bench radio".to_owned()),
        link_id: Some("bench".to_owned()),
        problem: Some(its_own.clone()),
    }));
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(bench.state().problem, Some(its_own));
    // Both retries are still there.
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Idle));
}

#[test]
fn a_reconnect_the_transport_started_before_hearing_of_the_failure_does_not_hide_it() {
    let mut bench = spent();
    // The transport saw the link drop and set off to reconnect before the
    // invalidation, which offers no retry, reached it.
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::InvalidFrame)
    );
    // Then it hears, and calls the reconnect off.
    bench.report(MobileRadioTransportPhase::Disconnecting);
    bench.report(MobileRadioTransportPhase::Idle);
    assert_eq!(bench.state().phase, MobileRadioPhase::Failed);
    assert_eq!(
        bench.state().problem,
        Some(MobileRadioProblem::InvalidFrame)
    );
    // Something new still clears it.
    bench.report(MobileRadioTransportPhase::Connecting);
    assert_eq!(bench.state().phase, MobileRadioPhase::Connecting);
    assert_eq!(bench.state().problem, None);
}

#[test]
fn faults_while_one_settles_are_the_same_incident() {
    let mut bench = Bench::attached();
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Disconnecting));
    bench.effects.clear();
    bench.handle(Event::LinkFault(MobileRadioProblem::Disconnected));
    assert!(bench.invalidations().is_empty());
    assert_eq!(bench.state().phase, MobileRadioPhase::Reconnecting);
    // Only the one retry is spent.
    bench.report(MobileRadioTransportPhase::Reconnecting);
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Idle));
}

/// A bench whose fault budget is spent, attached again.
fn spent() -> Bench {
    let mut bench = Bench::attached();
    for _ in 0..2 {
        assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
        bench.connect(true);
    }
    bench
}

#[test]
fn an_attach_that_held_earns_the_next_fault_a_fresh_budget() {
    let mut bench = spent();
    bench.advance(FATAL_FAULT_BUDGET_REFILL_MS);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
    bench.connect(true);
    assert!(bench.fault_and_report(MobileRadioTransportPhase::Reconnecting));
}

#[test]
fn an_attach_that_failed_early_is_the_same_incident() {
    let mut bench = spent();
    bench.advance(FATAL_FAULT_BUDGET_REFILL_MS - 1);
    assert!(!bench.fault_and_report(MobileRadioTransportPhase::Idle));
}

#[test]
fn an_ordinary_disconnect_fails_waiters_and_mesh_frames() {
    let mut bench = Bench::attached();
    bench.carrying = false;
    let refreshed = bench.command(|reply| Command::Refresh {
        call: Box::new(|session| session.refresh()),
        reply,
    });
    // Queued behind the refresh.
    bench.transmit(1);
    bench.effects.clear();
    bench.handle(Event::Transport(MobileRadioTransportStateRecord {
        phase: MobileRadioTransportPhase::Idle,
        name: Some("Bench radio".to_owned()),
        link_id: None,
        problem: Some(MobileRadioProblem::Disconnected),
    }));
    assert_eq!(
        outcome(refreshed),
        Some(Err(MobileRadioError::RadioUnavailable))
    );
    assert!(bench.take_effects().contains(&Effect::MeshFailOutbound));
    let state = bench.state();
    assert_eq!(state.phase, MobileRadioPhase::Idle);
    assert_eq!(state.problem, Some(MobileRadioProblem::Disconnected));
    assert_eq!(state.host, UlcpHostOwnership::Unknown);
    assert!(state.provisioning.is_none() && state.battery.is_none());
    assert_eq!(
        bench.core.next_deadline(),
        None,
        "nothing armed survives the link"
    );
}

#[test]
fn any_word_from_the_radio_clears_the_banner() {
    let mut bench = Bench::attached();
    bench.handle(Event::ReportProblem(MobileRadioProblem::Transport {
        domain: "bench".to_owned(),
        code: 1,
    }));
    assert!(bench.state().problem.is_some());
    let refreshed = bench.command(|reply| Command::Refresh {
        call: Box::new(|session| session.refresh()),
        reply,
    });
    assert!(matches!(outcome(refreshed), Some(Ok(_))));
    assert_eq!(bench.state().problem, None);
}

#[test]
fn frames_received_before_a_mesh_session_wait_for_it() {
    let mut bench = Bench::new();
    bench.handle(Event::HostKey(Some(HOST_KEY)));
    bench.connect(true);
    let info = RadioRxInfo::measured(-82, 35, None);
    let frames: Vec<Vec<u8>> = (0..MAXIMUM_FRAMES_AWAITING_MESH_SESSION + 2)
        .map(|index| {
            let mut packet = [0u8; 64];
            umsh_core::PacketBuilder::new(&mut packet)
                .broadcast()
                .source_hint(umsh_core::NodeHint([0x11, 0x22, index as u8]))
                .flood_hops(3)
                .payload(b"held")
                .build()
                .unwrap()
                .to_vec()
        })
        .collect();
    for frame in &frames {
        bench.device.inject_radio_rx(frame, &info, bench.clock_ms);
    }
    bench.deliver();
    let received = bench
        .take_effects()
        .into_iter()
        .filter(|effect| matches!(effect, Effect::Received(_)))
        .count();
    assert_eq!(received, MAXIMUM_FRAMES_AWAITING_MESH_SESSION + 2);

    bench.handle(Event::MeshSessionArrived);
    let replayed: Vec<_> = bench
        .take_effects()
        .into_iter()
        .filter_map(|effect| match effect {
            Effect::MeshReceive(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(replayed.len(), MAXIMUM_FRAMES_AWAITING_MESH_SESSION);
    assert_eq!(
        replayed[0].data, frames[2],
        "the oldest are the ones let go"
    );
    let effects = bench.take_effects();
    assert!(effects.is_empty(), "replayed once: {effects:?}");
}

#[test]
fn releasing_the_host_ends_when_the_radio_confirms() {
    let mut bench = Bench::attached();
    let device_key = bench.state().device_key.clone().unwrap();
    let (reply, mut released) = oneshot::channel();
    bench.handle(Event::Command(Command::ReleaseHost { reply }));
    assert_eq!(released.try_recv(), Ok(()));
    assert!(
        bench
            .take_effects()
            .contains(&Effect::HostReleased(device_key))
    );

    // Nothing left to release.
    let (reply, mut released) = oneshot::channel();
    bench.handle(Event::Command(Command::ReleaseHost { reply }));
    assert_eq!(released.try_recv(), Ok(()));
    assert!(
        bench
            .take_effects()
            .iter()
            .all(|e| !matches!(e, Effect::HostReleased(_)))
    );
}

#[test]
fn releasing_the_host_gives_up_on_a_silent_radio() {
    let mut bench = Bench::attached();
    bench.carrying = false;
    let (reply, mut released) = oneshot::channel();
    bench.handle(Event::Command(Command::ReleaseHost { reply }));
    let (second, mut joined) = oneshot::channel();
    bench.handle(Event::Command(Command::ReleaseHost { reply: second }));
    bench.advance(HOST_RELEASE_TIMEOUT_MS - 1);
    assert!(released.try_recv().is_err());
    bench.advance(1);
    assert_eq!(released.try_recv(), Ok(()));
    assert_eq!(joined.try_recv(), Ok(()));
    assert!(
        bench
            .take_effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::HostReleased(_))),
        "unconfirmed, so not announced"
    );
}

#[test]
fn dfu_entry_tells_the_transport_only_on_the_radios_confirmation() {
    // The soft device has no bootloader, and refuses.
    let mut bench = Bench::attached();
    let refused = bench.command(|reply| Command::LocalManagement {
        dfu: true,
        call: Box::new(|session| session.enter_dfu(UlcpDfuMode::Default)),
        reply,
    });
    let event = outcome(refused).unwrap().unwrap();
    assert_ne!(event.status_code, Some(0));
    assert!(!bench.take_effects().contains(&Effect::DidEnterDfu));

    // A radio that accepts: its answer is written by hand.
    bench.carrying = false;
    let accepted = bench.command(|reply| Command::LocalManagement {
        dfu: true,
        call: Box::new(|session| session.enter_dfu(UlcpDfuMode::Default)),
        reply,
    });
    let request = bench.last_sent.clone().unwrap();
    let tid = Frame::parse(&request).unwrap().header.tid();
    let mut answer = vec![0; 32];
    let length = umsh_ulcp::frame::prop_is(&mut answer, tid, prop::LAST_STATUS, &[0]).unwrap();
    answer.truncate(length);
    bench.effects.clear();
    bench.handle(Event::LinkReceived(answer));
    assert_eq!(outcome(accepted).unwrap().unwrap().status_code, Some(0));
    let effects = bench.take_effects();
    assert!(effects.contains(&Effect::DidEnterDfu));
    assert!(!effects.contains(&Effect::DidAttach));
}

#[test]
fn local_management_holds_its_slot_until_the_exchange_ends() {
    type Asked = Result<crate::ulcp::UlcpLocalManagementEventRecord, MobileRadioError>;
    fn ask(bench: &mut Bench) -> oneshot::Receiver<Asked> {
        bench.command(|reply| Command::LocalManagement {
            dfu: false,
            call: Box::new(|session| session.enter_dfu(UlcpDfuMode::Default)),
            reply,
        })
    }
    let mut bench = Bench::attached();
    bench.carrying = false;
    let mut held = ask(&mut bench);
    assert_eq!(
        outcome(ask(&mut bench)),
        Some(Err(MobileRadioError::OperationInProgress))
    );
    assert!(held.try_recv().is_err(), "still waiting on the radio");

    // The link going ends the exchange, and frees the slot.
    bench.cut();
    bench.report(MobileRadioTransportPhase::Reconnecting);
    assert_eq!(outcome(held), Some(Err(MobileRadioError::RadioUnavailable)));
    bench.connect(true);
    assert!(matches!(outcome(ask(&mut bench)), Some(Ok(_))));
}

#[test]
fn a_full_table_answers_its_caller_without_a_banner() {
    let mut bench = Bench::attached();
    let mut last = None;
    for index in 1..=u8::MAX {
        let key = [index; 32].to_vec();
        last = outcome(bench.command(|reply| Command::DeviceTable {
            requires_device_identity: true,
            call: Box::new(move |session| session.insert_device_peer(key)),
            reply,
        }));
        if last != Some(Ok(())) {
            break;
        }
    }
    assert_eq!(last, Some(Err(MobileRadioError::DeviceFull)));
    assert_eq!(bench.state().problem, None);
}

#[test]
fn configuring_waits_for_the_radios_answer() {
    let mut bench = Bench::attached();
    let mut settings = transmitter_settings(&bench);
    settings.transmit_power_dbm = 10;
    let configured = bench.command(|reply| Command::Configure {
        call: Box::new(move |session| session.configure(settings)),
        reply,
    });
    assert_eq!(outcome(configured), Some(Ok(())));
    assert_eq!(
        bench
            .state()
            .provisioning
            .as_ref()
            .unwrap()
            .transmit_power_dbm,
        10
    );
}

#[test]
fn a_radio_erasing_itself_drops_the_binding_after_the_attach() {
    let mut bench = Bench::attached();
    let erased = bench.command(|reply| Command::Immediate {
        call: Box::new(|session| session.factory_reset()),
        abandon_binding: true,
        reply,
    });
    assert_eq!(outcome(erased), Some(Ok(())));
    let effects = bench.take_effects();
    let abandoned = effects.iter().position(|e| *e == Effect::AbandonBinding);
    let attached = effects.iter().rposition(|e| *e == Effect::DidAttach);
    assert!(abandoned.is_some());
    assert!(attached.is_none_or(|attached| attached < abandoned.unwrap()));
}

#[test]
fn a_replaced_mesh_session_hears_nothing_meant_for_its_predecessor() {
    let mut bench = Bench::attached();
    bench.device.defer_tx();
    bench.transmit(1);
    bench.transmit(2);
    bench.handle(Event::MeshSessionLeaving);
    assert!(bench.take_effects().contains(&Effect::MeshFailOutbound));
    bench.handle(Event::MeshSessionArrived);
    bench.complete_tx(TxOutcome::Sent);
    assert!(
        bench.completions().is_empty(),
        "the frame in flight belonged to the old session"
    );
    assert_eq!(
        bench.raw_sends.len(),
        1,
        "and the one queued behind it went with it"
    );
}

fn transmitter_settings(bench: &Bench) -> UlcpRadioSettingsRecord {
    let provisioning = bench.state().provisioning.clone().unwrap();
    UlcpRadioSettingsRecord {
        device_name: None,
        phy_enabled: provisioning.phy_enabled,
        frequency_khz: provisioning.frequency_khz,
        transmit_power_dbm: provisioning.transmit_power_dbm,
        bandwidth_hz: provisioning.bandwidth_hz,
        spreading_factor: provisioning.spreading_factor,
        coding_rate_denom: provisioning.coding_rate_denom,
        duty_cycle_limit: provisioning.duty_cycle_limit,
    }
}

/// The driver whole, on its own thread, over a soft device that answers
/// from inside the link's calls, as a fast transport would.
mod runner {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    use std::time::{Duration, Instant};

    use super::super::core::{CONTROL_DEADLINE_MS, HOST_RELEASE_TIMEOUT_MS};

    use umsh_ulcp::hdlc;
    use umsh_ulcp_simdev::soft::{SoftDevice, SoftPlatform};
    use umsh_ulcp_simdev::{DutyLedger, SimulatedPlatform, full_config};

    use super::super::{
        MobileRadioDriver, MobileRadioDriverListener, MobileRadioPhase, MobileRadioTransportPhase,
        MobileRadioTransportStateRecord, RadioLink,
    };
    use super::HOST_KEY;
    use crate::{MobileCounterStore, MobileIdentity, MobileMeshSession};

    struct DeviceLink {
        device: Mutex<SoftDevice<SimulatedPlatform>>,
        decoder: Mutex<hdlc::Decoder<{ umsh_ulcp::gatt::MAX_FRAME }>>,
        driver: OnceLock<Weak<MobileRadioDriver>>,
        attached: Mutex<u32>,
        /// Whether the link swallows what the driver sends: a radio that
        /// has stopped answering.
        silent: AtomicBool,
    }

    impl DeviceLink {
        fn new() -> Arc<Self> {
            let duty = Box::leak(Box::new(DutyLedger::new()));
            let mut platform = SimulatedPlatform::new();
            platform.store_identity(Some(&[1; 32])).unwrap();
            Arc::new(Self {
                device: Mutex::new(SoftDevice::new(full_config(duty, None), platform)),
                decoder: Mutex::new(hdlc::Decoder::new()),
                driver: OnceLock::new(),
                attached: Mutex::new(0),
                silent: AtomicBool::new(false),
            })
        }

        /// Hand the driver whatever the device has said.
        fn deliver(&self) {
            let Some(driver) = self.driver.get().and_then(Weak::upgrade) else {
                return;
            };
            let mut frames = Vec::new();
            {
                let mut device = self.device.lock().unwrap();
                let mut decoder = self.decoder.lock().unwrap();
                while let Some(wire) = device.take_outbound() {
                    for byte in wire {
                        if let Some(frame) = decoder.push(byte) {
                            frames.push(frame.unwrap().to_vec());
                        }
                    }
                }
            }
            for frame in frames {
                driver.link_received(frame);
            }
        }
    }

    impl RadioLink for DeviceLink {
        fn send(&self, frame: Vec<u8>, _raw_transaction_id: Option<u8>) {
            if self.silent.load(Ordering::Relaxed) {
                return;
            }
            let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
            let length = hdlc::encode_frame(&frame, &mut wire).unwrap();
            self.device
                .lock()
                .unwrap()
                .ingest(&wire[..length], 0)
                .unwrap();
            self.deliver();
        }
        fn reset_framing(&self) {}
        fn invalidate(&self, _retry: bool) {}
        fn did_attach(&self) {
            *self.attached.lock().unwrap() += 1;
        }
        fn did_report_name(&self, _name: String) {}
        fn abandon_binding(&self) {}
        fn did_enter_dfu(&self) {}
    }

    struct Wakes(Mutex<u32>);

    impl MobileRadioDriverListener for Wakes {
        fn on_update_pending(&self) {
            *self.0.lock().unwrap() += 1;
        }
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "never: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A driver attached to a soft device of its own, as this phone's
    /// radio.
    fn attached_driver() -> (Arc<DeviceLink>, Arc<MobileRadioDriver>) {
        let link = DeviceLink::new();
        let driver = MobileRadioDriver::new(link.clone()).unwrap();
        link.driver.set(Arc::downgrade(&driver)).unwrap();
        driver.set_host_key(Some(HOST_KEY.to_vec())).unwrap();
        driver.transport_changed(MobileRadioTransportStateRecord {
            phase: MobileRadioTransportPhase::Connecting,
            name: Some("Device link".to_owned()),
            link_id: Some("device".to_owned()),
            problem: None,
        });
        link.device.lock().unwrap().attach();
        link.deliver();
        driver.link_ready(true);
        eventually("attached", || {
            driver.state().phase == MobileRadioPhase::Attached
                && driver
                    .state()
                    .provisioning
                    .is_some_and(|provisioning| provisioning.phy_enabled)
        });
        (link, driver)
    }

    /// A mesh session, and the directory its counters live in.
    async fn mesh_session() -> (tempfile::TempDir, Arc<MobileMeshSession>) {
        let directory = tempfile::tempdir().unwrap();
        let counters = MobileCounterStore::new(directory.path().display().to_string()).unwrap();
        let identity = MobileIdentity::unlock(vec![9; 32]).unwrap();
        let session = MobileMeshSession::start(identity, counters).await.unwrap();
        (directory, session)
    }

    #[tokio::test]
    async fn a_mesh_sessions_frame_reaches_the_air_through_the_driver() {
        let (link, driver) = attached_driver();
        let wakes = Arc::new(Wakes(Mutex::new(0)));
        driver.set_listener(wakes.clone());
        assert!(*wakes.0.lock().unwrap() > 0);
        let update = driver.poll_update();
        assert_eq!(update.state.unwrap().phase, MobileRadioPhase::Attached);
        assert!(!update.diagnostics.is_empty());
        assert_eq!(*link.attached.lock().unwrap(), 1);

        let refreshed = driver.refresh().await.unwrap();
        assert_eq!(refreshed.phase, MobileRadioPhase::Attached);

        let (_directory, session) = mesh_session().await;
        driver
            .use_mesh_session(Some(session.clone()))
            .await
            .unwrap();
        session.send_beacon().await.unwrap();
        eventually("the beacon on the air", || {
            !link.device.lock().unwrap().take_transmitted().is_empty()
        });
        assert!(
            session.poll_update().outbound_frames.is_empty(),
            "the driver took the frame, not the platform"
        );

        driver.use_mesh_session(None).await.unwrap();
        drop(driver);
    }

    #[tokio::test]
    async fn a_driver_the_session_was_taken_from_leaves_its_new_route_alone() {
        let (_first_link, first) = attached_driver();
        let (second_link, second) = attached_driver();
        let (_directory, session) = mesh_session().await;
        first.use_mesh_session(Some(session.clone())).await.unwrap();
        second
            .use_mesh_session(Some(session.clone()))
            .await
            .unwrap();
        // The first driver lets go only after the second has the session.
        first.use_mesh_session(None).await.unwrap();

        session.send_beacon().await.unwrap();
        eventually("the beacon on the second radio's air", || {
            !second_link
                .device
                .lock()
                .unwrap()
                .take_transmitted()
                .is_empty()
        });
    }

    #[tokio::test]
    async fn a_deadline_passes_on_the_drivers_own_thread() {
        let (link, driver) = attached_driver();
        link.silent.store(true, Ordering::Relaxed);
        let asked = Instant::now();
        driver.release_host().await;
        let waited = asked.elapsed();
        assert!(
            waited >= Duration::from_millis(HOST_RELEASE_TIMEOUT_MS),
            "gave up early, after {waited:?}"
        );
        assert!(
            waited < Duration::from_millis(CONTROL_DEADLINE_MS),
            "gave up only on a later deadline, after {waited:?}"
        );
    }

    #[tokio::test]
    async fn a_stopped_driver_fails_its_callers_and_lets_go_of_the_link() {
        let link = DeviceLink::new();
        let driver = MobileRadioDriver::new(link.clone()).unwrap();
        driver.stop();
        assert_eq!(
            driver.refresh().await,
            Err(super::MobileRadioError::Stopped)
        );
        eventually("the link let go", || Arc::strong_count(&link) == 1);
    }

    #[tokio::test]
    async fn an_operation_without_a_radio_is_refused_at_once() {
        let link = DeviceLink::new();
        let driver = MobileRadioDriver::new(link.clone()).unwrap();
        assert_eq!(
            driver.refresh().await,
            Err(super::MobileRadioError::RadioUnavailable)
        );
        assert_eq!(
            driver.set_host_key(Some(vec![1; 31])),
            Err(super::MobileRadioError::InvalidArgument)
        );
        // Nothing to release.
        driver.release_host().await;
    }
}
