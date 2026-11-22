//! The engine's pure rules: refusal reasons, the error table, firmware
//! update statuses, read states and the temperature summary.

use std::collections::BTreeMap;

use umsh_ulcp::Status;
use umsh_ulcp::ids::prop;

use crate::MobileError;
use crate::app_core::MobileAppError;
use crate::app_core::manage::reading::{Reading, decoder_row, persistent};
use crate::app_core::manage::records::{
    MobileManagementProblem as Problem, MobilePropertyState, MobileRefusal, MobileRefusalReason,
    MobileTemperatureNames, MobileTemperatureValue,
};
use crate::app_core::manage::refusal::{Stop, classify, dfu_outcome, driver_problem, mesh_stop};
use crate::app_core::records::MobileAppChangesRecord;
use crate::radio_driver::MobileRadioError;
use crate::ulcp::{UlcpManageCategory, UlcpManagedPropertyIds, ulcp_managed_property_ids};

#[test]
fn every_status_has_one_refusal_reason() {
    use MobileRefusalReason as Reason;
    let expected = [
        (Status::OK, Reason::Other),
        (Status::FAILURE, Reason::Other),
        (Status::UNIMPLEMENTED, Reason::NotImplemented),
        (Status::INVALID_ARGUMENT, Reason::OutOfRange),
        (Status::INVALID_STATE, Reason::NotNow),
        (Status::INVALID_COMMAND, Reason::Other),
        (Status::INTERNAL_ERROR, Reason::Other),
        (Status::PARSE_ERROR, Reason::Other),
        (Status::IN_PROGRESS, Reason::Busy),
        (Status::NOMEM, Reason::TooLarge),
        (Status::BUSY, Reason::Busy),
        (Status::PROP_NOT_FOUND, Reason::NoSuchProperty),
        (Status::CCA_FAILURE, Reason::Other),
        (Status::ALREADY, Reason::Other),
        (Status::ITEM_NOT_FOUND, Reason::Other),
        (Status::CURSOR_INVALID, Reason::Other),
        (Status::NOT_PERMITTED, Reason::NotPermitted),
        (Status::CHANNEL_NOT_FOUND, Reason::Other),
        (Status::NO_DEVICE, Reason::Other),
        (Status::NACK, Reason::Other),
        (Status::BUS_ERROR, Reason::Other),
        (Status::NO_ACK, Reason::Other),
        (Status::DUTY_LIMIT, Reason::Other),
        (Status::RESET_POWER_ON, Reason::Other),
        (Status::RESET_EXTERNAL, Reason::Other),
        (Status::RESET_SOFTWARE, Reason::Other),
        (Status::RESET_RESTORED, Reason::Other),
        (Status::RESET_CRASH, Reason::Other),
        (Status::RESET_ASSERT, Reason::Other),
        (Status::RESET_OTHER, Reason::Other),
        (Status::RESET_UNKNOWN, Reason::Other),
        (Status::RESET_WATCHDOG, Reason::Other),
    ];
    for (status, reason) in expected {
        assert_eq!(
            classify(Some(status.0)),
            MobileRefusal {
                reason,
                status: Some(status.0)
            },
            "{}",
            status.0
        );
    }
    assert_eq!(
        classify(None),
        MobileRefusal {
            reason: MobileRefusalReason::NoStatus,
            status: None
        }
    );
}

#[test]
fn firmware_update_statuses() {
    assert_eq!(dfu_outcome(Some(0)), Ok(()));
    assert_eq!(dfu_outcome(Some(2)), Err(MobileAppError::DfuUnsupported));
    assert_eq!(dfu_outcome(Some(5)), Err(MobileAppError::DfuUnsupported));
    assert_eq!(
        dfu_outcome(Some(12)),
        Err(MobileAppError::DfuRefused { status: 12 })
    );
    assert_eq!(dfu_outcome(None), Err(MobileAppError::DfuUnconfirmed));
}

#[test]
fn mesh_errors_read_as_problems() {
    let table = [
        (MobileAppError::NoAnswer, Stop::Problem(Problem::NoAnswer)),
        (
            MobileAppError::Unreachable,
            Stop::Problem(Problem::Unreachable),
        ),
        (
            MobileAppError::Unreadable,
            Stop::Problem(Problem::Unreadable),
        ),
        (MobileAppError::Cancelled, Stop::Cancelled),
        (
            MobileAppError::DfuUnsupported,
            Stop::Problem(Problem::DfuUnsupported),
        ),
        (
            MobileAppError::DfuRefused { status: 9 },
            Stop::Problem(Problem::DfuRefused { status: 9 }),
        ),
        (
            MobileAppError::DfuUnconfirmed,
            Stop::Problem(Problem::DfuUnconfirmed),
        ),
        (MobileAppError::NoRadio, Stop::Problem(Problem::NoRadio)),
        (
            MobileAppError::NotRunning,
            Stop::Problem(Problem::NotRunning),
        ),
        (MobileAppError::NoOwner, Stop::Problem(Problem::NoOwner)),
        (
            MobileAppError::NotThisPhone,
            Stop::Problem(Problem::NotThisPhone),
        ),
        (MobileAppError::NotFound, Stop::Problem(Problem::NotFound)),
        (
            MobileAppError::InvalidRequest,
            Stop::Problem(Problem::InvalidRequest),
        ),
        (
            MobileAppError::SendFailed,
            Stop::Problem(Problem::SendFailed),
        ),
        (MobileAppError::Busy, Stop::Problem(Problem::Busy)),
        (MobileAppError::Stopped, Stop::Problem(Problem::Stopped)),
        (
            MobileAppError::ChannelTableFull,
            Stop::Problem(Problem::Other),
        ),
    ];
    for (error, stop) in table {
        assert_eq!(mesh_stop(error.clone()), stop, "{error:?}");
    }
}

#[test]
fn local_link_errors_read_as_problems() {
    let table = [
        (MobileRadioError::TimedOut, Problem::NoAnswer),
        (MobileRadioError::RadioUnavailable, Problem::NoRadio),
        (MobileRadioError::Stopped, Problem::NoRadio),
        (
            MobileRadioError::LinkFailed { problem: None },
            Problem::NoRadio,
        ),
        (
            MobileRadioError::Refused {
                error: MobileError::InvalidUlcpFrame,
            },
            Problem::NoRadio,
        ),
        (MobileRadioError::OperationInProgress, Problem::RadioBusy),
        (MobileRadioError::DeviceFull, Problem::TableFull),
        (MobileRadioError::Unsupported, Problem::Unsupported),
        (
            MobileRadioError::OperationRejected {
                operation: "insert".to_owned(),
                status_code: 22,
                status_name: "NOT_PERMITTED".to_owned(),
            },
            Problem::Refused {
                refusal: MobileRefusal {
                    reason: MobileRefusalReason::NotPermitted,
                    status: Some(22),
                },
            },
        ),
        (MobileRadioError::UnrecognizedAnswer, Problem::Unreadable),
        (MobileRadioError::InvalidArgument, Problem::NotBuilt),
        (MobileRadioError::IncompatibleProtocol, Problem::NotBuilt),
        (MobileRadioError::IdentityUnavailable, Problem::NotBuilt),
        (MobileRadioError::TakeoverNotAllowed, Problem::NotBuilt),
    ];
    for (error, problem) in table {
        assert_eq!(driver_problem(error.clone()), problem, "{error:?}");
    }
    // One sentence for one condition on every link.
    assert_eq!(
        mesh_stop(MobileAppError::NoRadio),
        Stop::Problem(driver_problem(MobileRadioError::Refused {
            error: MobileError::InvalidUlcpFrame
        }))
    );
}

#[test]
fn every_managed_property_has_a_decoder_row() {
    let UlcpManagedPropertyIds {
        caps,
        host_key,
        device_version,
        device_model,
        device_name,
        battery,
        illuminance,
        temperatures,
        temperature_names,
        battery_current,
        battery_remaining_capacity,
        battery_full_capacity,
        battery_design_capacity,
        battery_ext_power_present,
        battery_present,
        battery_gauge_full,
        battery_gauge_initialized,
        battery_gauge_smoothing,
        battery_charge_voltage_request,
        battery_gauge_format,
        battery_gauge_status,
        battery_gauge_operation_status,
        phy_enabled,
        frequency,
        transmit_power,
        lora_bandwidth,
        lora_spreading_factor,
        lora_coding_rate,
        duty_cycle_now,
        rx_duty_cycle,
        duty_cycle_limit,
        stat_tx_packets,
        stat_tx_channel_busy,
        stat_rx_packets,
        stat_rx_bad_crc,
        stat_rx_non_umsh,
        stat_rx_accepted,
        stat_radio_resets,
        stat_forwarded,
        stat_forward_dropped,
        stat_forward_cancelled,
        repeaters_heard,
        stat_meshcore_seen,
        stat_meshcore_forwarded_routed,
        stat_meshcore_forwarded_flood,
        stat_meshcore_declined,
        ident_role,
        ident_mobile,
        ident_location,
        ident_altitude,
        dev_discoverable,
        gnss_ident_update,
        gnss_ident_precision,
        uptime,
        advert_interval,
        beacon_interval,
        startup_beacon,
        gnss_enabled,
        display_motion_wake_enabled,
        gnss_time_trust,
        ble_enabled,
        ble_bond_count,
        ble_link,
        ble_pairing,
        wifi_enabled,
        bridge_enabled,
        bridge_host,
        bridge_port,
        bridge_server_key,
        bridge_link,
        lan_bearer_enabled,
        lan_bearer_group,
        lan_bearer_ingress_limit,
        lan_bearer_state,
        dev_key,
        wifi_networks,
        wifi_network,
        wifi_scanning,
        wifi_scan_results,
        wifi_link,
        wifi_rssi,
        wifi_mac,
        ipv4_state,
        ipv4_config,
        ipv4_address,
        ipv6_state,
        ipv6_config,
        ipv6_addresses,
        ip_dns,
        ip_resolvers,
        time,
        tz_rule,
        time_24h,
        alert,
        repeater_mode,
        repeater_state,
        repeater_regions,
        repeater_default_region,
        repeater_min_rssi,
        repeater_min_snr,
        meshcore_forwarding_enabled,
        meshcore_region_policy,
        meshcore_regions,
        dev_peers,
        dev_admins,
        test_message_alerts,
    } = ulcp_managed_property_ids();
    let every = [
        caps,
        host_key,
        device_version,
        device_model,
        device_name,
        battery,
        illuminance,
        temperatures,
        temperature_names,
        battery_current,
        battery_remaining_capacity,
        battery_full_capacity,
        battery_design_capacity,
        battery_ext_power_present,
        battery_present,
        battery_gauge_full,
        battery_gauge_initialized,
        battery_gauge_smoothing,
        battery_charge_voltage_request,
        battery_gauge_format,
        battery_gauge_status,
        battery_gauge_operation_status,
        phy_enabled,
        frequency,
        transmit_power,
        lora_bandwidth,
        lora_spreading_factor,
        lora_coding_rate,
        duty_cycle_now,
        rx_duty_cycle,
        duty_cycle_limit,
        stat_tx_packets,
        stat_tx_channel_busy,
        stat_rx_packets,
        stat_rx_bad_crc,
        stat_rx_non_umsh,
        stat_rx_accepted,
        stat_radio_resets,
        stat_forwarded,
        stat_forward_dropped,
        stat_forward_cancelled,
        repeaters_heard,
        stat_meshcore_seen,
        stat_meshcore_forwarded_routed,
        stat_meshcore_forwarded_flood,
        stat_meshcore_declined,
        ident_role,
        ident_mobile,
        ident_location,
        ident_altitude,
        dev_discoverable,
        gnss_ident_update,
        gnss_ident_precision,
        uptime,
        advert_interval,
        beacon_interval,
        startup_beacon,
        gnss_enabled,
        display_motion_wake_enabled,
        gnss_time_trust,
        ble_enabled,
        ble_bond_count,
        ble_link,
        ble_pairing,
        wifi_enabled,
        bridge_enabled,
        bridge_host,
        bridge_port,
        bridge_server_key,
        bridge_link,
        lan_bearer_enabled,
        lan_bearer_group,
        lan_bearer_ingress_limit,
        lan_bearer_state,
        dev_key,
        wifi_networks,
        wifi_network,
        wifi_scanning,
        wifi_scan_results,
        wifi_link,
        wifi_rssi,
        wifi_mac,
        ipv4_state,
        ipv4_config,
        ipv4_address,
        ipv6_state,
        ipv6_config,
        ipv6_addresses,
        ip_dns,
        ip_resolvers,
        time,
        tz_rule,
        time_24h,
        alert,
        repeater_mode,
        repeater_state,
        repeater_regions,
        repeater_default_region,
        repeater_min_rssi,
        repeater_min_snr,
        meshcore_forwarding_enabled,
        meshcore_region_policy,
        meshcore_regions,
        dev_peers,
        dev_admins,
        test_message_alerts,
    ];
    for property in every {
        assert!(decoder_row(property).is_some(), "no row for {property}");
    }
}

/// A reading of `values`, as a read at `at` leaves it.
fn read(category: UlcpManageCategory, ids: &[u32], values: &[(u32, Vec<u8>)]) -> Reading {
    let mut reading = Reading::new(category, ids.to_vec(), 1);
    reading.absorb(
        &values.iter().cloned().collect(),
        1_000,
        true,
        &BTreeMap::new(),
        2,
    );
    reading
}

#[test]
fn read_states_take_refusal_then_failure_then_octets() {
    let ids = [prop::TIME, prop::TZ_RULE, prop::TIME_24H, prop::UPTIME];
    let mut reading = read(
        UlcpManageCategory::Time,
        &ids,
        &[
            // A rule that is not text decodes to nothing.
            (prop::TZ_RULE, vec![0xff, 0xfe]),
            (prop::TIME_24H, Vec::new()),
            (prop::UPTIME, super::time(5)),
        ],
    );
    reading.refused.insert(prop::TIME);
    reading
        .statuses
        .insert(prop::TIME, Status::PROP_NOT_FOUND.0);
    let states: Vec<MobilePropertyState> = ids.iter().map(|id| reading.state(*id)).collect();
    assert_eq!(
        states[0],
        MobilePropertyState::Refused {
            refusal: MobileRefusal {
                reason: MobileRefusalReason::NoSuchProperty,
                status: Some(13)
            }
        }
    );
    assert_eq!(states[1], MobilePropertyState::Invalid);
    assert_eq!(states[2], MobilePropertyState::Empty);
    assert_eq!(reading.state(prop::DEV_NAME), MobilePropertyState::NotRead);
    let record = reading.record(None);
    assert_eq!(
        record.answered,
        vec![prop::TZ_RULE, prop::TIME_24H, prop::UPTIME]
    );
}

#[test]
fn reset_is_offered_only_for_an_answered_counter() {
    let mut reading = Reading::new(
        UlcpManageCategory::Statistics,
        vec![prop::STAT_TX_PACKETS, prop::PHY_DUTY_NOW],
        1,
    );
    assert!(reading.record(None).can_reset_counters);
    reading.refused.insert(prop::STAT_TX_PACKETS);
    assert!(
        !reading.record(None).can_reset_counters,
        "duty cycle is not a counter"
    );
}

#[test]
fn temperature_rows_read_each_sample() {
    let mut reading = Reading::new(
        UlcpManageCategory::Sensors,
        vec![prop::TEMPERATURES, prop::TEMPERATURE_NAMES],
        1,
    );
    reading.properties.temperatures = Some(vec![Some(2981), None, Some(u16::MAX)]);
    reading.properties.temperature_names = Some(vec![
        "Die".to_owned(),
        "Air".to_owned(),
        "Case".to_owned(),
        "Spare".to_owned(),
    ]);
    reading.values.insert(prop::TEMPERATURES, vec![0]);
    reading.values.insert(prop::TEMPERATURE_NAMES, vec![0]);
    let summary = reading.record(None).temperatures.unwrap();
    let values: Vec<MobileTemperatureValue> = summary.rows.iter().map(|row| row.value).collect();
    assert_eq!(
        values,
        vec![
            MobileTemperatureValue::Reading {
                tenths_kelvin: 2981
            },
            MobileTemperatureValue::Unavailable,
            MobileTemperatureValue::Unavailable,
            MobileTemperatureValue::NotRead,
        ]
    );
    assert_eq!(summary.names, MobileTemperatureNames::Known);
    assert_eq!(summary.rows[3].name.as_deref(), Some("Spare"));

    reading.refused.insert(prop::TEMPERATURE_NAMES);
    assert_eq!(
        reading.record(None).temperatures.unwrap().names,
        MobileTemperatureNames::Unreadable
    );
}

#[test]
fn live_state_is_never_cached() {
    for property in [
        prop::ILLUMINANCE,
        prop::TEMPERATURES,
        prop::TEMPERATURE_NAMES,
        prop::WIFI_SCAN_RESULTS,
        prop::WIFI_RSSI,
        prop::WIFI_SCANNING,
    ] {
        assert!(!persistent(property), "{property}");
    }
    assert!(persistent(prop::DEV_NAME));
    assert!(persistent(prop::WIFI_ENABLED));
}

#[test]
fn the_radio_choices_are_the_devices() {
    let choices = crate::ulcp::ulcp_radio_choices();
    assert_eq!(choices.spreading_factors, (5..=12).collect::<Vec<u8>>());
    assert_eq!(choices.coding_rates, vec![5, 6, 7, 8]);
    assert_eq!(
        choices.duty_cycle_limits,
        vec![u16::MAX, 13_107, 6_553, 655, 65]
    );
    assert_eq!(
        choices.bandwidths_hz,
        crate::ulcp::ulcp_supported_bandwidths_hz()
    );
}

#[test]
fn managed_devices_merge_as_a_set() {
    let mut changes = MobileAppChangesRecord {
        managed_devices: vec![1, 2],
        ..MobileAppChangesRecord::default()
    };
    changes.merge(MobileAppChangesRecord {
        managed_devices: vec![2, 3],
        ..MobileAppChangesRecord::default()
    });
    assert_eq!(changes.managed_devices, vec![1, 2, 3]);
}

// MARK: Key tables, Wi-Fi rules and bond clearing

#[test]
fn a_key_table_diff_is_a_set_difference_in_byte_order() {
    use crate::app_core::manage::keys::{KeyTableDiff, key_table_diff};
    let key = |byte: u8| vec![byte; 32];
    assert_eq!(
        key_table_diff(&[key(3), key(1), key(2)], &[key(5), key(2), key(4), key(5)]),
        KeyTableDiff {
            removals: vec![key(1), key(3)],
            additions: vec![key(4), key(5)],
        }
    );
    assert!(key_table_diff(&[key(1), key(2)], &[key(2), key(1), key(1)]).is_empty());
    assert!(key_table_diff(&[], &[]).is_empty());
}

#[test]
fn a_join_plan_offers_what_the_network_offers_strongest_first() {
    use crate::app_core::manage::wifi::wifi_join_plan;
    let every = vec![3, 2, 4, 1, 0];
    let plan = |offered| {
        let plan = wifi_join_plan(offered);
        assert_eq!(Some(&plan.initial), plan.choices.first());
        (plan.choices, plan.unsupported)
    };
    assert_eq!(plan(None), (every.clone(), vec![]), "nothing heard");
    assert_eq!(plan(Some(0)), (every.clone(), vec![]), "could not tell");
    assert_eq!(plan(Some(0b1100)), (vec![3, 2], vec![]));
    assert_eq!(plan(Some(0b0001_0011)), (vec![4, 1, 0], vec![]));
    assert_eq!(
        plan(Some(0b1_1110_0000)),
        (every.clone(), vec![5, 6, 7, 8]),
        "nothing this app can build"
    );
    assert_eq!(plan(Some(0b0100_0100)), (vec![2], vec![6]));
}

#[test]
fn an_edit_plan_keeps_the_stored_mode_in_view() {
    use crate::app_core::manage::wifi::wifi_edit_plan;
    use crate::ulcp::UlcpWifiNetworkRecord;
    let stored = |security| UlcpWifiNetworkRecord {
        hidden: false,
        auto_join: true,
        security,
        ssid: b"Field Office".to_vec(),
    };
    let plan = wifi_edit_plan(stored(2));
    assert_eq!((plan.choices, plan.initial), (vec![3, 2, 4, 1, 0], 2));
    let plan = wifi_edit_plan(stored(5));
    assert_eq!((plan.choices, plan.initial), (vec![5, 3, 2, 4, 1, 0], 5));
    assert!(plan.unsupported.is_empty());
}

#[test]
fn an_entry_is_judged_name_then_credential() {
    use crate::app_core::manage::records::MobileWifiEntryProblem as Entry;
    use crate::app_core::manage::wifi::wifi_entry_check;
    use crate::ulcp::UlcpWifiNetworkRecord;
    let join = |ssid: &[u8], security: u8, credential: &[u8]| {
        wifi_entry_check(
            ssid.to_vec(),
            security,
            false,
            true,
            credential.to_vec(),
            None,
        )
    };
    let problem =
        |ssid: &[u8], security, credential: &[u8]| join(ssid, security, credential).problem;
    assert_eq!(problem(&[b'a'; 32], 0, b""), None, "a name of 32 bytes");
    assert_eq!(problem(&[b'a'; 33], 0, b""), Some(Entry::SsidTooLong));
    assert_eq!(problem(b"", 2, b""), Some(Entry::SsidEmpty));
    // Each mode's credential.
    assert_eq!(problem(b"net", 0, b""), None);
    assert_eq!(
        problem(b"net", 0, b"secret"),
        Some(Entry::CredentialInvalid)
    );
    assert_eq!(problem(b"net", 1, b""), None);
    assert_eq!(problem(b"net", 2, b""), Some(Entry::CredentialRequired));
    assert_eq!(
        problem(b"net", 2, b"7chars!"),
        Some(Entry::CredentialInvalid)
    );
    assert_eq!(problem(b"net", 2, b"8 chars!"), None);
    assert_eq!(problem(b"net", 4, &[b'a'; 63]), None);
    assert_eq!(
        problem(b"net", 4, &[b'a'; 64]),
        Some(Entry::CredentialInvalid)
    );
    assert_eq!(problem(b"net", 3, b"x"), None);
    assert_eq!(
        problem(b"net", 3, &[b'a'; 129]),
        Some(Entry::CredentialInvalid)
    );
    assert_eq!(problem(b"net", 5, b""), Some(Entry::CredentialInvalid));
    assert_eq!(problem(b"net", 9, b""), Some(Entry::CredentialInvalid));
    let checked = join(b"net", 2, b"8 chars!");
    assert!(checked.takes_credential && !checked.keeps_credential && checked.changed);
    assert!(!join(b"net", 1, b"").takes_credential);

    // Editing a stored network.
    let stored = UlcpWifiNetworkRecord {
        hidden: false,
        auto_join: true,
        security: 2,
        ssid: b"net".to_vec(),
    };
    let edit = |security, hidden, auto_join, credential: &[u8]| {
        wifi_entry_check(
            b"net".to_vec(),
            security,
            hidden,
            auto_join,
            credential.to_vec(),
            Some(stored.clone()),
        )
    };
    let unchanged = edit(2, false, true, b"");
    assert!(unchanged.keeps_credential && !unchanged.changed);
    assert_eq!(
        unchanged.problem, None,
        "an empty credential keeps the stored one"
    );
    assert!(edit(2, true, true, b"").changed);
    assert!(edit(2, false, false, b"").changed);
    assert!(edit(2, false, true, b"new secret").changed);
    let stronger = edit(3, false, true, b"");
    assert!(stronger.changed && !stronger.keeps_credential);
    assert_eq!(stronger.problem, Some(Entry::CredentialRequired));
    assert_eq!(edit(0, false, true, b"").problem, None);
}

#[test]
fn offered_modes_read_strongest_first() {
    use crate::app_core::manage::wifi::wifi_offered_modes;
    assert_eq!(wifi_offered_modes(0), Vec::<u8>::new());
    assert_eq!(wifi_offered_modes(0x01ff), vec![8, 7, 6, 3, 2, 4, 1, 5]);
    assert_eq!(wifi_offered_modes(0b0011_1100), vec![3, 2, 4, 5]);
}

#[test]
fn a_join_refusal_is_particular_only_at_the_store() {
    use crate::app_core::manage::records::{MobileWifiRefusal as Refusal, MobileWifiStep as Step};
    use crate::app_core::manage::wifi::{classify_join, classify_update};
    let refusal = |status: Status| classify(Some(status.0));
    assert_eq!(
        classify_join(Step::Store, refusal(Status::NOMEM), 2, None),
        Refusal::NoRoom
    );
    assert_eq!(
        classify_join(Step::Store, refusal(Status::INVALID_ARGUMENT), 2, None),
        Refusal::CredentialRejected
    );
    // The step-down walks the plan: with nothing heard, every mode.
    for (tried, weaker) in [
        (3, Some(2)),
        (2, Some(4)),
        (4, Some(1)),
        (1, Some(0)),
        (0, None),
    ] {
        assert_eq!(
            classify_join(Step::Store, refusal(Status::UNIMPLEMENTED), tried, None),
            Refusal::SecurityUnsupported { tried, weaker }
        );
    }
    // A mode the network does not offer has nothing after it.
    assert_eq!(
        classify_join(Step::Store, refusal(Status::UNIMPLEMENTED), 4, Some(0b1100)),
        Refusal::SecurityUnsupported {
            tried: 4,
            weaker: None
        }
    );
    for step in [Step::TurnOn, Step::Select] {
        for status in [
            Status::NOMEM,
            Status::INVALID_ARGUMENT,
            Status::UNIMPLEMENTED,
        ] {
            assert_eq!(
                classify_join(step, refusal(status), 3, None),
                Refusal::Other {
                    step,
                    refusal: refusal(status)
                }
            );
        }
    }
    assert_eq!(
        classify_join(Step::Store, classify(None), 2, None),
        Refusal::Other {
            step: Step::Store,
            refusal: classify(None)
        }
    );
    assert_eq!(
        classify_update(refusal(Status::UNIMPLEMENTED), 3),
        Refusal::SecurityUnsupported {
            tried: 3,
            weaker: None
        }
    );
    assert_eq!(
        classify_update(refusal(Status::NOMEM), 3),
        Refusal::Other {
            step: Step::Store,
            refusal: refusal(Status::NOMEM)
        }
    );
}

#[test]
fn a_bond_clearing_takes_on_the_device_echo() {
    use crate::app_core::manage::engine::{
        BondsNotCleared, bonds_cleared, bonds_problem, clear_bonds_writes,
    };
    use crate::mobile_mesh::MobileMeshManagementAnswerRecord;
    let writes = clear_bonds_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        (writes[0].property_id, writes[0].value.clone()),
        (prop::BLE_BOND_COUNT, vec![0])
    );
    let answer = |value: Option<Vec<u8>>, status_code| MobileMeshManagementAnswerRecord {
        property_id: prop::BLE_BOND_COUNT,
        value,
        status_code,
        refusal: status_code,
    };
    assert_eq!(bonds_cleared(&[answer(Some(vec![0]), None)]), Ok(()));
    assert_eq!(
        bonds_cleared(&[answer(None, Some(Status::PROP_NOT_FOUND.0))]),
        Err(BondsNotCleared::Refused(Some(Status::PROP_NOT_FOUND.0)))
    );
    assert_eq!(
        bonds_cleared(&[answer(None, None)]),
        Err(BondsNotCleared::Refused(None))
    );
    assert_eq!(bonds_cleared(&[]), Err(BondsNotCleared::Unanswered));
    assert_eq!(
        bonds_problem(BondsNotCleared::Unanswered),
        Problem::Unreadable
    );
    assert_eq!(
        bonds_problem(BondsNotCleared::Refused(Some(Status::PROP_NOT_FOUND.0))),
        Problem::Refused {
            refusal: classify(Some(Status::PROP_NOT_FOUND.0))
        }
    );
    assert_eq!(
        bonds_problem(BondsNotCleared::Refused(None)),
        Problem::Refused {
            refusal: classify(None)
        }
    );
}
