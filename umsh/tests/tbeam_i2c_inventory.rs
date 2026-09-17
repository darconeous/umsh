//! Exercise the BSP's HAL-independent startup identification on the host.
//! The production BSP depends on Xtensa; importing this pure module keeps
//! the tests on the exact discovery code without pulling in esp-hal.
#![cfg(feature = "tokio-support")]

#[path = "../../firmware-esp32/crates/umsh-bsp-tbeam-supreme/src/i2c/inventory.rs"]
mod inventory;

use embedded_hal_async::i2c::{ErrorKind, ErrorType, I2c, NoAcknowledgeSource, Operation};
use inventory::Inventory;
use std::collections::BTreeMap;

#[derive(Default)]
struct Bus {
    replies: BTreeMap<u8, u8>,
    calls: Vec<(u8, Option<u8>)>,
    stuck: Option<u8>,
}

impl ErrorType for Bus {
    type Error = ErrorKind;
}

impl I2c for Bus {
    async fn transaction(&mut self, addr: u8, ops: &mut [Operation<'_>]) -> Result<(), ErrorKind> {
        let register = match ops {
            [Operation::Read(out)] => {
                assert_eq!(addr, 0x3D, "only the panel status uses a bare read");
                assert_eq!(out.len(), 1);
                None
            }
            [Operation::Write(pointer), Operation::Read(out)] => {
                let expected = if matches!(addr, 0x76 | 0x77) {
                    0xD0
                } else {
                    0x00
                };
                assert_eq!(
                    *pointer,
                    [expected],
                    "discovery must not write configuration"
                );
                assert_eq!(out.len(), 1);
                Some(expected)
            }
            _ => panic!("unexpected discovery transaction"),
        };
        self.calls.push((addr, register));
        if self.stuck == Some(addr) {
            core::future::pending::<()>().await;
        }
        let value = self
            .replies
            .get(&addr)
            .ok_or(ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address))?;
        let Operation::Read(out) = ops.last_mut().unwrap() else {
            unreachable!()
        };
        out[0] = *value;
        Ok(())
    }
}

#[tokio::test]
async fn each_shipped_population_reports_only_its_actual_addresses() {
    for (mag, id, name, panel) in [
        (0x1C, 0x80, "QMC6310U magnetometer", 0x3C),
        (0x3C, 0x80, "QMC6310N magnetometer", 0x3D),
        (0x7C, 0x90, "QMC6309 magnetometer", 0x3C),
        (0x7C, 0x90, "QMC6309 magnetometer", 0x3D),
    ] {
        for bme in [0x76, 0x77] {
            let mut bus = Bus::default();
            // Unspecified SH1106 status bits may read high.
            bus.replies.extend([(mag, id), (panel, 0x78), (bme, 0x60)]);
            let mut inventory = Inventory::new();
            inventory.discover(&mut bus).await;
            assert_eq!(inventory.panel_address(), Some(panel));
            inventory.finish(true, true, true);
            let mut expected = vec![
                (0, mag, name),
                (0, panel, "SH1106 OLED"),
                (0, bme, "BME280 environmental sensor"),
                (1, 0x34, "AXP2101 PMIC"),
                (1, 0x51, "PCF8563 real-time clock"),
            ];
            expected.sort_unstable();
            assert_eq!(
                inventory
                    .devices()
                    .iter()
                    .map(|d| (d.bus, d.addr, d.name))
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn missing_peripherals_are_omitted_and_wrong_ids_remain_unknown() {
    let mut bus = Bus::default();
    // 0x58 is BMP280, not BME280; an ACK must not make it a BME280.
    bus.replies
        .extend([(0x76, 0x58), (0x1C, 0x42), (0x7C, 0x80)]);
    let mut inventory = Inventory::new();
    inventory.discover(&mut bus).await;
    assert_eq!(inventory.panel_address(), None);
    inventory.finish(false, false, false);
    assert_eq!(inventory.devices().len(), 3);
    assert!(
        inventory
            .devices()
            .iter()
            .all(|d| d.name == "Unknown I2C device")
    );
}

#[tokio::test]
async fn ambiguous_or_uninitialized_panels_are_not_advertised_as_oleds() {
    for (address, status, candidate) in [
        (0x3C, 0x80, None),
        (0x3D, 0x40, Some(0x3D)),
        (0x3D, 0xFF, None),
    ] {
        let mut bus = Bus::default();
        bus.replies.insert(address, status);
        let mut inventory = Inventory::new();
        inventory.discover(&mut bus).await;
        assert_eq!(inventory.panel_address(), candidate);
        inventory.finish(false, true, false);
        assert_eq!(inventory.devices()[0].name, "Unknown I2C device");
        assert_eq!(
            inventory.devices().len(),
            2,
            "failed RTC read adds no RTC entry"
        );
    }
}

#[tokio::test]
async fn canceled_discovery_retains_only_completed_observations() {
    let mut bus = Bus {
        stuck: Some(0x3C),
        ..Bus::default()
    };
    bus.replies.insert(0x1C, 0x80);
    let mut inventory = Inventory::new();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(5),
            inventory.discover(&mut bus)
        )
        .await
        .is_err()
    );
    inventory.finish(false, true, true);
    assert_eq!(
        inventory
            .devices()
            .iter()
            .map(|d| (d.bus, d.addr))
            .collect::<Vec<_>>(),
        [(0, 0x1C), (1, 0x34), (1, 0x51)]
    );
}

#[test]
fn maximum_inventory_fits_the_property_reply() {
    umsh_ulcp_device::assert_i2c_tables_fit(&[], &inventory::MAX_DEVICES);
}
