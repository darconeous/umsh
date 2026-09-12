//! IPv4 configuration and live ULCP tables. The runner is independent of
//! station association and the USB/BLE session.
use super::wifi::{self, Settings};
use core::cell::RefCell;
use embassy_net::{ConfigV4, Ipv4Address, Ipv4Cidr, Stack, StaticConfigV4};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use umsh_ulcp::{
    ids::prop,
    ip::{self, FamilyState, Method},
};
use umsh_ulcp_runtime::driver::PublishEvent;

static APPLIED: Mutex<CriticalSectionRawMutex, RefCell<Option<ip::V4Config>>> =
    Mutex::new(RefCell::new(None));
static STATE: Mutex<CriticalSectionRawMutex, RefCell<Option<FamilyState>>> =
    Mutex::new(RefCell::new(None));
#[cfg(feature = "ble-debug")]
static DIAGNOSTIC: Mutex<CriticalSectionRawMutex, RefCell<Option<(FamilyState, Option<[u8; 4]>)>>> =
    Mutex::new(RefCell::new(None));

pub async fn update(stack: Stack<'static>, settings: &Settings, linked: bool) {
    let wanted = if linked {
        settings.v4
    } else {
        ip::V4Config {
            method: Method::Disabled,
            ..Default::default()
        }
    };
    let changed = APPLIED.lock(|cell| {
        let mut old = cell.borrow_mut();
        if *old == Some(wanted) {
            false
        } else {
            *old = Some(wanted);
            true
        }
    });
    if changed {
        let config = match wanted.method {
            Method::Disabled => ConfigV4::None,
            Method::Static => ConfigV4::Static(StaticConfigV4 {
                address: Ipv4Cidr::new(Ipv4Address::from(wanted.address), wanted.prefix),
                gateway: (wanted.gateway != [0; 4]).then(|| Ipv4Address::from(wanted.gateway)),
                dns_servers: Default::default(),
            }),
            Method::Auto => {
                let mut dhcp = embassy_net::DhcpConfig::default();
                dhcp.hostname = Some(settings.hostname.as_str().try_into().unwrap());
                ConfigV4::Dhcp(dhcp)
            }
        };
        stack.set_config_v4(config);
    }
    // Upstream reports a configured address without an ACD readiness gate.
    // Manual DNS writes are rejected by this board's session configuration.
    let active = stack.config_v4().filter(|_| linked && stack.is_config_up());
    let state = if settings.v4.method == Method::Disabled {
        FamilyState::Disabled
    } else if !linked {
        FamilyState::NoLink
    } else if active.is_some() {
        FamilyState::Ready
    } else {
        FamilyState::Waiting
    };
    #[cfg(feature = "ble-debug")]
    {
        let diagnostic = (
            state,
            stack.config_v4().map(|c| c.address.address().octets()),
        );
        let changed = DIAGNOSTIC.lock(|cell| {
            let mut previous = cell.borrow_mut();
            if *previous == Some(diagnostic) {
                false
            } else {
                *previous = Some(diagnostic);
                true
            }
        });
        if changed {
            super::debug_log(format_args!(
                "IPv4: {:?} address={:?}",
                diagnostic.0, diagnostic.1
            ));
        }
    }
    // IPv4 is one fixed record, unlike the length-prefixed IPv6 and
    // resolver tables. IP address octets stay in network byte order.
    let mut addresses = [0; ip::V4_ADDRESS_LEN];
    let mut resolvers = heapless::Vec::<u8, 64>::new();
    if let Some(config) = &active {
        let address = ip::V4Address {
            address: config.address.address().octets(),
            prefix: config.address.prefix_len(),
            gateway: config.gateway.map_or([0; 4], |a| a.octets()),
        };
        address.encode(&mut addresses).unwrap();
        for server in &config.dns_servers {
            resolvers.push(4).unwrap();
            resolvers.extend_from_slice(&server.octets()).unwrap();
        }
    }
    wifi::table(
        prop::IPV4_ADDRESS,
        if active.is_some() { &addresses } else { &[] },
    )
    .await;
    wifi::table(prop::IP_RESOLVERS, &resolvers).await;
    let changed = STATE.lock(|cell| {
        let mut previous = cell.borrow_mut();
        if *previous == Some(state) {
            false
        } else {
            *previous = Some(state);
            true
        }
    });
    if changed {
        wifi::publish(PublishEvent::IpState(prop::IPV4_STATE, state)).await;
    }
}

#[embassy_executor::task]
pub async fn runner(mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface>) -> ! {
    runner.run().await
}
