//! Supported bootloader contracts, selected by the shipping board image.
//! These are not a probe for replacement bootloaders. Qualification records
//! and bootloader versions live in docs/dfu-entry.md.

use umsh_ulcp::{DfuMode, Status};

#[derive(Clone, Copy)]
enum Profile {
    TEcho,
    T1000E,
    SenseCapSolar,
    WioTrackerL1,
    XiaoSense,
    Unsupported,
}

const PROFILE: Profile = if cfg!(feature = "board-techo") {
    Profile::TEcho
} else if cfg!(feature = "board-t1000e") {
    Profile::T1000E
} else if cfg!(feature = "board-sensecap-solar") {
    Profile::SenseCapSolar
} else if cfg!(feature = "board-wio-tracker-l1") {
    Profile::WioTrackerL1
} else if cfg!(feature = "board-xiao-nrf52") {
    Profile::XiaoSense
} else {
    Profile::Unsupported
};

pub fn prepare(mode: DfuMode) -> Result<DfuMode, Status> {
    match PROFILE {
        Profile::TEcho
        | Profile::T1000E
        | Profile::SenseCapSolar
        | Profile::WioTrackerL1
        | Profile::XiaoSense => Ok(match mode {
            DfuMode::Default => DfuMode::Uf2,
            mode => mode,
        }),
        Profile::Unsupported => Err(Status::UNIMPLEMENTED),
    }
}
