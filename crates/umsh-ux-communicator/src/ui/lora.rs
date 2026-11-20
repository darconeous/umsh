//! LoRa: the radio's profile, and each parameter a profile sets, which can
//! also be set one at a time. Settings no profile has read as Custom.
//! Changes apply at once; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::LazyForEach;
use buoyant::view::lazy_foreach::Extent;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::setting::{End, marked_row, row};
use crate::model::{
    BANDWIDTHS, CODING_RATES, LoraChoice, RadioSettings, SPREADING_FACTORS, State, TRANSMIT_LIMITS,
};
use crate::nav::keys;

const ROW: u32 = 36;
/// The most values a LoRa setting has.
const CHOICE_ROWS: usize = 10;

/// The LoRa settings, as `settings` has them.
pub fn view(state: &State, settings: &RadioSettings) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let limit = settings.transmit_limit.map(limit_name);
    VStack::new((
        header(m, "LoRa", None, None),
        super::list(
            VStack::new((
                row(
                    m,
                    "Profile",
                    keys::PROFILE,
                    State::open_profiles,
                    End::value_chevron(state.profile_name(settings)),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Frequency",
                    keys::FREQUENCY,
                    State::open_frequency,
                    End::value_chevron(&frequency_name(settings.frequency_khz)),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Bandwidth",
                    keys::BANDWIDTH,
                    |s: &mut State| s.open_lora_choice(LoraChoice::Bandwidth),
                    End::value_chevron(&bandwidth_name(settings.bandwidth_hz)),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Spreading factor",
                    keys::SPREADING_FACTOR,
                    |s: &mut State| s.open_lora_choice(LoraChoice::SpreadingFactor),
                    End::value_chevron(&spreading_factor_name(settings.spreading_factor)),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Coding rate",
                    keys::CODING_RATE,
                    |s: &mut State| s.open_lora_choice(LoraChoice::CodingRate),
                    End::value_chevron(&coding_rate_name(settings.coding_rate)),
                    false,
                    ROW,
                ),
                limit.map(|limit| {
                    row(
                        m,
                        "Transmit limit",
                        keys::TRANSMIT_LIMIT,
                        |s: &mut State| s.open_lora_choice(LoraChoice::TransmitLimit),
                        End::value_chevron(&limit),
                        false,
                        ROW,
                    )
                }),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(ROW),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(back)
}

/// The values `choice` can be set to, the radio's own checked. Pressing one
/// sets it.
pub fn choices(state: &State, choice: LoraChoice) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let current = choice.position(&state.node.radio());
    VStack::new((
        header(m, choice.title(), None, None),
        super::list(
            LazyForEach::<CHOICE_ROWS>::new_vertical(
                choice.count(),
                Extent::Fixed(ROW),
                move |index| {
                    marked_row(
                        m,
                        choice.name(index).unwrap_or_default(),
                        keys::lora_choice(index),
                        move |s: &mut State| s.choose_lora(choice, index),
                        End::Nothing,
                        false,
                        ROW,
                        Some(current == Some(index)),
                    )
                },
            )
            .keyed(keys::lora_choice),
        )
        .with_scroll_step(ROW),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(back)
}

fn back(key: Key, s: &mut State) -> KeyResponse {
    match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    }
}

/// `thousandths` as a decimal with no trailing zeros, then `unit`:
/// 910525 and "MHz" read "910.525 MHz", and 917500 "917.5 MHz".
fn decimal(thousandths: u32, unit: &str) -> String<16> {
    let mut text = String::new();
    let (whole, mut fraction) = (thousandths / 1000, thousandths % 1000);
    _ = core::fmt::write(&mut text, format_args!("{whole}"));
    if fraction != 0 {
        let mut digits = 3;
        while fraction % 10 == 0 {
            fraction /= 10;
            digits -= 1;
        }
        _ = core::fmt::write(&mut text, format_args!(".{fraction:0digits$}"));
    }
    _ = core::fmt::write(&mut text, format_args!(" {unit}"));
    text
}

fn frequency_name(khz: u32) -> String<16> {
    decimal(khz, "MHz")
}

/// As [`BANDWIDTHS`] calls it, or in kHz when it is none of them.
fn bandwidth_name(hz: u32) -> String<16> {
    match BANDWIDTHS.iter().find(|&&(bw, _)| bw == hz) {
        Some(&(_, name)) => String::try_from(name).unwrap_or_default(),
        None => decimal(hz, "kHz"),
    }
}

fn spreading_factor_name(sf: u8) -> String<16> {
    match SPREADING_FACTORS.iter().find(|&&(s, _)| s == sf) {
        Some(&(_, name)) => String::try_from(name).unwrap_or_default(),
        None => {
            let mut text = String::new();
            _ = core::fmt::write(&mut text, format_args!("SF{sf}"));
            text
        }
    }
}

fn coding_rate_name(denominator: u8) -> String<16> {
    match CODING_RATES.iter().find(|&&(cr, _)| cr == denominator) {
        Some(&(_, name)) => String::try_from(name).unwrap_or_default(),
        None => {
            let mut text = String::new();
            _ = core::fmt::write(&mut text, format_args!("4/{denominator}"));
            text
        }
    }
}

/// As [`TRANSMIT_LIMITS`] calls it, or as a percentage.
fn limit_name(limit: u16) -> String<16> {
    match TRANSMIT_LIMITS.iter().find(|&&(l, _)| l == limit) {
        Some(&(_, name)) => String::try_from(name).unwrap_or_default(),
        None => percent(limit),
    }
}

/// A share of the hour out of `u16::MAX` as a percentage, to the nearest
/// tenth.
fn percent(share: u16) -> String<16> {
    let max = u32::from(u16::MAX);
    let tenths = (u32::from(share) * 1_000 + max / 2) / max;
    let mut text = String::new();
    if tenths % 10 == 0 {
        _ = core::fmt::write(&mut text, format_args!("{}%", tenths / 10));
    } else {
        _ = core::fmt::write(&mut text, format_args!("{}.{}%", tenths / 10, tenths % 10));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{bandwidth_name, frequency_name, limit_name, percent};
    use crate::model::TRANSMIT_LIMITS;

    #[test]
    fn frequencies_read_in_megahertz_without_trailing_zeros() {
        assert_eq!(frequency_name(910_525), "910.525 MHz");
        assert_eq!(frequency_name(917_500), "917.5 MHz");
        assert_eq!(frequency_name(869_050), "869.05 MHz");
        assert_eq!(frequency_name(915_000), "915 MHz");
        assert_eq!(frequency_name(433_005), "433.005 MHz");
    }

    #[test]
    fn a_bandwidth_off_the_list_reads_in_kilohertz() {
        assert_eq!(bandwidth_name(62_500), "62.5 kHz");
        assert_eq!(bandwidth_name(200_000), "200 kHz");
    }

    #[test]
    fn each_offered_limit_is_named_as_the_percentage_it_is() {
        for (limit, name) in TRANSMIT_LIMITS {
            if limit != u16::MAX {
                assert_eq!(percent(limit), name);
            }
        }
        assert_eq!(limit_name(100), "0.2%");
    }
}
