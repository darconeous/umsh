# T-LoRa Pager BQ27220 default configuration proposal

Status: **documentation for review; not implemented or hardware-qualified**.
Prepared 2026-09-19 from the completed discharge capture. Firmware and gauge
settings remain unchanged.

This proposal uses a 10% EDV2 point and a **1500 mAh nominal design capacity**.
Capacity is expressed in mAh; mA measures current. The measured full-capacity
seed is **1610 mAh**. These are distinct parameters.

## Target configuration

A device may start with factory defaults, learned values, or an unknown
configuration. The values below define the intended profile independently of
that starting state. Read and verify each device's actual configuration when
provisioning; do not assume a particular earlier value.

Addresses below are UMSH configuration-v1 Profile 1 RAM mappings. This table
is a proposal, not a sequence of register-write commands.

| Parameter | Target default | Purpose |
|---|---:|---|
| `cedv_config` (`0x929B`) | **`0x1022`** | Select fixed EDV thresholds (`EDV_CMP=0`). |
| `design_capacity` (`0x929F`) | **1500 mAh** | Use the requested nominal battery rating. |
| `full_capacity` (`0x929D`) | **1610 mAh initial seed** | Initialize from the measured usable discharge; preserve subsequent valid learning. |
| `battery_low` (`0x9251`) | **1000 (10.00%)** | Set the capacity represented by EDV2. |
| `fixed_edv2` (`0x92BA`) | **3420 mV** | Match approximately 10% remaining in this capture. |
| `fixed_edv1` (`0x92B7`) | **3340 mV** | Match approximately 3% remaining. |
| `fixed_edv0` (`0x92B4`) | **3120 mV** | Put empty near the last measured point, just above the existing 3100 mV shutdown threshold. |
| TI **DOD at EDV2** | **14746 (`0x399A`) initial value** | Initialize the learned DOD reference for 10% EDV2: round((1 − 0.10) × 16384). |

Fixed mode uses the configured EDV voltages. EDV2 represents Battery Low %,
EDV1 represents 3%, and EDV0 represents zero. Changing Battery Low % also
requires initializing DOD at EDV2 as above. See [TI SLUUBD4A,
sections 1.1.4, 4.9.14, and 4.9.37](https://www.ti.com/lit/ug/sluubd4/sluubd4.pdf).

The DOD-at-EDV2 row is a required part of the proposal, but is **not an existing
UMSH configuration-v1 field**. Its writable RAM location and supported access
must be verified before implementation; this document does not guess an
address. The relevant schema is `crates/umsh-ulcp/src/battery_gauge_config.rs`.

Use `FCC_LIMIT=0`, as encoded by `0x1022`, so a 1500 mAh design rating does
not cap learned FCC at 1500 mAh. TI documents this distinction in
[sections 1.1.9 and 4.9.14](https://www.ti.com/lit/ug/sluubd4/sluubd4.pdf).
The proposed 1610 mAh seed is about 107.3% of the nominal rating; it is
intentional and should not be silently replaced by 1500 mAh.

## Evidence and threshold derivation

The 2026-09-19 capture contains 631 successful discharge readings spanning
10:49:15–21:35:02 PDT (10 h 45 min 47 s), plus one failed poll. Voltage declined
from 4097 to 3119 mV. Temperature ranged from 24.85 to 31.15°C. Most measured
current magnitudes were around 135–180 mA, with a sampled peak of 264 mA.

The signed raw coulomb count changed from −28 to 1586 mAh: **1614 mAh**
discharged. Trapezoidal integration of the sampled current yields about
**1608 mAh**, motivating the rounded 1610 mAh seed. Both measurements originate
in the same gauge and are not independent current calibration. The last
measurement bounds observed usable capacity; it does not measure charge after
logging stopped or establish the exact shutdown voltage/time.

For each capacity fraction, interpolate voltage against raw coulomb count,
using the difference from the first counter reading and the last recorded
point as the usable-discharge endpoint:

| Remaining fraction of observed discharge | Interpolated loaded voltage | Selected threshold |
|---|---:|---:|
| 10% (161.4 mAh) | 3419.6 mV | 3420 mV, EDV2 |
| 3% (48.42 mAh) | 3335.4 mV | 3340 mV, EDV1 |
| Observed endpoint | 3119 mV | 3120 mV, EDV0 |

The 10% point occurred about 61 minutes before the final sample. These are
starting values fitted to one battery/run, not guaranteed operating limits
across temperature, load, aging, or different cells.

The earlier correction occurred at 16:15:46 PDT: remaining capacity changed
from 759 to 98 mAh and SOC from 50% to 7%, while voltage changed from 3620 to
3619 mV and the raw counter from 757 to 759 mAh. FCC changed from 1544 to
1416 mAh. OperationStatus changed from `0x00B2` to `0x00AA`.
The proposed fixed thresholds move the correction points to the measured
low-capacity region. They address the model mismatch rather than merely
spreading the old correction over time.

## Supporting profile settings

These are the supporting targets for the first validation. They are not
assumptions about settings already present on another device.

| Parameter(s) | Target value |
|---|---|
| `smoothing_config` | `0x08` |
| `edv2_hold`, `edv1_hold`, `edv0_hold` | 10 s, 1 s, 1 s |
| `reserve_capacity`, `near_full` | 0 mAh, 200 mAh |
| `charging_voltage`, `taper_current`, `termination_voltage_margin` | 4200 mV, 220 mA, 100 mV |
| `discharge_detection`, `charge_detection`, `quit_current` | 60 mA, 75 mA, 40 mA |
| `charge_efficiency`, `discharge_efficiency` | 100%, 100% |
| `operation_config_a`, `operation_config_b`, `battery_id` | `0x0484`, `0x1800`, `0x00` |
| `flag_config_a`, `flag_config_b` | `0x0C8C`, `0x8C` |
| `full_set_voltage`, `full_clear_voltage` | 4200 mV, 4100 mV |
| `full_set_soc`, `full_clear_soc` | 100%, 95% |
| `design_voltage`, `learning_low_temp`, `overload_current` | 3700 mV, 119 raw, 1500 mA |

Calibration values such as `cc_gain` and `cc_delta` are device-specific, not
profile defaults copied from the sampled unit. Preserve each device's
calibration. This proposal also does not prescribe replacement CEDV model
coefficients, deadbands, initialization voltage tables, or Qmax values; inspect
those separately if a device's unknown starting configuration needs qualification.

With `smoothing_config=0x08`, end-of-charge smoothing is enabled and
reported discharge smoothing is disabled (`SMEN=0`). This makes the
first repeat run easier to interpret. See [TI section
4.1.1](https://www.ti.com/lit/ug/sluubd4/sluubd4.pdf).

The existing BQ25896 termination policy remains separate: a 220 mA gauge taper
permits at most a 128 mA charger cutoff under the current 75%-margin rule.
No charger or shutdown-policy change is proposed here. The loaded discharge
curve is not enough evidence to replace the initialization voltage table,
Qmax settings, calibration, or temperature selection.

## Implementation and validation boundary

Current firmware inspects the gauge and preserves its battery-backed state;
it does not install these proposed defaults. The existing hardware reference
remains the description of current behavior. Review of this document precedes
any implementation, provisioning, flashing, or OTP work.

For a later implementation:

1. Read the device's actual starting configuration and preserve its calibration.
   Verify DOD-at-EDV2 access, confirm the intended active profile, and read back
   every target setting after provisioning. Configuration version 1 alone
   cannot confirm the DOD value.
2. Treat 1610 mAh and 14746 as initialization/migration seeds. Subsequent valid
   learning must survive ordinary boots; do not repeatedly force either value
   back to its seed.
3. Distinguish ordinary MCU restart from gauge power loss. A plan for restoring
   RAM defaults after gauge power loss remains to be implemented and tested;
   this proposal does not claim persistence or automatic recovery.
4. With the new configuration active, establish a recognized full charge and
   perform another comparable discharge. Record raw counter, voltage, current,
   temperature, remaining/full/design capacities, and OperationStatus.
5. Check EDV2 near 3420 mV and approximately 10% remaining, EDV1 near 3340 mV,
   and empty near the observed endpoint. Look for substantially smaller
   corrections and FCC staying near the measured 1.6 Ah range. These are
   validation targets, not simulated or already demonstrated results.
6. Verify that a matching configuration preserves learned state across reboot,
   and qualify colder or heavier-load operation separately before treating the
   profile as general-purpose.
