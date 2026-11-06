//! An administrator and a device over a link that loses, repeats, and
//! delays what it carries. A write runs at most once, however often it
//! arrives.

use umsh_node_mgmt::admin::{Exchange, Outcome, Reassembly, Step};

use crate::device;
use crate::fixup::cast;
use crate::script::{Fields, records};
use crate::targets::node_mgmt_device::{Engine, PAYLOAD, serve};

pub const OP_EXCHANGE: u8 = 0;

/// Past every attempt an exchange makes.
const STEPS: usize = 64;

const LOSE_REQUEST: u8 = 0x01;
const LOSE_RESPONSE: u8 = 0x02;
const REPEAT_REQUEST: u8 = 0x04;
const REPEAT_LATE: u8 = 0x08;
const UNDELIVERED: u8 = 0x10;

pub fn run(data: &[u8]) {
    let (mut device, _) = device::soft_device();
    let mut engine = Engine::new(0x5A5A);
    let from = &cast().parties[0].key.0;
    let mut now_ms = 1u64;

    for record in records(data) {
        let mut fields = Fields::new(record.body);
        let seed = fields.u16();
        let fate_len = usize::from(fields.u8());
        let rest = fields.rest();
        let (fates, frame) = rest.split_at(fate_len.min(rest.len()));
        let mut fates = fates.iter().copied().cycle();

        let Ok(mut exchange) = Exchange::<192>::new(frame, seed, now_ms) else {
            continue;
        };
        let mut storage = [0u8; 4096];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut writes = 0;
        let before = device.platform().inner.i2c().executed();
        let mut late: Option<Vec<u8>> = None;
        let mut outcome = None;

        for _ in 0..STEPS {
            match exchange.poll(now_ms, &mut wire) {
                Step::Send { len } => {
                    let fate = fates.next().unwrap_or(0);
                    let request = wire[..len].to_vec();
                    if fate & REPEAT_LATE != 0 {
                        late = Some(request.clone());
                    }
                    let mut response = None;
                    if fate & LOSE_REQUEST == 0 {
                        let (answer, executed) =
                            serve(&mut engine, &mut device, from, &request, now_ms);
                        writes += usize::from(executed == Some(false));
                        response = answer;
                    }
                    if fate & REPEAT_REQUEST != 0 {
                        let (answer, executed) =
                            serve(&mut engine, &mut device, from, &request, now_ms);
                        writes += usize::from(executed == Some(false));
                        response = response.or(answer);
                    }
                    if fate & UNDELIVERED != 0 {
                        exchange.undelivered();
                    } else {
                        exchange.acknowledged(now_ms);
                    }
                    if fate & LOSE_RESPONSE == 0
                        && let Some(response) = response
                    {
                        let _ = exchange.receive(&response, &mut reassembly, now_ms, &mut wire);
                    }
                }
                Step::Wait { deadline_ms } => now_ms = deadline_ms,
                Step::Delivering => exchange.acknowledged(now_ms),
                Step::Done(done) => {
                    outcome = Some(done);
                    break;
                }
            }
        }
        let outcome = outcome.expect("an exchange ends");

        if let Some(request) = late {
            let (_, executed) = serve(&mut engine, &mut device, from, &request, now_ms);
            writes += usize::from(executed == Some(false));
        }
        assert!(writes <= 1, "a write ran {writes} times");
        let transactions = device.platform().inner.i2c().executed() - before;
        if writes == 0 {
            assert_eq!(transactions, 0, "a bus transaction with no write behind it");
        }
        if let Outcome::Replied { len } = outcome {
            assert!(len <= reassembly.len(), "a reply past what arrived");
        }
    }
}
