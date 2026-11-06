//! The settings model behind a device's own screens and a phone's remote
//! administration, against a link that answers whatever it likes.

use std::collections::VecDeque;

use umsh_ulcp_admin::descriptor::{self, COVERED};
use umsh_ulcp_admin::{Arrival, Busy, Exchange, Model, Request, Ticket};

use crate::script::{Fields, records};

pub const OP_ANSWER: u8 = 0;
pub const OP_PUBLICATION: u8 = 1;
pub const OP_LOST: u8 = 2;
pub const OP_OVERRUN: u8 = 3;
pub const OP_REFRESH: u8 = 4;
pub const OP_READ: u8 = 5;
pub const OP_SET: u8 = 6;
pub const OP_INSERT: u8 = 7;
pub const OP_REMOVE: u8 = 8;
pub const OP_SAVE: u8 = 9;
pub const OP_REBOOT: u8 = 10;
pub const OP_DECODE: u8 = 11;
const OPS: u8 = 12;

/// A request's room on any real link.
const SLOTS: usize = 7;

enum Delivery {
    Answer(Vec<u8>),
    Publication(Vec<u8>),
    Lost,
    Overrun,
}

/// A link that hands back what the script says.
#[derive(Default)]
pub struct Port {
    outstanding: VecDeque<Ticket>,
    next: u32,
    deliveries: VecDeque<Delivery>,
    /// Every request taken, encoded, for the seed generator.
    pub requests: Vec<Vec<u8>>,
}

impl Port {
    /// Queue an answer to the oldest request outstanding.
    pub fn deliver(&mut self, frame: Vec<u8>) {
        self.deliveries.push_back(Delivery::Answer(frame));
    }
}

impl Exchange for Port {
    const ANSWER_MAX: usize = 4096;

    fn submit(&mut self, request: &Request<'_>) -> Result<Ticket, Busy> {
        if self.outstanding.len() >= SLOTS {
            return Err(Busy::Full);
        }
        let mut frame = [0u8; 300];
        let len = request.encode(1, &mut frame).map_err(|_| Busy::TooLarge)?;
        self.requests.push(frame[..len].to_vec());
        let ticket = Ticket(self.next);
        self.next = self.next.wrapping_add(1);
        self.outstanding.push_back(ticket);
        Ok(ticket)
    }

    fn receive<'b>(&mut self, out: &'b mut [u8]) -> Option<Arrival<'b>> {
        loop {
            let copy = |bytes: Vec<u8>, out: &'b mut [u8]| -> &'b [u8] {
                let len = bytes.len().min(out.len());
                out[..len].copy_from_slice(&bytes[..len]);
                &out[..len]
            };
            return match self.deliveries.pop_front()? {
                Delivery::Answer(frame) => {
                    let Some(ticket) = self.outstanding.pop_front() else {
                        continue;
                    };
                    Some(Arrival::Answer {
                        ticket,
                        frame: copy(frame, out),
                    })
                }
                Delivery::Publication(frame) => Some(Arrival::Publication {
                    frame: copy(frame, out),
                }),
                Delivery::Lost => {
                    let Some(ticket) = self.outstanding.pop_front() else {
                        continue;
                    };
                    Some(Arrival::Lost { ticket })
                }
                Delivery::Overrun => Some(Arrival::Overrun),
            };
        }
    }
}

fn sweep(model: &mut Model) {
    while model.next_event().is_some() {}
    for covered in COVERED {
        let key = covered.key;
        let _ = model.raw(key);
        let _ = model.value(key);
        let _ = model.freshness(key);
        let _ = model.pending(key);
        let _ = model.intended(key);
        let _ = model.items(key).map(Iterator::count);
        let _ = model.prefixed(key).map(Iterator::count);
    }
    let _ = model.caps().map(Iterator::count);
    let _ = model.device_name();
    let _ = model.device_key();
    let _ = model.saved();
    let _ = model.radio();
    let _ = model.tx_power_dbm();
    let _ = model.duty_now();
    let _ = model.duty_limit();
}

pub fn run(data: &[u8]) {
    let mut model = Model::new();
    let mut port = Port::default();
    let mut now_ms = 0;
    for record in records(data) {
        now_ms += 1_000;
        let mut fields = Fields::new(record.body);
        let mut key = || COVERED[usize::from(fields.u8()) % COVERED.len()].key;
        match record.op % OPS {
            OP_ANSWER => port
                .deliveries
                .push_back(Delivery::Answer(record.body.to_vec())),
            OP_PUBLICATION => port
                .deliveries
                .push_back(Delivery::Publication(record.body.to_vec())),
            OP_LOST => port.deliveries.push_back(Delivery::Lost),
            OP_OVERRUN => port.deliveries.push_back(Delivery::Overrun),
            OP_REFRESH => model.refresh(),
            OP_READ => {
                let key = key();
                model.read(key);
            }
            OP_SET => {
                let key = key();
                let _ = model.set(key, fields.rest());
            }
            OP_INSERT => {
                let key = key();
                let _ = model.insert(key, fields.rest());
            }
            OP_REMOVE => {
                let key = key();
                let _ = model.remove(key, fields.rest());
            }
            OP_SAVE => {
                let _ = model.save();
            }
            OP_REBOOT => {
                let _ = model.reboot();
            }
            _ => {
                let covered = &COVERED[usize::from(fields.u8()) % COVERED.len()];
                let _ = descriptor::decode(covered.codec, fields.rest());
            }
        }
        model.pump(&mut port, now_ms);
        sweep(&mut model);
    }
}
