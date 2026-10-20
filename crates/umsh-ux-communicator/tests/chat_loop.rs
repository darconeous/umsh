//! The chat loop on the T-LoRa Pager.

const BOARD: &umsh_ux_communicator::board::Board = &umsh_ux_communicator::board::Board::PAGER;

include!("chat_loop/cases.rs");
