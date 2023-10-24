// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

mod allow;
mod tx_queue;

use core::cell::Cell;
use core::cmp::min;
use core::pin::pin;
use libtock::platform::{DefaultConfig, share, Subscribe, Syscalls};
use libtock::runtime::{set_main, stack_size, TockSyscalls};
use tx_queue::TxQueue;

#[allow(unused)]
use libtock::low_level_debug::LowLevelDebug;

set_main!(main);
stack_size!(0x800);

const RX_BUFFER_LEN: usize = 256; // Should match longest possible message.
const MAX_RX_LEN: usize = 12/*64*/;     // Matches Console SyscallDriver buffer size.

fn main() {
    let rx_upcall: Cell<Option<(u32, u32)>> = Cell::new(None);
    let mut rx_buffer = [0; RX_BUFFER_LEN];
    let mut rx_cursor = 0;
    let tx_queue = pin!(Default::default());
    let tx_queue = TxQueue::new(tx_queue);
    share::scope::<(Subscribe<_, 1, 2>, tx_queue::Handle), _, _>(|handle| {
        let (rx_subscribe_handle, tx_handle) = handle.split();
        TockSyscalls::subscribe::<_, _, DefaultConfig, 1, 2>(rx_subscribe_handle, &rx_upcall).unwrap();
        tx_queue.init(tx_handle);
        loop {
            let bytes = share::scope(|rx_handle| {
                let read_len = min(MAX_RX_LEN, RX_BUFFER_LEN - rx_cursor);
                TockSyscalls::allow_rw::<DefaultConfig, 1, 1>(rx_handle, &mut rx_buffer[rx_cursor..(rx_cursor + read_len)]).unwrap();
                TockSyscalls::command(1, 2, read_len as u32, 0).to_result::<(), libtock::platform::ErrorCode>().unwrap();
                loop {
                    TockSyscalls::yield_wait();
                    if let Some((_, bytes)) = rx_upcall.take() {
                        return bytes;
                    }
                }
            });
            tx_queue.println(&rx_buffer[rx_cursor..(rx_cursor+bytes as usize)]);
            tx_queue.ack(bytes as u8);
            rx_cursor += bytes as usize;
        }
    });
}
