use core::cell::Cell;
use core::cmp::min;
use core::pin::Pin;
use crate::allow;
use libtock::platform::{DefaultConfig, share, subscribe, Subscribe, Syscalls, Upcall};
use libtock::runtime::TockSyscalls;

#[allow(unused)]
use libtock::low_level_debug::LowLevelDebug;

const MAX_TX_LEN: usize = 256; // Should match longest possible TX message, currently a conservative guess.

pub type Handle<'s> = Subscribe<'s, TockSyscalls, 1, 1>;

pub struct TxQueue<'buffer> {
    buffer: Cell<Option<Pin<&'buffer mut allow::Buffer<MAX_TX_LEN>>>>,
    debug_pause: Cell<bool>,
    to_ack: Cell<u8>,
}

impl<'buffer> TxQueue<'buffer> {
    pub fn new(buffer: Pin<&'buffer mut allow::Buffer<MAX_TX_LEN>>) -> Self {
        TxQueue {
            buffer: Cell::new(Some(buffer)),
            debug_pause: Cell::new(false),
            to_ack: Cell::new(0),
        }
    }
}

impl TxQueue<'_> {
    pub fn ack(&self, len: u8) {
        self.to_ack.set(self.to_ack.get() + len);
        self.run();
    }

    #[allow(unused)]
    pub fn println(&self, msg: &[u8]) {
        self.debug_pause.set(true);
        let mut cursor = 0;
        loop {
            if cursor > msg.len() { break }
            let mut buffer = self.buffer.take().unwrap();
            let Some(data) = buffer.as_mut().get_mut_buffer() else {
                self.buffer.set(Some(buffer));
                TockSyscalls::yield_wait();
                continue
            };
            let to_cp = min(MAX_TX_LEN, msg.len() - cursor);
            data[..to_cp].copy_from_slice(&msg[cursor..(cursor + to_cp)]);
            let to_tx = match to_cp < MAX_TX_LEN {
                false => to_cp,
                true => {
                    data[to_cp] = b'\n';
                    to_cp + 1
                },
            };
            buffer.as_ref().allow_ro(1, 1, to_tx);
            let _ = TockSyscalls::command(1, 1, to_tx as u32, 0);
            cursor += to_tx;
            self.buffer.set(Some(buffer));
        }
        self.debug_pause.set(false);
    }

    pub fn init<'s>(&'s self, handle: share::Handle<Handle<'s>>) {
        TockSyscalls::subscribe::<_, _, DefaultConfig, 1, 1>(handle, self).unwrap();
    }

    fn run(&self) {
        if self.debug_pause.get() { return }
        let Some(mut buffer) = self.buffer.take() else { return };
        if buffer.is_shared() {
            self.buffer.set(Some(buffer));
            return
        }
        // Note: Prioritize other messages over ACK.
        if self.to_ack.get() > 0 {
            let Some(data) = buffer.as_mut().get_mut_buffer() else { return };
            data[0..8].copy_from_slice(b"ACK    \n");
            data[4] = b'0' + self.to_ack.get() / 100;
            data[5] = b'0' + self.to_ack.get() % 100 / 10;
            data[6] = b'0' + self.to_ack.get() % 10;
            buffer.as_ref().allow_ro(1, 1, 8);
            let _ = TockSyscalls::command(1, 1, 8, 0);
            self.to_ack.set(0);
        }
        self.buffer.set(Some(buffer));
    }
}

impl Upcall<subscribe::OneId<1, 1>> for TxQueue<'_> {
    fn upcall(&self, _bytes: u32, _: u32, _: u32) {
        let Some(buffer) = self.buffer.take() else { return };
        buffer.as_ref().unallow();
        self.buffer.set(Some(buffer));
        self.run();
    }
}
