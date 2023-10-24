use core::cell::Cell;
use core::marker::PhantomPinned;
use core::pin::Pin;
use libtock::platform::{Syscalls, RawSyscalls};
use libtock::runtime::TockSyscalls;

#[allow(unused)]
use libtock::low_level_debug::LowLevelDebug;

pub struct Buffer<const LEN: usize> {
    buffer: [u8; LEN],
    _pinned: PhantomPinned,
    state: Cell<State>,
}

impl<const LEN: usize> Buffer<LEN> {
    pub fn allow_ro(self: Pin<&Self>, driver: u32, buffer: u32, len: usize) {
        if self.state.get() != State::Unshared || len > LEN { return }
        unsafe {
            TockSyscalls::syscall4::<4>([
                driver.into(),
                buffer.into(),
                self.buffer.as_ptr().into(),
                len.into(),
            ]);
        }
        self.state.set(State::Ro { driver, buffer });
    }

    pub fn get_mut_buffer(self: Pin<&mut Self>) -> Option<&mut [u8; LEN]> {
        let this = unsafe { self.get_unchecked_mut() };
        match this.state.get() {
            State::Unshared => Some(&mut this.buffer),
            _ => None,
        }
    }

    pub fn is_shared(&self) -> bool {
        self.state.get() != State::Unshared
    }

    pub fn unallow(&self) {
        match self.state.get() {
            State::Ro { driver, buffer } => TockSyscalls::unallow_ro(driver, buffer),
            State::Rw { driver, buffer } => TockSyscalls::unallow_rw(driver, buffer),
            State::Unshared => {},
        }
        self.state.set(State::Unshared);
    }
}

impl<const LEN: usize> Default for Buffer<LEN> {
    fn default() -> Self {
        Buffer {
            buffer: [0; LEN],
            _pinned: PhantomPinned,
            state: Cell::new(State::Unshared),
        }
    }
}

impl<const LEN: usize> Drop for Buffer<LEN> {
    fn drop(&mut self) {
        self.unallow();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Ro { driver: u32, buffer: u32 },
    #[allow(unused)]
    Rw { driver: u32, buffer: u32 },
    Unshared,
}
