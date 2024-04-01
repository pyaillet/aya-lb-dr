#![no_std]

pub const BACKENDS_ARRAY_CAPACITY: usize = 128;
pub const BPF_MAPS_CAPACITY: u32 = 128;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BackendList {
    pub backends: [[u8; 6]; BACKENDS_ARRAY_CAPACITY],
    // backends_len is the length of the backends array
    pub backends_len: u16,
}

pub type Frontend = u32;

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for BackendList {}
}
