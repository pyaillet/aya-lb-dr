#![no_std]

pub const BACKENDS_ARRAY_CAPACITY: usize = 64;
pub const BPF_MAPS_CAPACITY: u32 = 64;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ClientKey {
    pub ip: u32,
    pub port: u16,
}

pub type Backend = [u8; 6];

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BackendList {
    pub backends: [Backend; BACKENDS_ARRAY_CAPACITY],
    // backends_len is the length of the backends array
    pub backends_len: u16,
    pub backend_idx: u16,
}

pub type Frontend = u32;

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for BackendList {}
    unsafe impl aya::Pod for ClientKey {}
}
