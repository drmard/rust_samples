#![no_std]

pub const MAX_PATH_LEN: usize = 256;

// flags for file operations
pub const AUTH_OPEN: u32 = 1 << 0;
pub const AUTH_READ: u32 = 1 << 1;
pub const AUTH_WRITE: u32 = 1 << 2;
pub const AUTH_EXEC: u32 = 1 << 3;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileRuleKey {
    pub path: [u8; MAX_PATH_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileRuleValue {
    pub allowed_mask: u32, // flags AUTH_*
}

#[cfg(feature = "user")]
unsafe impl aya::pod::Pod for FileRuleKey {}
#[cfg(feature = "user")]
unsafe impl aya::pod::Pod for FileRuleValue {}

