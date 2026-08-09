#![no_std]

// events
pub const EVENT_EXEC: u32 = 1;
pub const EVENT_OPEN: u32 = 2;
pub const EVENT_MEMFD: u32 = 3;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ProcessEvent {
    pub pid: u32,
    pub tgid: u32,
    pub event_type: u32,
    pub comm: [u8; 16],      # Process name
    pub filename: [u8; 64],  # File path
}
