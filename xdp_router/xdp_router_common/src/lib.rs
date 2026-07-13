#![no_std]

// key for lookup
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RouteKey {
    pub ip_type: u32, // 4 for IPv4, 6 for IPv6
    pub ip_v4: [u8; 4],
    pub ip_v6: [u8; 16],
    pub vlan_id: u16, // 0: VLAN is missing
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RouteValue {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub if_index: u32, // target network interface
    pub vlan_id: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::pod::Pod for RouteKey {}
#[cfg(feature = "user")]
unsafe impl aya::pod::Pod for RouteValue {}

