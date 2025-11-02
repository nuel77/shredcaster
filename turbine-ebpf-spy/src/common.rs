use core::mem;

use arrayvec::ArrayVec;
use aya_ebpf::{macros::map, maps::RingBuf};

pub const PACKET_DATA_SIZE: usize = 1232;

// Packet, is_egress
pub type PacketBuf = (ArrayVec<u8, PACKET_DATA_SIZE>, bool);

pub const PACKET_BUF_SIZE: usize = mem::size_of::<PacketBuf>();

// Store a max of 16384 packets
#[map]
pub static PACKET_BUF: RingBuf = RingBuf::with_byte_size(16384 * PACKET_BUF_SIZE as u32, 0);
