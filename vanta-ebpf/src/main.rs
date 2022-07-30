#![no_std]
#![no_main]

use core::mem;

mod bindings;
use bindings::{ethhdr, iphdr};

use aya_bpf::bindings::{tcphdr, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::{macros::classifier, programs::SkBuffContext};
use aya_log_ebpf::info;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[classifier(name = "vanta")]
pub fn vanta(ctx: SkBuffContext) -> i32 {
    match unsafe { try_vanta(ctx) } {
        Ok(ret) => TC_ACT_PIPE,
        Err(ret) => TC_ACT_SHOT,
    }
}

unsafe fn try_vanta(ctx: SkBuffContext) -> Result<(), i64> {
    let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    info!(&ctx, "received a packet, tcp offset = {}", offset);
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
