#![no_std]
#![no_main]

use core::mem;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};

use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::maps::PerCpuArray;
use aya_bpf::{macros::classifier, programs::SkBuffContext};
use aya_log_ebpf::info;

#[macro_use]
extern crate memoffset;

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
    let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
    let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
    let source_port =
        u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?);
    let dest_port =
        u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?);
    info!(
        &ctx,
        "received a packet, eth(proto={}) ip(proto={} saddr={} daddr={}) tcp(source={}, dest={})",
        eth_proto,
        ip_proto,
        saddr,
        daddr,
        source_port,
        dest_port
    );
    //let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
