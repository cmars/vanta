#![no_std]
#![no_main]

use core::mem;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr, udphdr};

use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::maps::PerCpuArray;
use aya_bpf::{macros::classifier, programs::SkBuffContext};
use aya_log_ebpf::trace;

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

unsafe fn try_vanta(mut ctx: SkBuffContext) -> Result<(), i64> {
    // Decode network packet headers
    let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
    let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
    let source_port =
        u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?);
    let dest_port =
        u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?);

    if source_port == 0 || dest_port == 0 {
        trace!(&ctx, "not messing with non-socket packet");
        return Ok(());
    }
    if is_allowed(ip_proto, source_port, dest_port) {
        trace!(&ctx, "not messing with VPN traffic");
        return Ok(());
    }

    let ifindex = &(*ctx.skb).ifindex;
    trace!(
        &ctx,
        "received a packet on ifindex={}, eth(proto={}) ip(proto={} saddr={} daddr={}) tcp(source={}, dest={})",
        ifindex,
        eth_proto,
        ip_proto,
        saddr,
        daddr,
        source_port,
        dest_port
    );

    // Drop other packets
    Err(0)
}

fn is_allowed(ip_proto: u8, source_port: u16, dest_port: u16) -> bool {
    // TODO: Improve this w/DPI beyond a simple naive port number match
    if source_port == 0 || dest_port == 0 {
        return true;
    }
    if ip_proto != IPPROTO_UDP {
        return false;
    }
    return is_vpn_port(source_port) || is_vpn_port(dest_port);
}

fn is_vpn_port(port: u16) -> bool {
    match port {
        1194u16 | 4569u16 | 5060u16 | 51280u16 => true,
        _ => false,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
