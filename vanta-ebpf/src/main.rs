#![no_std]
#![no_main]

use aya_bpf::{
    macros::classifier,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[classifier(name="vanta")]
pub fn vanta(ctx: SkBuffContext) -> i32 {
    match unsafe { try_vanta(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_vanta(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
