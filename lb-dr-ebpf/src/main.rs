#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

use lb_dr_common::{BackendList, Frontend, BPF_MAPS_CAPACITY};

#[map(name = "LOADBALANCERS")]
static mut LOADBALANCERS: HashMap<Frontend, BackendList> =
    HashMap::<Frontend, BackendList>::with_max_entries(BPF_MAPS_CAPACITY, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
    // unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    debug!(&ctx, "Received a packet");
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    info!(&ctx, "SRC IP: {:i}", source_addr);

    // Check if the destination address is managed by the lb
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    info!(&ctx, "DST IP: {:i}", dest_addr);

    if let Some(backends) = unsafe { LOADBALANCERS.get(&dest_addr) } {
        info!(&ctx, "Frontend found for this request");
        if backends.backends_len > 0 {
            let dst_addr = backends.backends[0];
            info!(&ctx, "Backend found",);
            // Get previous destination hw address to set it as source for the reemitted frame
            let old_dst_addr: [u8; 6] = unsafe { (*ethhdr).dst_addr };
            unsafe {
                (*ethhdr).src_addr = old_dst_addr;
            }
            // Set the backend hw address in the emitted frame
            unsafe {
                (*ethhdr).dst_addr = dst_addr;
            }
            return Ok(xdp_action::XDP_TX);
        } else {
            info!(&ctx, "no backend found");
        }
    } else {
        info!(&ctx, "No frontend found");
    }
    Ok(xdp_action::XDP_PASS)
}
