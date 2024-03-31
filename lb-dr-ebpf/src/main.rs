#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
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
    info!(&ctx, "Received a packet");
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    info!(&ctx, "SRC IP: {:i}", source_addr);

    let tcphdr: *const TcpHdr = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Check if the destination address and ports are managed by the lb
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
    // find a way to translate "192.168.31.50" to 0xc0a81f32
    if dest_addr == 0xc0a81f32 && dest_port == 80_u16 {
        // Get previous destination hw address to set it as source for the reemitted frame
        let old_dst_addr: [u8; 6] = unsafe { (*ethhdr).dst_addr };
        unsafe {
            (*ethhdr).src_addr = old_dst_addr;
        }
        // Set the backend hw address in the emitted frame
        unsafe {
            (*ethhdr).dst_addr = [0x30, 0x33, 0x11, 0x11, 0x11, 0x11];
        }
    } else {
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_TX)
}
