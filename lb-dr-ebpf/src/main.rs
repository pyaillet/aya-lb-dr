#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::*;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

use lb_dr_common::{
    Backend, BackendList, ClientKey, Frontend, BACKENDS_ARRAY_CAPACITY, BPF_MAPS_CAPACITY,
};

#[map(name = "LOADBALANCERS")]
static mut LOADBALANCERS: HashMap<Frontend, BackendList> =
    HashMap::<Frontend, BackendList>::with_max_entries(BPF_MAPS_CAPACITY, 0);

#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: LruHashMap<ClientKey, Backend> =
    LruHashMap::<ClientKey, Backend>::with_max_entries(8198, 0);

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
    trace!(&ctx, "Received a packet");
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let source_port = u16::from_be(unsafe { (*tcphdr).source });
    trace!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    // Check if the destination address is managed by the lb
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
    trace!(&ctx, "DST IP: {:i}, DST PORT: {}", dest_addr, dest_port);

    let lb_key = Frontend {
        ip: dest_addr,
        port: dest_port.into(),
    };

    let client_key = ClientKey {
        ip: source_addr,
        port: source_port.into(),
    };

    if let Some(back) = unsafe { CONNECTIONS.get(&client_key) } {
        debug!(&ctx, "Previous connection found for this client");
        if unsafe { (*tcphdr).rst() } == 1_u16 {
            if unsafe { CONNECTIONS.remove(&client_key) }.is_err() {
                warn!(&ctx, "Unable to remove connection");
            }
        }
        return redirect(ethhdr, *back);
    }

    if let Some(backends) = unsafe { LOADBALANCERS.get(&lb_key) } {
        debug!(&ctx, "Frontend found for this request");
        if backends.backends_len > 0 {
            debug!(&ctx, "Backend found",);
            let mut idx: u16 = 0;
            if backends.backend_idx < backends.backends_len {
                idx = backends.backend_idx.into();
            };
            if usize::from(idx) >= BACKENDS_ARRAY_CAPACITY {
                return Ok(xdp_action::XDP_PASS);
            }

            let mut b = backends.clone();
            b.backend_idx = idx + 1;
            if unsafe { LOADBALANCERS.insert(&lb_key, &b, 0) }.is_err() {
                warn!(&ctx, "Unable to update lb backend");
            }

            if unsafe { (*tcphdr).rst() } == 1_u16 {
                if unsafe { CONNECTIONS.remove(&client_key) }.is_err() {
                    warn!(&ctx, "Unable to remove connection");
                }
            } else if unsafe {
                CONNECTIONS.insert(&client_key, &backends.backends[usize::from(idx)], 0)
            }
            .is_err()
            {
                warn!(&ctx, "Unable to update connection");
            }
            return redirect(ethhdr, backends.backends[usize::from(idx)]);
        } else {
            debug!(&ctx, "no backend found");
        }
    } else {
        trace!(&ctx, "No frontend found");
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn redirect(ethhdr: *mut EthHdr, backend: Backend) -> Result<u32, ()> {
    // Get previous destination hw address to set it as source for the reemitted frame
    let old_dst_addr: [u8; 6] = unsafe { (*ethhdr).dst_addr };
    unsafe { (*ethhdr).src_addr = old_dst_addr };
    // Set the backend hw address in the emitted frame
    unsafe { (*ethhdr).dst_addr = backend };
    Ok(xdp_action::XDP_TX)
}
