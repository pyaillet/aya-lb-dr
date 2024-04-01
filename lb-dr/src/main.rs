use std::fs;

use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use lb_dr_common::{BackendList, Frontend};
use log::{debug, info, warn};
use tokio::signal;

mod config;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "config.toml")]
    config_file: String,
}

fn init_config(bpf: &mut Ebpf, config_file: &str) -> anyhow::Result<()> {
    let mut loadbalancers: HashMap<_, Frontend, BackendList> =
        HashMap::try_from(bpf.map_mut("LOADBALANCERS").unwrap())?;

    let config = fs::read_to_string(config_file)?;
    let config: config::Config = toml::from_str(&config)?;

    for server in config.servers.unwrap_or(vec![]) {
        let frontend: Frontend = Frontend {
            ip: server.ip.into(),
            port: server.port.into(),
        };
        let mut backends = BackendList {
            backends: [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; 64],
            backends_len: 2,
            backend_idx: 0,
        };
        for (i, backend) in server.backends.iter().enumerate() {
            backends.backends[i] = backend.bytes();
        }
        loadbalancers.insert(frontend, backends, 0)?;
    }
    info!("Default configuration initialized");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lb-dr"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lb-dr"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program_count = bpf.programs().count();
    println!("{} Programs found", program_count);
    bpf.programs()
        .for_each(|(n, _p)| println!("Program found: {}", n));

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    if let Err(e) = init_config(&mut bpf, &opt.config_file) {
        warn!("error initializing config: {}", e);
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
