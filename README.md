# lb-dr

Experiment using [eBPF](https://ebpf.io/) and [aya-rs](https://aya-rs.dev/) to build a simple load balancer with direct return.

## How to use

There is an example setup with [containerlab](https://containerlab.dev/) in the `./test/` directory.

### Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`
2. Install [containerlab](https://containerlab.dev/install/)

### Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

### Deploy the example lab


