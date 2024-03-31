# lb-dr

Experiment using [eBPF](https://ebpf.io/) and [aya-rs](https://aya-rs.dev/) to build a simple load balancer with direct return.

## How to use

There is an example setup with [containerlab](https://containerlab.dev/) in the `./test/` directory.

You can deploy all what's necessary with `make deploy` (which is the default make target).

You can then test a request from the `client` container to the VIP:

```bash
docker container exec clab-aya-lb-dr-client curl --silent --head 192.168.31.50
```


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

Check the make targets and use the default one:

`make deploy`
