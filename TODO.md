# TODO

- [x] Get frontend with bpf maps
- [x] Get backends with bpf maps
- [x] Manage connection based on the client ip:port
  - [x] There is still a bug with concurrency (it was not concurrency but incosistent struct memory padding)
- [ ] Implement some automated tests
- [x] Manage connection state correctly
- [ ] Complete the example with iperf to compare with a regular `IPVS` setup
