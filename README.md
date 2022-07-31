# vanta

Vanta is going to be an always-on VPN agent with "kill-switch" capabilities, forcing all egress traffic through VPN connections.

Like the pigment, vanta makes your host go "dark", except for outbound VPN connections. It's an intelligent firewall built with [eBPF](https://ebpf.io/) and [aya](https://aya-rs.dev/book/).

Vanta doesn't actually work yet.

## Motivation

Many commercial VPN services offer agents like this with their over-engineered "clients". Setting something similar up from scratch for a custom VPN setup is tedious: a lot of iptables and scripting. Yuck!

I'd rather write Rust, and this seems a great use case for eBPF.

## Plans

The big idea with vanta:

- Given a primary network device and a collection of VPN configurations,
- Stay connected to the best VPN connection!
- Only allow VPN traffic on the primary network device,
- Redirect all other traffic through the VPN connection if it is available,
- Block all other traffic if it is not.

OpenVPN and Wireguard support for sure.

A basic config file and systemd configuration for Nix and Debian is probably as far as I'm willing to go for UX.

## Prerequisites

Currently developing on NixOS. If you use Nix, `nix-shell` should drop you into a shell environment with `rustup` and LLVM dependencies.

If not, well.. I'll probably Dockerize the build if/when this gets serious enough to make it to CI.

Then, first time setup:

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Re-generate code

Only necessary if you need to update bindings for kernel structures like packet headers. You'll need to set `LIBCLANG_PATH` and then:

```bash
cargo xtask codegen
```

## Run

```bash
cargo xtask run
```
