{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    bcc
    rustup
    llvmPackages_latest.llvm
    llvmPackages_latest.libclang
    glibc
    rust-bindgen
    nixos-shell
  ];
  shellHook = ''
    export LIBCLANG_PATH=$(realpath $(dirname $(which clang))/../lib)
  '';
}

