{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    bcc
    rustup
    llvmPackages_latest.llvm
    llvmPackages_latest.libclang
    glibc
    libelf
  ];
  shellHook = ''
  '';
}

