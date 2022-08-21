{ pkgs, ... }: {
  boot.kernelPackages = pkgs.linuxPackages_latest;

  imports = [
# Add one or more VPN configurations and uncomment to test in a VM
    ./test-vm-files/openvpn.nix
#    ./test-vm-files/wireguard.nix
  ];

}
