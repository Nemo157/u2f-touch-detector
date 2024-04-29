{ pkgs ? import <nixpkgs> {}}:

with pkgs; mkShell {
  nativeBuildInputs = [
    pkg-config rustc cargo
  ];
  buildInputs = [
    udev
  ];
}
