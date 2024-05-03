{ rustPlatform, pkg-config, udev }:

rustPlatform.buildRustPackage {
  pname = "u2f-touch-detector";
  version = "0.1.0";

  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ udev ];
}
