{ lib, rustPlatform, pkg-config, udev }:
let
  ignored = lib.fileset.unions [
    ./flake.lock
    (lib.fileset.fileFilter (file: file.hasExt "nix") ./.)
    (lib.fileset.fileFilter (file: lib.hasPrefix "." file.name) ./.)
    # why is there no way to filter directories based on name in lib.fileset 😔
    (lib.fileset.maybeMissing ./.jj)
    (lib.fileset.maybeMissing ./.direnv)
  ];
in rustPlatform.buildRustPackage {
  pname = "u2f-touch-detector";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.difference ./. ignored;
  };
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ udev ];

  postInstall = ''
    install -Dm444 -t $out/share/systemd/user *.{service,socket}

    substituteInPlace $out/share/systemd/user/*.service \
      --replace ExecStart=u2f-touch-detector "ExecStart=$out/bin/u2f-touch-detector"
  '';
}
