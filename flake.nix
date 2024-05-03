{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
  let
    systems = builtins.filter
      (system: nixpkgs.lib.strings.hasSuffix "linux" system)
      flake-utils.lib.defaultSystems;
  in {
    overlays = rec {
      default = final: prev: {
        u2f-touch-detector = final.callPackage ./package.nix {};
      };
    };
  } // flake-utils.lib.eachSystem systems (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
    in {
      packages = rec {
        default = pkgs.u2f-touch-detector;
      };

      checks = rec {
        inherit (pkgs) u2f-touch-detector;
      };

      devShells = rec {
        default = pkgs.mkShell {
          inputsFrom = [ pkgs.u2f-touch-detector ];
        };
      };
    }
  );
}
