{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, home-manager }:
  let
    systems = builtins.filter
      (system: nixpkgs.lib.strings.hasSuffix "linux" system)
      flake-utils.lib.defaultSystems;
  in {

    overlays.default = final: prev: {
      u2f-touch-detector = final.callPackage ./package.nix {};
    };

    homeManagerModules.default = import ./module.nix;

  } // flake-utils.lib.eachSystem systems (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
    in {
      packages.default = pkgs.u2f-touch-detector;

      checks = {
        inherit (pkgs) u2f-touch-detector;

        homeManagerModule = pkgs.testers.runNixOSTest {
          name = "homeManagerModule";

          nodes.machine = {
            imports = [ home-manager.nixosModules.home-manager ];

            users.users.alice.isNormalUser = true;
            services.getty.autologinUser = "alice";

            home-manager = {
              useUserPackages = true;
              useGlobalPkgs = true;
              users.alice = {
                imports = [ self.homeManagerModules.default ];
                home.stateVersion = "24.05";
                services.u2f-touch-detector = {
                  enable = true;
                  settings = {
                      notify = {
                          enable = true;
                          heading = "Bonk!";
                      };
                  };
                };
              };
            };
          };

          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_open_unix_socket("/run/user/1000/u2f-touch-detector.socket", False, 1)
            machine.wait_for_unit("u2f-touch-detector.service", "alice", 1)
          '';
        };
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [ pkgs.u2f-touch-detector ];
      };
    }
  );
}
