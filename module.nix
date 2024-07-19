{ pkgs, lib, config, ... }:
let
  cfg = config.services.u2f-touch-detector;
  format = pkgs.formats.toml {};
in {
  options.services.u2f-touch-detector = {
    enable = lib.mkEnableOption "u2f-touch-detector";

    settings = lib.mkOption {
      default = { };

      example = lib.literalExpression ''
        {
          notify = {
            enable = true;
            heading = "Boop";
            image = ./dongle.png;
          };
          devices = {
            89CEA06EAF6CE3FC5D8BCD69350BE6BE = {
              image = ./rainbow-yubikey.png;
            };
          };
        }
      '';

      description = ''
        Configuration written to {file}`$XDG_CONFIG_HOME/u2f-touch-detector/config.toml`.
      '';

      type = lib.types.submodule {
        freeformType = format.type;
      };
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ pkgs.u2f-touch-detector ];

    xdg.configFile = let
      base = "${pkgs.u2f-touch-detector}/share/systemd/user";
    in {
      "u2f-touch-detector/config.toml" = lib.mkIf (cfg.settings != { }) {
        source = format.generate "u2f-touch-detector-config" cfg.settings;
      };

      # "enable" the service, afaict there's no way to do this from home-manager's
      # systemd module directly, it only deals with units defined by itself
      "systemd/user/default.target.wants/u2f-touch-detector.service" = {
        source = "${base}/u2f-touch-detector.service";
      };
      "systemd/user/sockets.target.wants/u2f-touch-detector.socket" = {
        source = "${base}/u2f-touch-detector.socket";
      };
    };
  };
}
