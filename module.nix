{ pkgs, lib, config, ... }:
let
  cfg = config.services.u2f-touch-detector;
in {
  options.services.u2f-touch-detector = {
    enable = lib.mkEnableOption "u2f-touch-detector";
  };
  config = lib.mkIf cfg.enable {
    home.packages = [ pkgs.u2f-touch-detector ];

    # "enable" the service, afaict there's no way to do this from home-manager's
    # systemd module directly, it only deals with units defined by itself
    xdg.configFile = let
      base = "${pkgs.u2f-touch-detector}/share/systemd/user";
    in {
      "systemd/user/default.target.wants/u2f-touch-detector.service" = {
        source = "${base}/u2f-touch-detector.service";
      };
      "systemd/user/sockets.target.wants/u2f-touch-detector.socket" = {
        source = "${base}/u2f-touch-detector.socket";
      };
    };
  };
}
