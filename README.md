# u2f-touch-detector

A simplified utility like https://github.com/maximbaz/yubikey-touch-detector but
only listening for u2f events, and without the yubikey branding.

## WIP, TODO:

 - [x] detect devices and get interaction needed events
 - [x] hysteresis on per-device interaction needed state
 - [x] output to unix socket, reuse yubikey-touch-detector protocol for compat
   - [x] configure socket path
 - [ ] output to desktop notification
   - [ ] configure message based on serial
 - [x] detect devices added after startup
 - [x] systemd configs
   - [x] integrate systemd socket passing
