# u2f-touch-detector

A simplified utility like https://github.com/maximbaz/yubikey-touch-detector but
only listening for u2f events, and without the yubikey branding.

## WIP, TODO:

 - [x] detect devices and get interaction needed events
 - [ ] hysteresis on per-device interaction needed state
 - [ ] output to unix socket, reuse yubikey-touch-detector protocol for compat
 - [ ] output to desktop notification
   - [ ] configure message based on serial
 - [ ] detect devices added after startup
 - [ ] systemd configs
