# wifi-commissioning-gatt-service

This service is intended to run on a device that is delivered to an end-user without a preset configuration for its wifi settings.
It allows a bluetooth client (like a Chrome browser running an a PC or smartphone) to make the appropriate settings
to connect the device to an existing wlan access point.

## `systemd` integration

The crate `wifi-commissioning-gatt-service` has the optional feature `systemd`.<br>
If you enable `systemd` it [notifies](https://www.freedesktop.org/software/systemd/man/sd_notify.html#READY=1) `systemd` that the startup is finished.<br>

## License

Licensed under either of

* Apache License, Version 2.0, (./LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license (./LICENSE-MIT or <http://opensource.org/licenses/MIT>)

at your option.
