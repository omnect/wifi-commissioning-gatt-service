# wifi-commissioning-gatt-service

This service is intended to run on a device that is delivered to an end-user without a preset configuration for its wifi settings.
It allows a bluetooth client (like a Chrome browser running on a PC or smartphone) to make the appropriate settings
to connect the device to an existing wlan access point.

## Usage
This service uses the following command line options:
- -b, --ble-secret \<BLE_SECRET\>
    - secret shared between client and server used for BLE communication
- -i, --interface \<INTERFACE\>
    - (wireless) network interface name [optional, default: *wlan0*]

## `systemd` integration

The crate `wifi-commissioning-gatt-service` has the optional feature `systemd`.<br>
If you enable `systemd` it [notifies](https://www.freedesktop.org/software/systemd/man/sd_notify.html#READY=1) `systemd` that the startup is finished.<br>

The systemd service file `systemd/wifi-commissioning-gatt@.service` is using the script `ics_dm_get_deviceid.sh` (see *-b* option), in order to supply the device ID.
In the case the service is not used in combination with the *meta-ics-dm* layer, it has to be adapted accordingly.

## Test

There is the web based bluetooth client `client/web_ble.html`, which can be used to configure the wifi of the device using bluetooth.
The web browser has to support the bluetooth API; e.g., the Chrome browser.
The `BLE_SECTET` variable in `client/web_ble.js` has to be set to the shared secret, in order to authorize the bluetooth connection.

## License

Licensed under either of

* Apache License, Version 2.0, (./LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license (./LICENSE-MIT or <http://opensource.org/licenses/MIT>)

at your option.
