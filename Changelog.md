# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] Q3 2022
- moved systemd service file from meta-ics-dm

## [0.2.4] Q3 2022
- fixed 32bit builds by updating `wpactrl` to 0.5.*
- updated all dependencies via `cargo update`

## [0.2.3] Q3 2022
- updated dependencies (especially bluer)

## [0.2.2] Q2 2022
- add client/web_ble.html in [README](./README.md)

## [0.2.1] Q1 2022
- fixed multiple cargo audit warnings by updating dependencies

## [0.2.0] Q1 2022
- added optional feature `systemd` (see [README](./README.md))
- clap: use version and author from Cargo.toml

## [0.1.5] Q1 2022
- Cargo.toml: added SPDX license expression
- restructured Changelog.txt -> Changelog.md
- renamed license files

## [0.1.4]
Added authentication feature (device will deny read/write unless authentication key characteristic has been written with the correct value first.
Key is Sha3_256 hash of the device id.
Device Id and wlan interface can be specified on the cmdline.

## [0.1.3]
Remove wifiscanner dependency since it does not produce correct JSON format for non-ascii unicode.
Instead use WpaCtrl for scanning, which also makes running the service as non-root possible.

## [0.1.2]
Report errors for wpa_supplicant interaction (previously errors were ignored).
Add retry for connect to bluetooth adapter on startup (previously the service paniced).

## [0.1.1]
Refactoring scan and connect

## [0.1.0]
First release
