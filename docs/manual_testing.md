# Manual testing with bluetoothctl

Activate bluetooth controller and scan for device:

```
sudo bluetoothctl
[bluetooth]# power on
Changing power on succeeded
[bluetooth]# menu scan
...
[bluetooth]# transport le
[bluetooth]# back
...
[bluetooth]# scan on
SetDiscoveryFilter success
Discovery started
[CHG] Controller 18:56:80:76:D9:AE Discovering: yes
...
[CHG] Device B8:27:EB:EB:B8:7A Name: OmnectWifiConfig
[CHG] Device B8:27:EB:EB:B8:7A Alias: OmnectWifiConfig
[CHG] Device B8:27:EB:EB:B8:7A ManufacturerData Key: 0xc6c6
[CHG] Device B8:27:EB:EB:B8:7A ManufacturerData Value:
  21 22 23 24                                      !"#$
...
[bluetooth]# scan off
```

This shows that the device is broadcasting the service announcement.
Now connect the device and access the characteristics:

```
[bluetooth]# connect B8:27:EB:EB:B8:7A
Attempting to connect to B8:27:EB:EB:B8:7A
[CHG] Device B8:27:EB:EB:B8:7A Connected: yes
Connection successful
[CHG] Device B8:27:EB:EB:B8:7A Name: raspberrypi
[CHG] Device B8:27:EB:EB:B8:7A Alias: raspberrypi
...
[OmnectWifiConfig]# menu gatt
...
[OmnectWifiConfig]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa6
[raspberrypi:/service00XX/char00XX]# write "0x00 0x00 0x00 ... 0x00" # insert sha-3 hash of device id here
[OmnectWifiConfig]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa0
[raspberrypi:/service00e5/char00ea]# read
Attempting to read /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00ea
[CHG] Attribute /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00ea Value:
  00                                               .
[raspberrypi:/service00e5/char00ea]# write 01
Attempting to write /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00ea
[raspberrypi:/service00e5/char00ea]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa1
[raspberrypi:/service00e5/char00e8]# read
Attempting to read /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00e8
[CHG] Attribute /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00e8 Value:
  18                                               .
```

Refer to the log output of the gatt service: if the scan was successful, a number of services will have been found.
The whole service list is shown in the service log. Since the list will likely not fit into one characteristic read,
querying the scan select characteristic above will show that to read the whole list, 0x18 = 24 result characterisitic reads are needed.


```
[raspberrypi:/service00e5/char00e8]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa1
[raspberrypi:/service00e5/char00e8]# write 0
Attempting to write /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00e8
[raspberrypi:/service00e5/char00e8]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa2
[raspberrypi:/service00e5/char00e6]# read
Attempting to read /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00e6
[CHG] Attribute /org/bluez/hci0/dev_B8_27_EB_EB_B8_7A/service00e5/char00e6 Value:
  5b 57 69 66 69 20 7b 20 6d 61 63 3a 20 22 66 30  [Wifi { mac: "f0
  3a 62 30 3a 31 34 3a 35 33 3a 33 30 3a 39 37 22  :b0:14:53:30:97"
  2c 20 73 73 69 64 3a 20 22 44 72 61 67 6f 6e 27  , ssid: "Dragon'
  73 20 44 65 6e 22 2c 20 63 68 61 6e 6e 65 6c 3a  s Den", channel:
  20 22 31 33 22 2c 20 73 69 67 6e 61 6c 5f 6c 65   "13", signal_le
  76 65 6c 3a 20 22 2d 36 33 2e 30 30 22 2c 20 73  vel: "-63.00", s
  65 63 75 72                                      ecur
```

This reads the first part of the result. Repeat this for the other parts of the result, increasing the counter for "write 0" by one for every read
until reaching the value read above minus one, in this case 23. The data you read should match the log output on the server.

Now lets have the device connect to one of the access points from the results list. For this we need to generate the preshared key (PSK).
This can be done on https://www.wireshark.org/tools/wpa-psk.html. Enter the SSID and the password there and note the hex string generated, which you will use in the second step below:

```
[raspberrypi:/service00e5/char00e6]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa4
[raspberrypi:/service00db/char00df]# write "0x44 0x72 0x61 0x67 0x6f 0x6e 0x27 0x73 0x20 0x44 0x65 0x6e"    # "Dragon's Den" from the result fragment above
[raspberrypi:/service00e5/char00df]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa5
[raspberrypi:/service00e5/char00e1]# write "0x## 0x## ....."                                                # PSK generated above, must be 32 bytes
[raspberrypi:/service00db/char00e1]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa3
[raspberrypi:/service00db/char00dc]# write 01                                                               # connect
```

Please refer to the server log to see that the connection has been established.

```
[raspberrypi:/service00db/char00e1]# select-attribute 811ce666-22e0-4a6d-a50f-0c78e076faa3
[raspberrypi:/service00db/char00dc]# write 00                                                               # disconnect
```

