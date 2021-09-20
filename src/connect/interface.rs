pub async fn connect(ssid: Vec<u8>, psk: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path("/var/run/wpa_supplicant/wlan0")
        .open()
        .unwrap();

    let _disconnect_response = wpa.request("DISCONNECT")?;

    let ssid_request = format!("SET_NETWORK 0 ssid \"{:}\"", String::from_utf8(ssid)?);
    let _ssid_set_response = wpa.request(&ssid_request)?;

    let mut psk_hex: String = String::new();
    for byte in psk {
        psk_hex = psk_hex + &format!("{:02x}", byte);
    }
    let psk_request = format!("SET_NETWORK 0 psk {:}", psk_hex);
    let _psk_set_response = wpa.request(&psk_request)?;

    let _select_response = wpa.request("SELECT_NETWORK 0")?;

    let _save_config_response = wpa.request("SAVE_CONFIG")?;

    let _reconfig_response = wpa.request("RECONFIGURE")?;

    let _reconnect_response = wpa.request("RECONNECT")?;

    Ok(())
}

pub async fn disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path("/var/run/wpa_supplicant/wlan0")
        .open()
        .unwrap();
    let _output = wpa.request("DISCONNECT")?;
    Ok(())
}

pub async fn status() -> Result<(u8, String), Box<dyn std::error::Error>> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path("/var/run/wpa_supplicant/wlan0")
        .open()
        .unwrap();
    let output = wpa.request("STATUS")?;
    let mut state = 0u8;
    let mut ip = "<unknown>";
    let lines = output.lines();
    for line in lines {
        let pair: Vec<&str> = line.splitn(2, '=').collect();
        if pair[0] == "wpa_state" {
            if pair[1] == "COMPLETED" {
                state = 1u8;
            } else {
                state = 0u8;
            }
        } else if pair[0] == "ip_address" {
            ip = pair[1];
        }
    }

    Ok((state, ip.to_string()))
}
