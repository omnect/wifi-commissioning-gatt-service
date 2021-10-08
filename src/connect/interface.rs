pub async fn connect(interface: String, ssid: Vec<u8>, psk: Vec<u8>) -> Result<(), String> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(format!("/var/run/wpa_supplicant/{}", interface))
        .open()
        .map_err(|e| e.to_string())?;

    let disconnect_response = wpa.request("DISCONNECT").map_err(|e| e.to_string())?;
    if disconnect_response.trim() == "FAIL" {
        return Err("Disconnect failed.".to_string());
    }

    let remove_network_response = wpa.request("REMOVE_NETWORK 0").map_err(|e| e.to_string())?;
    if remove_network_response.trim() == "FAIL" {
        println!(
            "REMOVE_NETWORK 0 failed, but this is ok if there was no network in config before."
        );
    }

    let add_network_response = wpa.request("ADD_NETWORK").map_err(|e| e.to_string())?;
    if add_network_response.trim() == "FAIL" {
        return Err("ADD_NETWORK failed.".to_string());
    }
    if add_network_response.trim() != "0" {
        return Err(format!(
            "ADD_NETWORK succeeded but returned {} instead of 0.",
            add_network_response
        ));
    }

    let ssid_utf8 = String::from_utf8(ssid).map_err(|e| e.to_string())?;
    let ssid_request = format!("SET_NETWORK 0 ssid \"{:}\"", ssid_utf8);
    let ssid_set_response = wpa.request(&ssid_request).map_err(|e| e.to_string())?;
    if ssid_set_response.trim() == "FAIL" {
        return Err("SET_NETWORK 0 ssid failed.".to_string());
    }

    let mut psk_hex: String = String::new();
    for byte in psk {
        psk_hex = psk_hex + &format!("{:02x}", byte);
    }
    let psk_request = format!("SET_NETWORK 0 psk {:}", psk_hex);
    let psk_set_response = wpa.request(&psk_request).map_err(|e| e.to_string())?;
    if psk_set_response.trim() == "FAIL" {
        return Err("SET_NETWORK 0 psk failed.".to_string());
    }

    let select_response = wpa.request("SELECT_NETWORK 0").map_err(|e| e.to_string())?;
    if select_response.trim() == "FAIL" {
        return Err("SELECT_NETWORK 0 failed.".to_string());
    }

    let save_config_response = wpa.request("SAVE_CONFIG").map_err(|e| e.to_string())?;
    if save_config_response.trim() == "FAIL" {
        return Err("SAVE_CONFIG failed.".to_string());
    }

    let reconfig_response = wpa.request("RECONFIGURE").map_err(|e| e.to_string())?;
    if reconfig_response.trim() == "FAIL" {
        return Err("RECONFIGURE failed.".to_string());
    }

    let reconnect_response = wpa.request("RECONNECT").map_err(|e| e.to_string())?;
    if reconnect_response.trim() == "FAIL" {
        return Err("RECONNECT failed.".to_string());
    }

    Ok(())
}

pub async fn disconnect(interface: String) -> Result<(), String> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(format!("/var/run/wpa_supplicant/{}", interface))
        .open()
        .map_err(|e| e.to_string())?;
    let output = wpa.request("DISCONNECT").map_err(|e| e.to_string())?;
    if output.trim() == "FAIL" {
        return Err("DISCONNECT failed.".to_string());
    }
    Ok(())
}

pub async fn status(interface: String) -> Result<(u8, String), String> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(format!("/var/run/wpa_supplicant/{}", interface))
        .open()
        .map_err(|e| e.to_string())?;
    let output = wpa.request("STATUS").map_err(|e| e.to_string())?;
    if output.trim() == "FAIL" {
        return Err("STATUS failed.".to_string());
    }
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
