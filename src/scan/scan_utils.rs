use log::{debug, error, info};
use std::fmt::Write;

fn unescape_hex(ssid: &str) -> Vec<u8> {
    let re = regex::bytes::Regex::new(r"\\(\\|(x([0-9a-fA-F]{2})))").unwrap();
    let out = re.replace_all(ssid.as_bytes(), |caps: &regex::bytes::Captures| {
        if caps[0] == [0x5Cu8, 0x5Cu8] {
            [0x5Cu8]
        } else {
            [u8::from_str_radix(std::str::from_utf8(&caps[3]).unwrap(), 16).unwrap()]
        }
    });
    out.to_vec()
}

fn escape_invalid_unicode(bytestring: Vec<u8>) -> String {
    let mut escaped = String::with_capacity(bytestring.len() * 2);
    let mut bytes: &[u8] = &bytestring;
    loop {
        let s = std::str::from_utf8(bytes);
        match s {
            Err(e) => {
                error!("Decoding {:?} failed: {}", bytes, e.to_string());
                let (good, bad) = bytes.split_at(e.valid_up_to());
                if !good.is_empty() {
                    escaped += std::str::from_utf8(good).unwrap(); // this cannot fail
                }
                write!(&mut escaped, "{:#04X}", bad[0] as u8).unwrap();
                bytes = &bytes[(e.valid_up_to() + 1)..]; // skip the offending byte
            }
            Ok(s) => {
                escaped += s;
                return escaped;
            }
        }
    }
}

fn escape_json(bytestring: Vec<u8>) -> String {
    let mut escaped = String::with_capacity(bytestring.len() * 2);
    let unescaped_str = escape_invalid_unicode(bytestring);
    for c in unescaped_str.chars() {
        match c {
            '"' => escaped += "\\\"",
            '\\' => escaped += "\\\\",
            '\x08' => escaped += "\\b",
            '\n' => escaped += "\\n",
            '\r' => escaped += "\\r",
            '\x0C' => escaped += "\\f",
            '\t' => escaped += "\\t",
            c if c < ' ' => write!(&mut escaped, "\\u00{:02X}", c as u16).unwrap(),
            c if c >= '\u{10000}' => {
                let u = c as u32 - 0x10000u32;
                let h = (u >> 10) as u16 + 0xD800u16;
                let l = (u & 0x03FFu32) as u16 + 0xDC00u16;
                write!(&mut escaped, "\\u{:04X}\\u{:04X}", h, l).unwrap()
            }
            c if c > '~' => write!(&mut escaped, "\\u{:04X}", c as u16).unwrap(),
            c => escaped.push(c),
        }
    }
    escaped
}

fn parse_aps(aps: &str) -> String {
    let re = regex::Regex::new(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\t([0-9]+)\t(-?[0-9]+)\t((\[[a-zA-Z0-9+-]+\]))*\t([^\n]*)\n").unwrap();
    let mut json: String = String::new();
    json.push('[');
    for cap in re.captures_iter(aps) {
        if json.len() > 1 {
            json.push(',');
        }
        write!(
            &mut json,
            "{{\"ssid\":\"{}\",\
               \"rssi\":\"{}\",\
               \"mac\":\"{}\",\
               \"ch\":\"{}\"}}",
            escape_json(unescape_hex(&cap[7])),
            &cap[4],
            &cap[1],
            &cap[3]
        )
        .unwrap();
    }
    json.push(']');
    json
}

pub async fn scan(interface: String) -> Result<Vec<u8>, String> {
    let scan_task = tokio::task::spawn_blocking(move || {
        info!("Starting SSID scan");
        let mut wpa = wpactrl::Client::builder()
            .ctrl_path(format!("/var/run/wpa_supplicant/{}", interface))
            .open()
            .map_err(|e| e.to_string())?;
        let output = wpa.request("SCAN").map_err(|e| e.to_string())?;
        if output.trim() == "FAIL" {
            return Err("SCAN failed.".to_string());
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
        let output = wpa.request("SCAN_RESULTS").map_err(|e| e.to_string())?;
        if output.trim() == "FAIL" {
            return Err("SCAN_RESULTS failed.".to_string());
        }
        info!("Finished SSID scan");
        Ok(output)
    });
    let scan_task_result = scan_task.await.map_err(|e| e.to_string())?;
    match scan_task_result {
        Ok(found_hotspots) => {
            let json = parse_aps(&found_hotspots);
            debug!("Scan successful: {:?}", json);
            return Ok(json.as_bytes().to_vec());
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_invalid_unicode() {
        let v1: Vec<u8> = vec![
            0xF0u8, 0x00u8, 0x08u8, 0x01u8, 0x5Cu8, 0x02u8, 0x0Cu8, 0x03u8, 0xFFu8, 0x0Au8, 0xf0u8,
            0x9fu8, 0x92u8, 0xa9u8, 0x0Du8, 0xF1u8, 0x22u8, 0x09u8,
        ];
        let unescaped =
            unescape_hex(r"\xF0\x00\x08\x01\\\x02\x0C\x03\xFF\x0A\xf0\x9f\x92\xa9\x0D\xF1\x22\x09");
        assert_eq!(unescaped, v1);
        assert_eq!(
            escape_invalid_unicode(v1.clone()),
            "0xF0\x00\x08\x01\x5C\x02\x0C\x030xFF\x0A💩\x0D0xF1\x22\x09"
        );
        assert_eq!(
            escape_json(v1),
            "0xF0\\u0000\\b\\u0001\\\\\\u0002\\f\\u00030xFF\\n\\uD83D\\uDCA9\\r0xF1\\\"\\t"
        )
    }
    #[test]
    fn test_parse() {
        let input = r#"01:02:03:04:05:06	1234	-99	[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS]	SomeName\xf0\x9f\x92\xa9
        02:03:04:05:06:07	2345	-98	[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS]	\x00\x00\\\x00\\\x01\x01\x01
        03:04:05:06:07:08	3456	-97	[WPA2-PSK-CCMP][WPS][ESS]	"SomeOtherName"
        04:05:06:07:08:09	4567	-96	[WPA2-PSK-CCMP][ESS]	
        "#;
        let output = parse_aps(input);
        assert_eq!(
            output,
            r#"[{"ssid":"SomeName\uD83D\uDCA9","rssi":"-99","mac":"01:02:03:04:05:06","ch":"1234"},{"ssid":"\u0000\u0000\\\u0000\\\u0001\u0001\u0001","rssi":"-98","mac":"02:03:04:05:06:07","ch":"2345"},{"ssid":"\"SomeOtherName\"","rssi":"-97","mac":"03:04:05:06:07:08","ch":"3456"},{"ssid":"","rssi":"-96","mac":"04:05:06:07:08:09","ch":"4567"}]"#
        );
    }
}
