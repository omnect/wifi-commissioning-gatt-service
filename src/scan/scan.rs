// Wrap wifiscanner::Error into own type since that one does not implement std::error::Error

#[derive(Debug)]
struct ScanError {
    internal: wifiscanner::Error,
}

impl ScanError {
    fn new(e: wifiscanner::Error) -> ScanError {
        ScanError { internal: e }
    }
}

impl std::error::Error for ScanError {
    fn description(&self) -> &str {
        match &self.internal {
            wifiscanner::Error::SyntaxRegexError => "SyntaxRegexError",
            wifiscanner::Error::CommandNotFound => "CommandNotFound",
            wifiscanner::Error::NoMatch => "NoMatch",
            wifiscanner::Error::FailedToParse => "FailedToParse",
            wifiscanner::Error::NoValue => "NoValue",
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub async fn scan() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let scan_task = tokio::task::spawn_blocking(|| {
        println!("Starting SSID scan");
        let scan_result = wifiscanner::scan();
        println!("Finished SSID scan");
        scan_result
    });
    let scan_task_result = scan_task.await;
    match scan_task_result {
        Ok(Ok(found_hotspots)) => {
            let mut json: String = String::new();
            json.push_str("[");
            for item in found_hotspots {
                if json.len() > 1 {
                    json.push_str(",");
                }
                json.push_str(&format!(
                    "{{\"ssid\":\"{}\",\
                       \"rssi\":\"{}\",\
                       \"mac\":\"{}\",\
                       \"ch\":\"{}\"}}",
                    item.ssid, item.signal_level, item.mac, item.channel
                ));
            }
            json.push_str("]");
            println!("Scan successful: {:?}", json);
            return Ok(json.as_bytes().to_vec());
        }
        Ok(Err(e)) => {
            return Err(Box::new(ScanError::new(e)));
        }
        Err(e) => {
            return Err(Box::new(e));
        }
    }
}
