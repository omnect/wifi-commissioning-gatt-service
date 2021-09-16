use bluer::{
    adv::Advertisement,
    gatt::{
        local::{
            characteristic_control, service_control, Application, Characteristic,
            CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
            CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod, ReqError, Service,
        },
        CharacteristicWriter,
    },
};
use enclose::enclose;
use futures::{pin_mut, FutureExt, StreamExt};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::Mutex,
    time::{interval, sleep},
};
use wifiscanner;

const SCAN_SERVICE_UUID: uuid::Uuid = uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c863);
const STATUS_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa0);
const SELECT_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa1);
const RESULT_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa2);

const CONNECT_SERVICE_UUID: uuid::Uuid = uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c864);
const STATE_CONNECT_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa3);
const SSID_CONNECT_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa4);
const PSK_CONNECT_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa5);
const SECURITY_CONNECT_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa6);

const MANUFACTURER_ID: u16 = 0xc6c6;

const RESULT_FIELD_LENGTH: usize = 100;

async fn connect(ssid: Vec<u8>, psk: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
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

async fn disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path("/var/run/wpa_supplicant/wlan0")
        .open()
        .unwrap();
    let _output = wpa.request("DISCONNECT")?;
    Ok(())
}

async fn status() -> Result<(u8, String), Box<dyn std::error::Error>> {
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    env_logger::init();

    let session = bluer::Session::new().await?;
    let adapter_names = session.adapter_names().await?;
    let adapter_name = adapter_names.first().expect("No Bluetooth adapter present");
    let adapter = session.adapter(adapter_name)?;
    adapter.set_powered(true).await?;

    println!(
        "Advertising on Bluetooth adapter {} with address {}",
        &adapter_name,
        adapter.address().await?
    );
    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(MANUFACTURER_ID, vec![0x21, 0x22, 0x23, 0x24]);
    let le_advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![SCAN_SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some("DmWifiConfig".to_string()),
        ..Default::default()
    };
    let adv_handle = adapter.advertise(le_advertisement).await?;

    println!(
        "Adv instances {}",
        adapter.active_advertising_instances().await?
    );

    println!(
        "Serving GATT service on Bluetooth adapter {}",
        &adapter_name
    );

    let (_scan_service_control, scan_service_handle) = service_control();
    let (status_scan_char_control, status_scan_char_handle) = characteristic_control();
    let (_select_scan_char_control, select_scan_char_handle) = characteristic_control();
    let (_result_scan_char_control, result_scan_char_handle) = characteristic_control();
    let (_connect_service_control, connect_service_handle) = service_control();
    let (state_connect_char_control, state_connect_char_handle) = characteristic_control();
    let (_ssid_connect_char_control, ssid_connect_char_handle) = characteristic_control();
    let (_psk_connect_char_control, psk_connect_char_handle) = characteristic_control();
    let (_security_connect_char_control, security_connect_char_handle) = characteristic_control();

    // (initial) values for the characteristics

    // Holds the whole scan results, before split into fields that is done into result_scan_value
    let results = Arc::new(Mutex::new(vec![]));

    // Number of fields that splitting 'results' into RESULT_FIELD_LENGTH sized fields yielded
    let select_max_records = Arc::new(Mutex::new(0u8));

    // Current field that a read from the result characteristic will return.
    // The index of this fields is set by writing select_scan_value.
    let result_scan_value = Arc::new(Mutex::new(vec![0; RESULT_FIELD_LENGTH]));

    // Scan select result, u8
    // After a scan has finished (status 2), the client shall read this
    // characteristic to query the number of records the client needs
    // to read to capture all the scan output. The client will when write
    // to this characteristic the index of the result record to read (starting at 0),
    // then read the result characteristic (see below) to fetch the record,
    // and then increment this characteristic until all records have been read.
    let select_scan_value = Arc::new(Mutex::new(vec![0x00]));

    // Scan status, u8
    // 0: Idle
    // 1: Scanning
    // 2: Scan Finished
    // 3: Error
    // Client is expected to write an 1 to start scan.
    // When scan is finished, server will set this value to 2 or 3.
    // Client is epxected to write a 0 to finish scan handling, allowing server to discard scan results.
    const STATUS_SCAN_IDLE: u8 = 0u8;
    const STATUS_SCAN_SCAN: u8 = 1u8;
    const STATUS_SCAN_FINISHED: u8 = 2u8;
    const STATUS_SCAN_ERROR: u8 = 3u8;
    let status_scan_value = Arc::new(Mutex::new(vec![STATUS_SCAN_IDLE]));

    // Notifier instance for status_scan_value. Only one notification client is supported.
    let status_scan_notify_opt: Arc<Mutex<Option<CharacteristicWriter>>> =
        Arc::new(Mutex::new(Option::None));

    // Connect state, u8
    // 0: Idle
    // 1: Connect
    // 2: Connected
    // 3: Connection failed
    // Client is expected to write an 1 after setting ssid and psk to connect to this AP.
    // When connection is finished, server will set this value to 2 or 3.
    // Client is epxected to write a 0 to disconnect from the AP.
    const STATE_CONNECT_IDLE: u8 = 0u8;
    const STATE_CONNECT_CONNECT: u8 = 1u8;
    const STATE_CONNECT_CONNECTED: u8 = 2u8;
    const STATE_CONNECT_FAILED: u8 = 3u8;
    let state_connect_value = Arc::new(Mutex::new(vec![STATE_CONNECT_IDLE]));
    let state_connect_notify_opt: Arc<Mutex<Option<CharacteristicWriter>>> =
        Arc::new(Mutex::new(Option::None));

    // SSID of the Ap to connect to
    let ssid_connect_value = Arc::new(Mutex::new(vec![0; 32]));

    // The PSK is expected to be 32 bytes and calculated as
    // PSK = PBKDF2(HMAC−SHA1, passphrase, ssid, 4096, 256)
    // see https://en.wikipedia.org/wiki/PBKDF2
    let psk_connect_value = Arc::new(Mutex::new(vec![0; 32]));

    // ------- handling of RESULT_SCAN_CHAR_UUID -------
    let result_scan_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( (result_scan_value) move |req| {
            enclose!( (result_scan_value) async move {
                let result_scan_value = result_scan_value.lock().await.clone();
                println!(
                    "Scan result read request {:?} with value {:x?}",
                    &req, &result_scan_value
                );
                let offset = req.offset as usize;
                let mtu = req.mtu as usize;
                if offset > result_scan_value.len() {
                    println!("Scan result returning invalid offset");
                    return Err(ReqError::InvalidOffset.into());
                }
                let mut size = result_scan_value.len() - offset;
                if size > mtu {
                    size = mtu;
                }
                let slice = &result_scan_value[offset..(offset + size)];
                let vector: Vec<u8> = slice.iter().cloned().collect();
                println!("Scan result read request returning {:x?}", &vector);
                Ok(vector)
            }
            .boxed())
        })),
        ..Default::default()
    };

    // ------- handling of SELECT_SCAN_CHAR_UUID -------
    let select_scan_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( (select_scan_value) move |req| {
            enclose!( (select_scan_value) async move {
                let select_scan_value = select_scan_value.lock().await.clone();
                println!(
                    "Scan select read request {:?} with value {:x?}",
                    &req, &select_scan_value
                );
                Ok(select_scan_value)
            }
            .boxed())
        })),
        ..Default::default()
    };

    let select_scan_char_write = CharacteristicWrite {
        write: true,
        write_without_response: true,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( (select_scan_value, results, result_scan_value, select_max_records)
                move |new_value, req| {
                    enclose!( (select_scan_value, results, result_scan_value, select_max_records)
                    async move {
                        println!(
                            "Scan select write request {:?} with value {:x?}",
                            &req, &new_value
                        );
                        if new_value.len() > 1 {
                            println!("Scan select write invalid length.");
                            return Err(ReqError::NotSupported.into());
                        }
                        let select_max_records = select_max_records.lock().await;
                        if new_value[0] >= *select_max_records {
                            println!(
                                "Scan status write invalid index, expected to be < {:x?}.",
                                select_max_records
                            );
                            return Err(ReqError::NotSupported.into());
                        }
                        let mut results_store = result_scan_value.lock().await;
                        let results_all = results.lock().await;
                        let offset: usize = (new_value[0] as usize) * RESULT_FIELD_LENGTH;
                        let mut size: usize = RESULT_FIELD_LENGTH;
                        if offset + size > results_all.len() {
                            size = results_all.len() - offset;
                        }
                        let slice = &results_all[offset..(offset + size)];
                        let vector: Vec<u8> = slice.iter().cloned().collect();
                        *results_store = vector;
                        let mut select_scan_value = select_scan_value.lock().await;
                        *select_scan_value = new_value;
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };

    // ------- handling of STATUS_SCAN_CHAR_UUID -------
    let status_scan_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( (status_scan_value) move |req| {
            enclose!( (status_scan_value) async move {
                let status_scan_value = status_scan_value.lock().await.clone();
                println!(
                    "Scan status read request {:?} with value {:x?}",
                    &req, &status_scan_value
                );
                Ok(status_scan_value)
            }
            .boxed())
        })),
        ..Default::default()
    };

    let status_scan_char_write = CharacteristicWrite {
        write: true,
        write_without_response: true,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( (status_scan_value, results, select_max_records, status_scan_notify_opt, select_scan_value ) move |new_value, req| {
                enclose!( (status_scan_value, results, select_max_records, status_scan_notify_opt, select_scan_value ) async move {
                    println!(
                        "Scan status write request {:?} with value {:x?}",
                        &req, &new_value
                    );
                    if new_value.len() > 1 {
                        println!("Scan status write invalid length.");
                        return Err(ReqError::NotSupported.into());
                    }
                    if new_value[0] != STATUS_SCAN_IDLE && new_value[0] != STATUS_SCAN_SCAN {
                        println!("Scan status write invalid status, expected either 0 or 1.");
                        return Err(ReqError::NotSupported.into());
                    }
                    let mut status_scan_value = status_scan_value.lock().await;
                    let old = status_scan_value[0];
                    status_scan_value[0] = new_value[0];
                    // 0 -> 1: Start scan
                    if new_value[0] == STATUS_SCAN_SCAN && old == STATUS_SCAN_IDLE {
                        let scan_task = tokio::task::spawn_blocking(|| {
                            println!("Starting SSID scan");
                            let scan_result = wifiscanner::scan();
                            println!("Finished SSID scan");
                            scan_result
                        });
                        let scan_task_result = scan_task.await;
                        let mut results_store = results.lock().await;
                        let mut select_max_records = select_max_records.lock().await;
                        let mut select_scan_value = select_scan_value.lock().await;
                        match scan_task_result {
                            Ok(Ok(found_hotspots)) => {
                                let found_hotspots = format!("{:?}", found_hotspots);
                                println!("Scan successful: {:?}", found_hotspots);
                                status_scan_value[0] = STATUS_SCAN_FINISHED; // scan finished
                                let max_fields = (found_hotspots.len() + (RESULT_FIELD_LENGTH - 1))
                                    / RESULT_FIELD_LENGTH;
                                if max_fields < 255 {
                                    *select_max_records = max_fields as u8;
                                    select_scan_value[0] = max_fields as u8;
                                    *results_store = found_hotspots.as_bytes().to_vec();
                                } else {
                                    println!("Scan failed due to too many results");
                                    status_scan_value[0] = STATUS_SCAN_ERROR; // scan failed
                                }
                            }
                            Ok(Err(e)) => {
                                println!("Scan failed: {:?}", e);
                                status_scan_value[0] = STATUS_SCAN_ERROR; // scan failed
                            }
                            Err(e) => {
                                println!("Scan failed: {:?}", e);
                                status_scan_value[0] = STATUS_SCAN_ERROR; // scan failed
                            }
                        }
                        let mut opt = status_scan_notify_opt.lock().await;
                        if let Some(writer) = opt.as_mut() {
                            println!("Notifying scan status with value {:x?}", &status_scan_value);
                            if let Err(err) = writer.write(&status_scan_value).await {
                                println!("Notification stream error: {}", &err);
                                *opt = None;
                            }
                        }
                    } else if new_value[0] == STATUS_SCAN_IDLE && old != STATUS_SCAN_IDLE {
                        // 1 -> 0: Discard results
                        let mut results_store = results.lock().await;
                        *results_store = vec![0; RESULT_FIELD_LENGTH]; // clear results
                        let mut select_max_records = select_max_records.lock().await;
                        *select_max_records = 0u8;
                        let mut select_scan_value = select_scan_value.lock().await;
                        select_scan_value[0] = 0u8;
                    }
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };

    let status_scan_char_notify = CharacteristicNotify {
        notify: true,
        method: CharacteristicNotifyMethod::Io,
        ..Default::default()
    };

    // ------- handling of STATE_CONNECT_CHAR_UUID -------

    let state_connect_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( (state_connect_value) move |req| {
            enclose!( (state_connect_value) async move {
                let state_connect_value = state_connect_value.lock().await.clone();
                println!(
                    "Connect state read request {:?} with value {:x?}",
                    &req, &state_connect_value
                );
                Ok(state_connect_value)
            }
            .boxed())
        })),
        ..Default::default()
    };

    let state_connect_char_write = CharacteristicWrite {
        write: true,
        write_without_response: true,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( ( state_connect_value, psk_connect_value, ssid_connect_value, state_connect_notify_opt ) move |new_value, req| {
                enclose!( ( state_connect_value, psk_connect_value, ssid_connect_value, state_connect_notify_opt ) async move {
                    println!(
                        "Connect state write request {:?} with value {:x?}",
                        &req, &new_value
                    );
                    if new_value.len() > 1 {
                        println!("Connect state write invalid length.");
                        return Err(ReqError::NotSupported.into());
                    }
                    if new_value[0] != 0 && new_value[0] != 1 {
                        println!("Connect state write invalid status, expected either 0 or 1.");
                        return Err(ReqError::NotSupported.into());
                    }
                    let mut state_connect_value = state_connect_value.lock().await;
                    let old = state_connect_value[0];
                    state_connect_value[0] = new_value[0];
                    if new_value[0] == STATE_CONNECT_CONNECT && old == STATE_CONNECT_IDLE {
                        // 0 -> 1: connect
                        let ssid_connect_value = ssid_connect_value.lock().await;
                        let psk_connect_value = psk_connect_value.lock().await;
                        let result =
                            connect(ssid_connect_value.clone(), psk_connect_value.clone()).await;
                        match result {
                            Err(e) => {
                                println!("Connect failed: {:?}", e);
                                state_connect_value[0] = STATE_CONNECT_FAILED;
                                return Err(ReqError::Failed.into());
                            }
                            Ok(_o) => {
                                println!("Connect successful, waiting for ip");
                            }
                        }
                    } else if new_value[0] == STATE_CONNECT_IDLE && old != STATE_CONNECT_IDLE {
                        // 1 -> 0: disconnect
                        let result = disconnect().await;
                        match result {
                            Err(e) => {
                                println!("Disconnect failed: {:?}", e);
                                state_connect_value[0] = STATE_CONNECT_FAILED;
                                return Err(ReqError::Failed.into());
                            }
                            Ok(_o) => {
                                println!("Disconnect successful");
                            }
                        }
                    }

                    let mut opt = state_connect_notify_opt.lock().await;
                    if let Some(writer) = opt.as_mut() {
                        println!(
                            "Notifying connect state with value {:x?}",
                            &state_connect_value
                        );
                        if let Err(err) = writer.write(&state_connect_value).await {
                            println!("Notification stream error: {}", &err);
                            *opt = None;
                        }
                    }
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };
    let state_connect_char_notify = CharacteristicNotify {
        notify: true,
        method: CharacteristicNotifyMethod::Io,
        ..Default::default()
    };

    let ssid_connect_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( ( ssid_connect_value ) move |req| {
            enclose!( ( ssid_connect_value ) async move {
                let ssid_connect_value = ssid_connect_value.lock().await.clone();
                println!(
                    "Connect SSID read request {:?} with value {:x?}",
                    &req, &ssid_connect_value
                );
                let offset = req.offset as usize;
                let mtu = req.mtu as usize;
                if offset > ssid_connect_value.len() {
                    println!("Connect SSID returning invalid offset");
                    return Err(ReqError::InvalidOffset.into());
                }
                let mut size = ssid_connect_value.len() - offset;
                if size > mtu {
                    size = mtu;
                }
                let slice = &ssid_connect_value[offset..(offset + size)];
                let vector: Vec<u8> = slice.iter().cloned().collect();
                println!("Connect SSID read request returning {:x?}", &vector);
                Ok(vector)
            }
            .boxed())
        })),
        ..Default::default()
    };

    let ssid_connect_char_write = CharacteristicWrite {
        write: true,
        // due to its length, this characteristic cannot be written with only one Write command,
        // so a write without response is not possible
        write_without_response: false,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( ( ssid_connect_value ) move |new_value, req| {
                enclose!( ( ssid_connect_value ) async move {
                    println!(
                        "Connect SSID write request {:?} with value {:x?}",
                        &req, &new_value
                    );
                    let offset = req.offset as usize;
                    let len = new_value.len();
                    if len + offset > 32 {
                        println!("Connect SSID write invalid length.");
                        return Err(ReqError::NotSupported.into());
                    }
                    let mut ssid_connect_value = ssid_connect_value.lock().await;
                    ssid_connect_value.splice(offset..offset + len, new_value.iter().cloned());
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };

    let psk_connect_char_write = CharacteristicWrite {
        write: true,
        // due to its length, this characteristic cannot be written with only one Write command,
        // so a write without response is not possible
        write_without_response: false,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( ( psk_connect_value ) move |new_value, req| {
                enclose!( ( psk_connect_value ) async move {
                    println!(
                        "Connect PSK write request {:?} with value {:x?}",
                        &req, &new_value
                    );
                    let offset = req.offset as usize;
                    let len = new_value.len();
                    if len + offset > 32 {
                        println!("Connect PSK write invalid length.");
                        return Err(ReqError::NotSupported.into());
                    }
                    let mut psk_connect_value = psk_connect_value.lock().await;
                    psk_connect_value.splice(offset..offset + len, new_value.iter().cloned());
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };

    let security_connect_value = Arc::new(Mutex::new(vec![0]));

    let security_connect_char_read = CharacteristicRead {
        read: true,
        fun: Box::new(enclose!( (security_connect_value) move |req| {
            enclose!( (security_connect_value) async move {
                let security_connect_value = security_connect_value.lock().await.clone();
                println!(
                    "Connect security read request {:?} with value {:x?}",
                    &req, &security_connect_value
                );
                Ok(security_connect_value)
            }
            .boxed())
        })),
        ..Default::default()
    };

    let security_connect_char_write = CharacteristicWrite {
        write: true,
        write_without_response: true,
        method: CharacteristicWriteMethod::Fun(Box::new(
            enclose!( (security_connect_value ) move |new_value, req| {
                enclose!( (security_connect_value ) async move {
                    println!(
                        "Connect state write request {:?} with value {:x?}",
                        &req, &new_value
                    );
                    if new_value.len() > 1 {
                        println!("Connect security write invalid length.");
                        return Err(ReqError::NotSupported.into());
                    }
                    let mut security_connect_value = security_connect_value.lock().await;
                    *security_connect_value = new_value;
                    Ok(())
                }
                .boxed())
            }),
        )),
        ..Default::default()
    };

    let app = Application {
        services: vec![
            Service {
                uuid: SCAN_SERVICE_UUID,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: STATUS_SCAN_CHAR_UUID,
                        read: Some(status_scan_char_read),
                        write: Some(status_scan_char_write),
                        notify: Some(status_scan_char_notify),
                        control_handle: status_scan_char_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: SELECT_SCAN_CHAR_UUID,
                        read: Some(select_scan_char_read),
                        write: Some(select_scan_char_write),
                        control_handle: select_scan_char_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: RESULT_SCAN_CHAR_UUID,
                        read: Some(result_scan_char_read),
                        control_handle: result_scan_char_handle,
                        ..Default::default()
                    },
                ],
                control_handle: scan_service_handle,
                ..Default::default()
            },
            Service {
                uuid: CONNECT_SERVICE_UUID,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: STATE_CONNECT_CHAR_UUID,
                        read: Some(state_connect_char_read),
                        write: Some(state_connect_char_write),
                        notify: Some(state_connect_char_notify),
                        control_handle: state_connect_char_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: SSID_CONNECT_CHAR_UUID,
                        read: Some(ssid_connect_char_read),
                        write: Some(ssid_connect_char_write),
                        control_handle: ssid_connect_char_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: PSK_CONNECT_CHAR_UUID,
                        write: Some(psk_connect_char_write),
                        control_handle: psk_connect_char_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: SECURITY_CONNECT_CHAR_UUID,
                        read: Some(security_connect_char_read),
                        write: Some(security_connect_char_write),
                        control_handle: security_connect_char_handle,
                        ..Default::default()
                    },
                ],
                control_handle: connect_service_handle,
                ..Default::default()
            },
        ],
    };
    let app_handle = adapter.serve_gatt_application(app).await?;

    let mut interval = interval(Duration::from_secs(1));
    pin_mut!(status_scan_char_control);
    pin_mut!(state_connect_char_control);

    loop {
        tokio::select! {
            evt = status_scan_char_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Write(_req)) => {
                        println!("Status scan unexpected IO write event");
                    },
                    Some(CharacteristicControlEvent::Notify(notifier)) => {
                        println!("Status scan accepting notify request event with MTU {}", notifier.mtu());
                        let mut opt = status_scan_notify_opt.lock().await;
                        *opt = Some(notifier);
                    },
                    None => break,
                }
            }
            evt = state_connect_char_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Write(_req)) => {
                        println!("State connect unexpected IO write event");
                    },
                    Some(CharacteristicControlEvent::Notify(notifier)) => {
                        println!("State connect accepting notify request event with MTU {}", notifier.mtu());
                        let mut opt = state_connect_notify_opt.lock().await;
                        *opt = Some(notifier);
                    },
                    None => break,
                }
            }
            _ = interval.tick() => {
                let mut state_connect_value = state_connect_value.lock().await;
                if state_connect_value[0] == STATE_CONNECT_CONNECT {
                    let result = status().await;
                    match result {
                        Err(e) => {
                            println!("Status failed: {:?}", e);
                            state_connect_value[0] = STATE_CONNECT_FAILED;
                        }
                        Ok((status, ip)) => {
                            if status == 1u8 && ip != "<unknown>" {
                                println!("Connected with ip {:?}", ip);
                                state_connect_value[0] = STATE_CONNECT_CONNECTED;
                            }
                        }
                    }
                }
            }
        }
    }

    println!("Removing service and advertisement");
    drop(app_handle);
    drop(adv_handle);
    sleep(Duration::from_secs(1)).await;

    Ok(())
}
