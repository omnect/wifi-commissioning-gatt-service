use bluer::gatt::local::{
    characteristic_control, service_control, Characteristic, CharacteristicNotifier,
    CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicRead,
    CharacteristicReadRequest, CharacteristicWrite, CharacteristicWriteMethod,
    CharacteristicWriteRequest, ReqError, ReqResult, Service,
};
use enclose::enclose;
use futures::FutureExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use wifiscanner;

const RESULT_FIELD_LENGTH: usize = 100;

pub const SCAN_SERVICE_UUID: uuid::Uuid = uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c863);
const STATUS_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa0);
const SELECT_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa1);
const RESULT_SCAN_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa2);

const STATUS_SCAN_IDLE: u8 = 0u8;
const STATUS_SCAN_SCAN: u8 = 1u8;
const STATUS_SCAN_FINISHED: u8 = 2u8;
const STATUS_SCAN_ERROR: u8 = 3u8;

struct ScanSharedData {
    // Scan status, u8
    // 0: Idle
    // 1: Scanning
    // 2: Scan Finished
    // 3: Error
    // Client is expected to write an 1 to start scan.
    // When scan is finished, server will set this value to 2 or 3.
    // Client is epxected to write a 0 to finish scan handling, allowing server to discard scan results.
    status_scan_value: Mutex<Vec<u8>>,
    // Current field that a read from the result characteristic will return.
    // The index of this fields is set by writing select_scan_value.
    result_scan_value: Mutex<Vec<u8>>,
    // Holds the whole scan results, before split into fields that is done into result_scan_value
    results: Mutex<Vec<u8>>,
    // Number of fields that splitting 'results' into RESULT_FIELD_LENGTH sized fields yielded
    select_max_records: Mutex<u8>,
    // Scan select result, u8
    // After a scan has finished (status 2), the client shall read this
    // characteristic to query the number of records the client needs
    // to read to capture all the scan output. The client will when write
    // to this characteristic the index of the result record to read (starting at 0),
    // then read the result characteristic (see below) to fetch the record,
    // and then increment this characteristic until all records have been read.
    select_scan_value: Mutex<Vec<u8>>,
    // Notifier instance for status_scan_value. Only one notification client is supported.
    status_scan_notify_opt: Mutex<Option<CharacteristicNotifier>>,
}

impl ScanSharedData {
    fn new() -> ScanSharedData {
        ScanSharedData {
            status_scan_value: Mutex::new(vec![STATUS_SCAN_IDLE]),
            result_scan_value: Mutex::new(vec![0; RESULT_FIELD_LENGTH]),
            results: Mutex::new(vec![]),
            select_max_records: Mutex::new(0u8),
            select_scan_value: Mutex::new(vec![0x00]),
            status_scan_notify_opt: Mutex::new(Option::None),
        }
    }
}

async fn read_result(
    shared: Arc<ScanSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    let result_scan_value = shared.result_scan_value.lock().await.clone();
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

async fn read_status(
    shared: Arc<ScanSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    let status_scan_value = shared.status_scan_value.lock().await.clone();
    println!(
        "Scan status read request {:?} with value {:x?}",
        &req, &status_scan_value
    );
    Ok(status_scan_value)
}

async fn write_status(
    shared: Arc<ScanSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
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
    let mut status_scan_value = shared.status_scan_value.lock().await;
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
        let mut results_store = shared.results.lock().await;
        let mut select_max_records = shared.select_max_records.lock().await;
        let mut select_scan_value = shared.select_scan_value.lock().await;
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
                status_scan_value[0] = STATUS_SCAN_FINISHED; // scan finished
                let max_fields = (json.len() + (RESULT_FIELD_LENGTH - 1)) / RESULT_FIELD_LENGTH;
                if max_fields < 255 {
                    *select_max_records = max_fields as u8;
                    select_scan_value[0] = max_fields as u8;
                    *results_store = json.as_bytes().to_vec();
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
        let mut opt = shared.status_scan_notify_opt.lock().await;
        if let Some(writer) = opt.as_mut() {
            println!("Notifying scan status with value {:x?}", &status_scan_value);
            if let Err(err) = writer.notify(status_scan_value.clone()).await {
                println!("Notification stream error: {}", &err);
                *opt = None;
            }
        }
    } else if new_value[0] == STATUS_SCAN_IDLE && old != STATUS_SCAN_IDLE {
        // 1 -> 0: Discard results
        let mut results_store = shared.results.lock().await;
        *results_store = vec![0; RESULT_FIELD_LENGTH]; // clear results
        let mut select_max_records = shared.select_max_records.lock().await;
        *select_max_records = 0u8;
        let mut select_scan_value = shared.select_scan_value.lock().await;
        select_scan_value[0] = 0u8;
    }
    Ok(())
}

async fn start_notify_status(shared: Arc<ScanSharedData>, notifier: CharacteristicNotifier) {
    println!(
        "Status scan accepting notify, confirming {}",
        notifier.confirming()
    );
    let mut opt = shared.status_scan_notify_opt.lock().await;
    *opt = Some(notifier);
}

async fn read_select(
    shared: Arc<ScanSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    let select_scan_value = shared.select_scan_value.lock().await.clone();
    println!(
        "Scan select read request {:?} with value {:x?}",
        &req, &select_scan_value
    );
    Ok(select_scan_value)
}

async fn write_select(
    shared: Arc<ScanSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
    println!(
        "Scan select write request {:?} with value {:x?}",
        &req, &new_value
    );
    if new_value.len() > 1 {
        println!("Scan select write invalid length.");
        return Err(ReqError::NotSupported.into());
    }
    let select_max_records = shared.select_max_records.lock().await;
    if new_value[0] >= *select_max_records {
        println!(
            "Scan status write invalid index, expected to be < {:x?}.",
            select_max_records
        );
        return Err(ReqError::NotSupported.into());
    }
    let mut results_store = shared.result_scan_value.lock().await;
    let results_all = shared.results.lock().await;
    let offset: usize = (new_value[0] as usize) * RESULT_FIELD_LENGTH;
    let mut size: usize = RESULT_FIELD_LENGTH;
    if offset + size > results_all.len() {
        size = results_all.len() - offset;
    }
    let slice = &results_all[offset..(offset + size)];
    let vector: Vec<u8> = slice.iter().cloned().collect();
    *results_store = vector;
    let mut select_scan_value = shared.select_scan_value.lock().await;
    *select_scan_value = new_value;
    Ok(())
}

pub struct ScanService {
    shared: Arc<ScanSharedData>,
}

impl ScanService {
    pub fn new() -> ScanService {
        ScanService {
            shared: Arc::new(ScanSharedData::new()),
        }
    }
    pub fn service_entry(&mut self) -> Service {
        let shared = self.shared.clone();
        let (_scan_service_control, scan_service_handle) = service_control();
        let (_status_scan_char_control, status_scan_char_handle) = characteristic_control();
        let (_select_scan_char_control, select_scan_char_handle) = characteristic_control();
        let (_result_scan_char_control, result_scan_char_handle) = characteristic_control();
        Service {
            uuid: SCAN_SERVICE_UUID,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: STATUS_SCAN_CHAR_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(
                            enclose!( (shared) move |req| read_status(shared.clone(), req).boxed()),
                        ),
                        ..Default::default()
                    }),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(
                            enclose!( (shared) move|new_value, req| {
                                let shared = shared.clone();
                                write_status(shared, new_value, req).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Fun(Box::new(
                            enclose!( (shared) move|notifier| {
                                let shared = shared.clone();
                                start_notify_status(shared, notifier).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    control_handle: status_scan_char_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: SELECT_SCAN_CHAR_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(
                            enclose!( (shared) move |req| read_select(shared.clone(), req).boxed()),
                        ),
                        ..Default::default()
                    }),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(
                            enclose!( (shared) move |new_value, req| {
                                let shared = shared.clone();
                                write_select(shared, new_value, req).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    control_handle: select_scan_char_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: RESULT_SCAN_CHAR_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(
                            enclose!( (shared) move |req| read_result(shared.clone(), req).boxed()),
                        ),
                        ..Default::default()
                    }),
                    control_handle: result_scan_char_handle,
                    ..Default::default()
                },
            ],
            control_handle: scan_service_handle,
            ..Default::default()
        }
    }
}
