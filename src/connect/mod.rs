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

pub mod interface;

pub const CONNECT_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c864);
const STATE_CONNECT_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa3);
const SSID_CONNECT_CHAR_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa4);
const PSK_CONNECT_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa5);

const STATE_CONNECT_IDLE: u8 = 0u8;
const STATE_CONNECT_CONNECT: u8 = 1u8;
const STATE_CONNECT_CONNECTED: u8 = 2u8;
const STATE_CONNECT_FAILED: u8 = 3u8;

struct ConnectSharedData {
    // Connect state, u8
    // 0: Idle
    // 1: Connect
    // 2: Connected
    // 3: Connection failed
    // Client is expected to write an 1 after setting ssid and psk to connect to this AP.
    // When connection is finished, server will set this value to 2 or 3.
    // Client is epxected to write a 0 to disconnect from the AP.
    state_connect_value: Mutex<Vec<u8>>,
    // Notifier instance for state_connect_value. Only one notification client is supported.
    state_connect_notify_opt: Mutex<Option<CharacteristicNotifier>>,
    // SSID of the AP to connect to
    ssid_connect_value: Mutex<Vec<u8>>,
    // The PSK is expected to be 32 bytes and calculated as
    // PSK = PBKDF2(HMAC−SHA1, passphrase, ssid, 4096, 256)
    // see https://en.wikipedia.org/wiki/PBKDF2
    psk_connect_value: Mutex<Vec<u8>>,
}

impl ConnectSharedData {
    fn new() -> ConnectSharedData {
        ConnectSharedData {
            state_connect_value: Mutex::new(vec![STATE_CONNECT_IDLE]),
            ssid_connect_value: Mutex::new(vec![0; 32]),
            psk_connect_value: Mutex::new(vec![0; 32]),
            state_connect_notify_opt: Mutex::new(Option::None),
        }
    }
}

async fn read_state(
    shared: Arc<ConnectSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    let state_connect_value = shared.state_connect_value.lock().await.clone();
    println!(
        "Connect state read request {:?} with value {:x?}",
        &req, &state_connect_value
    );
    Ok(state_connect_value)
}

async fn write_state(
    shared: Arc<ConnectSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
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
    let mut state_connect_value = shared.state_connect_value.lock().await;
    let old = state_connect_value[0];
    state_connect_value[0] = new_value[0];
    if new_value[0] == STATE_CONNECT_CONNECT && old == STATE_CONNECT_IDLE {
        // 0 -> 1: connect
        let ssid_connect_value = shared.ssid_connect_value.lock().await;
        let psk_connect_value = shared.psk_connect_value.lock().await;
        let result =
            interface::connect(ssid_connect_value.clone(), psk_connect_value.clone()).await;
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
        let result = interface::disconnect().await;
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

    let mut opt = shared.state_connect_notify_opt.lock().await;
    if let Some(writer) = opt.as_mut() {
        println!(
            "Notifying connect state with value {:x?}",
            &state_connect_value
        );
        if let Err(err) = writer.notify(state_connect_value.clone()).await {
            println!("Notification stream error: {}", &err);
            *opt = None;
        }
    }
    Ok(())
}

async fn start_notify_state(shared: Arc<ConnectSharedData>, notifier: CharacteristicNotifier) {
    println!(
        "State connect accepting notify, confirming {}",
        notifier.confirming()
    );
    let mut opt = shared.state_connect_notify_opt.lock().await;
    *opt = Some(notifier);
}

async fn read_ssid(
    shared: Arc<ConnectSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    let ssid_connect_value = shared.ssid_connect_value.lock().await.clone();
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

async fn write_ssid(
    shared: Arc<ConnectSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
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
    let mut ssid_connect_value = shared.ssid_connect_value.lock().await;
    // The SSID field is variable length, and the user might write first a long ssid
    // and then a shorter one. We should not leave characters from the first write
    // in the value, so clear it here.
    if offset == 0 {
        ssid_connect_value.clear();
    }
    let mut endoffset = offset + len;
    if endoffset > ssid_connect_value.len() {
        endoffset = ssid_connect_value.len();
    }
    ssid_connect_value.splice(offset..endoffset, new_value.iter().cloned());
    Ok(())
}

async fn write_psk(
    shared: Arc<ConnectSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
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
    let mut psk_connect_value = shared.psk_connect_value.lock().await;
    psk_connect_value.splice(offset..offset + len, new_value.iter().cloned());
    Ok(())
}

pub struct ConnectService {
    shared: Arc<ConnectSharedData>,
}

impl ConnectService {
    pub fn new() -> ConnectService {
        ConnectService {
            shared: Arc::new(ConnectSharedData::new()),
        }
    }
    pub fn service_entry(&mut self) -> Service {
        let shared = self.shared.clone();
        let (_connect_service_control, connect_service_handle) = service_control();
        let (_state_connect_scan_char_control, state_connect_char_handle) =
            characteristic_control();
        let (_ssid_connect_char_control, ssid_connect_char_handle) = characteristic_control();
        let (_psk_connect_scan_char_control, psk_connect_char_handle) = characteristic_control();
        Service {
            uuid: CONNECT_SERVICE_UUID,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: STATE_CONNECT_CHAR_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(
                            enclose!( (shared) move |req| read_state(shared.clone(), req).boxed()),
                        ),
                        ..Default::default()
                    }),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(
                            enclose!( (shared) move|new_value, req| {
                                let shared = shared.clone();
                                write_state(shared, new_value, req).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Fun(Box::new(
                            enclose!( (shared) move|notifier| {
                                let shared = shared.clone();
                                start_notify_state(shared, notifier).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    control_handle: state_connect_char_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: SSID_CONNECT_CHAR_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(
                            enclose!( (shared) move |req| read_ssid(shared.clone(), req).boxed()),
                        ),
                        ..Default::default()
                    }),
                    write: Some(CharacteristicWrite {
                        write: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(
                            enclose!( (shared) move |new_value, req| {
                                let shared = shared.clone();
                                write_ssid(shared, new_value, req).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    control_handle: ssid_connect_char_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: PSK_CONNECT_CHAR_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(
                            enclose!( (shared) move |new_value, req| {
                                let shared = shared.clone();
                                write_psk(shared, new_value, req).boxed()
                            }),
                        )),
                        ..Default::default()
                    }),
                    control_handle: psk_connect_char_handle,
                    ..Default::default()
                },
            ],
            control_handle: connect_service_handle,
            ..Default::default()
        }
    }
    pub async fn tick(&mut self) {
        let mut notify = false;
        let mut state_connect_value = self.shared.state_connect_value.lock().await;
        if state_connect_value[0] == STATE_CONNECT_CONNECT {
            let result = interface::status().await;
            match result {
                Err(e) => {
                    println!("Status failed: {:?}", e);
                    state_connect_value[0] = STATE_CONNECT_FAILED;
                    notify = true;
                }
                Ok((status, ip)) => {
                    if status == 1u8 && ip != "<unknown>" {
                        println!("Connected with ip {:?}", ip);
                        state_connect_value[0] = STATE_CONNECT_CONNECTED;
                        notify = true
                    }
                }
            }
        }
        if notify {
            let mut opt = self.shared.state_connect_notify_opt.lock().await;
            if let Some(writer) = opt.as_mut() {
                println!(
                    "Notifying connect state with value {:x?}",
                    &state_connect_value
                );
                if let Err(err) = writer.notify(state_connect_value.clone()).await {
                    println!("Notification stream error: {}", &err);
                    *opt = None;
                }
            }
        }
    }
}
