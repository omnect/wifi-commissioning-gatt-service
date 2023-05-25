use crate::authorize;
use bluer::gatt::local::{
    characteristic_control, service_control, Characteristic, CharacteristicNotifier,
    CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicRead,
    CharacteristicReadRequest, CharacteristicWrite, CharacteristicWriteMethod,
    CharacteristicWriteRequest, ReqError, ReqResult, Service,
};
use enclose::enclose;
use futures::FutureExt;
use log::{debug, error, info};
use std::convert::TryFrom;
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
const SSID_MAX_LENGTH: usize = 32;
const PSK_LENGTH: usize = 32;

#[derive(Clone, Copy)]
#[repr(u8)]
enum ConnectionState {
    Idle = 0u8,
    Connect = 1u8,
    Connected = 2u8,
    Failed = 3u8,
}

impl std::convert::TryFrom<u8> for ConnectionState {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let result = match value {
            0u8 => ConnectionState::Idle,
            1u8 => ConnectionState::Connect,
            2u8 => ConnectionState::Connected,
            3u8 => ConnectionState::Failed,
            _ => Err(format!("invalid connection state: {}", value))?,
        };

        Ok(result)
    }
}

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
    authorized: Arc<Mutex<dyn Authorized + Send + Sync>>,
    interface: String,
}

impl ConnectSharedData {
    fn new(interf: String, auth: Arc<Mutex<dyn Authorized + Send + Sync>>) -> ConnectSharedData {
        ConnectSharedData {
            state_connect_value: Mutex::new(vec![ConnectionState::Idle as u8]),
            ssid_connect_value: Mutex::new(vec![0; SSID_MAX_LENGTH]),
            psk_connect_value: Mutex::new(vec![0; PSK_LENGTH]),
            state_connect_notify_opt: Mutex::new(Option::None),
            authorized: auth,
            interface: interf,
        }
    }
}

async fn read_state(
    shared: Arc<ConnectSharedData>,
    req: CharacteristicReadRequest,
) -> ReqResult<Vec<u8>> {
    if !shared.authorized.lock().await.is_authorized().await {
        error!("Connect state read no auth {:?}", &req);
        return Err(ReqError::NotAuthorized);
    }
    let state_connect_value = shared.state_connect_value.lock().await.clone();
    info!("Connect state read request {:?}", &req);
    debug!(" with value {:x?}", &state_connect_value);
    Ok(state_connect_value)
}

async fn write_state(
    shared: Arc<ConnectSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
    if !shared.authorized.lock().await.is_authorized().await {
        error!("Connect state write no auth {:?}", &req);
        return Err(ReqError::NotAuthorized);
    }
    info!("Connect state write request {:?}", &req);
    debug!(" with value {:x?}", &new_value);
    if new_value.len() > 1 {
        error!("Connect state write invalid length.");
        return Err(ReqError::InvalidValueLength);
    }
    let new_state = match ConnectionState::try_from(new_value[0]) {
        Ok(state @ (ConnectionState::Idle | ConnectionState::Connect)) => state,
        _ => {
            error!("Connect state write invalid status, expected either 0 or 1.");
            return Err(ReqError::NotSupported);
        }
    };
    let mut state_connect_value = shared.state_connect_value.lock().await;
    let old_state = ConnectionState::try_from(state_connect_value[0]).unwrap(); // this cannot fail
    state_connect_value[0] = new_state as u8;
    match (old_state, new_state) {
        (ConnectionState::Idle | ConnectionState::Connected, ConnectionState::Connect) => {
            // connect
            let ssid_connect_value = shared.ssid_connect_value.lock().await;
            let psk_connect_value = shared.psk_connect_value.lock().await;
            let result = interface::connect(
                shared.interface.clone(),
                ssid_connect_value.clone(),
                psk_connect_value.clone(),
            )
            .await;
            match result {
                Err(e) => {
                    error!("Connect failed: {:?}", e);
                    state_connect_value[0] = ConnectionState::Failed as u8;
                    return Err(ReqError::Failed);
                }
                Ok(_o) => {
                    info!("Connect successful, waiting for ip");
                }
            }
        }
        (_old, ConnectionState::Connect) => {
            // invalid
            error!(
                "Invalid connection state transition from {} to {}.",
                old_state as u8, new_state as u8
            );
            return Err(ReqError::NotSupported);
        }
        (_old, ConnectionState::Idle) => {
            // disconnect
            let result = interface::disconnect(shared.interface.clone()).await;
            match result {
                Err(e) => {
                    error!("Disconnect failed: {:?}", e);
                    state_connect_value[0] = ConnectionState::Failed as u8;
                    return Err(ReqError::Failed);
                }
                Ok(_o) => {
                    info!("Disconnect successful");
                }
            }
        }
        (_old, ConnectionState::Connected | ConnectionState::Failed) => {
            // unreachable
        }
    };

    let mut opt = shared.state_connect_notify_opt.lock().await;
    if let Some(writer) = opt.as_mut() {
        info!(
            "Notifying connect state with value {:x?}",
            &state_connect_value
        );
        if let Err(err) = writer.notify(state_connect_value.clone()).await {
            error!("Notification stream error: {}", &err);
            *opt = None;
        }
    }
    Ok(())
}

async fn start_notify_state(shared: Arc<ConnectSharedData>, notifier: CharacteristicNotifier) {
    info!(
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
    if !shared.authorized.lock().await.is_authorized().await {
        error!("Connect SSID read no auth {:?}", &req);
        return Err(ReqError::NotAuthorized);
    }
    let ssid_connect_value = shared.ssid_connect_value.lock().await.clone();
    info!("Connect SSID read request {:?}", &req);
    debug!(" with value {:x?}", &ssid_connect_value);
    let offset = req.offset as usize;
    let mtu = req.mtu as usize;
    if offset > ssid_connect_value.len() {
        error!("Connect SSID returning invalid offset");
        return Err(ReqError::InvalidOffset);
    }
    let mut size = ssid_connect_value.len() - offset;
    if size > mtu {
        size = mtu;
    }
    let slice = &ssid_connect_value[offset..(offset + size)];
    let vector: Vec<u8> = slice.to_vec();
    debug!("Connect SSID read request returning {:x?}", &vector);
    Ok(vector)
}

async fn write_ssid(
    shared: Arc<ConnectSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
    if !shared.authorized.lock().await.is_authorized().await {
        error!("Connect SSID write no auth {:?}", &req);
        return Err(ReqError::NotAuthorized);
    }
    info!("Connect SSID write request {:?}", &req);
    debug!(" with value {:x?}", &new_value);
    let offset = req.offset as usize;
    let len = new_value.len();
    if len + offset > SSID_MAX_LENGTH {
        error!("Connect SSID write invalid length.");
        return Err(ReqError::InvalidValueLength);
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
    if !shared.authorized.lock().await.is_authorized().await {
        error!("Connect PSK write no auth {:?}", &req);
        return Err(ReqError::NotAuthorized);
    }
    info!("Connect PSK write request {:?}", &req);
    debug!(" with value {:x?}", &new_value);
    let offset = req.offset as usize;
    let len = new_value.len();
    if len + offset > PSK_LENGTH {
        error!("Connect PSK write invalid length.");
        return Err(ReqError::InvalidValueLength);
    }
    let mut psk_connect_value = shared.psk_connect_value.lock().await;
    psk_connect_value.splice(offset..offset + len, new_value.iter().cloned());
    Ok(())
}

use authorize::Authorized;

pub struct ConnectService {
    shared: Arc<ConnectSharedData>,
}

impl ConnectService {
    pub fn new(
        interface: String,
        auth: Arc<Mutex<dyn Authorized + Send + Sync>>,
    ) -> ConnectService {
        ConnectService {
            shared: Arc::new(ConnectSharedData::new(interface, auth)),
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
        if let Ok(ConnectionState::Connect) = ConnectionState::try_from(state_connect_value[0]) {
            let result = interface::status(self.shared.interface.clone()).await;
            match result {
                Err(e) => {
                    error!("Status failed: {:?}", e);
                    state_connect_value[0] = ConnectionState::Failed as u8;
                    notify = true;
                }
                Ok((status, ip)) => {
                    if status == 1u8 && ip != "<unknown>" {
                        info!("Connected with ip {:?}", ip);
                        state_connect_value[0] = ConnectionState::Connected as u8;
                        notify = true
                    }
                }
            }
        }
        if notify {
            let mut opt = self.shared.state_connect_notify_opt.lock().await;
            if let Some(writer) = opt.as_mut() {
                info!(
                    "Notifying connect state with value {:x?}",
                    &state_connect_value
                );
                if let Err(err) = writer.notify(state_connect_value.clone()).await {
                    error!("Notification stream error: {}", &err);
                    *opt = None;
                }
            }
        }
    }
}
