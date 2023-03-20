use async_trait::async_trait;
use bluer::gatt::local::{
    characteristic_control, service_control, Characteristic, CharacteristicWrite,
    CharacteristicWriteMethod, CharacteristicWriteRequest, ReqError, ReqResult, Service,
};
use enclose::enclose;
use futures::FutureExt;
use log::{debug, error, info, warn};
use sha3::Digest;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[async_trait]
pub trait Authorized {
    async fn is_authorized(&self) -> bool;
}

pub const AUTHORIZE_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c865);
const KEY_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa6);
const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(300);

struct AuthorizeSharedData {
    key: Mutex<Vec<u8>>,
    authorized_timeout: Mutex<std::time::Duration>,
    device_id: String,
}

impl AuthorizeSharedData {
    fn new(id: String) -> AuthorizeSharedData {
        AuthorizeSharedData {
            key: Mutex::new(vec![0; sha3::Sha3_256::output_size()]),
            authorized_timeout: Mutex::new(Duration::from_secs(0)),
            device_id: id,
        }
    }
}

async fn write_key(
    shared: Arc<AuthorizeSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
    info!("Key write request {:?}", &req);
    debug!(" value {:x?}", &new_value);
    let offset = req.offset as usize;
    let len = new_value.len();
    if len + offset > sha3::Sha3_256::output_size() {
        error!("Key write invalid length.");
        return Err(ReqError::InvalidValueLength);
    }
    let mut key = shared.key.lock().await;
    key.splice(offset..offset + len, new_value.iter().cloned());
    let hash = sha3::Sha3_256::digest(shared.device_id.as_bytes());
    if hash.to_vec() == *key {
        info!("Authorization granted.");
        let mut counter = shared.authorized_timeout.lock().await;
        *counter = AUTHORIZE_TIMEOUT;
    } else {
        warn!("Authorization failed.");
        let mut counter = shared.authorized_timeout.lock().await;
        *counter = Duration::from_secs(0);
        // note that if BLE client does not support 32 byte writes, this case
        // will be entered at least once for a partial write, so we must not
        // reset the key here.
    }
    Ok(())
}

pub struct AuthorizeService {
    shared: Arc<AuthorizeSharedData>,
}

impl AuthorizeService {
    pub fn new(device_id: String) -> AuthorizeService {
        AuthorizeService {
            shared: Arc::new(AuthorizeSharedData::new(device_id)),
        }
    }
    pub fn service_entry(&mut self) -> Service {
        let shared = self.shared.clone();
        let (_authorize_service_control, authorize_service_key_handle) = service_control();
        let (_key_char_control, key_char_handle) = characteristic_control();
        Service {
            uuid: AUTHORIZE_SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: KEY_CHAR_UUID,
                write: Some(CharacteristicWrite {
                    write: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(
                        enclose!( (shared) move|new_value, req| {
                            write_key(shared.clone(), new_value, req).boxed()
                        }),
                    )),
                    ..Default::default()
                }),
                control_handle: key_char_handle,
                ..Default::default()
            }],
            control_handle: authorize_service_key_handle,
            ..Default::default()
        }
    }
    pub async fn tick(&mut self) {
        let mut authorized_timeout = self.shared.authorized_timeout.lock().await;
        if !authorized_timeout.is_zero() {
            *authorized_timeout -= Duration::from_secs(1);
            if authorized_timeout.is_zero() {
                info!("Authorization expired.");
                let mut key = self.shared.key.lock().await;
                // clear the key
                *key = vec![0; sha3::Sha3_256::output_size()];
            }
        }
    }
}

#[async_trait]
impl Authorized for AuthorizeService {
    async fn is_authorized(&self) -> bool {
        let authorized_timeout = self.shared.authorized_timeout.lock().await;
        return !authorized_timeout.is_zero();
    }
}
