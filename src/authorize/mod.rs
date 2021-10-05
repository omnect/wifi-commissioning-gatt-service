use async_trait::async_trait;
use bluer::gatt::local::{
    characteristic_control, service_control, Characteristic, CharacteristicWrite,
    CharacteristicWriteMethod, CharacteristicWriteRequest, ReqError, ReqResult, Service,
};
use enclose::enclose;
use futures::FutureExt;
use sha3::Digest;
use std::sync::Arc;
use tokio::sync::Mutex;

#[async_trait]
pub trait Authorized {
    async fn is_authorized(&self) -> bool;
}

pub const AUTHORIZE_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xd69a37ee1d8a4329bd2425db4af3c865);
const KEY_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(0x811ce66622e04a6da50f0c78e076faa6);
const AUTHORIZE_COUNT: u16 = 300u16;

struct AuthorizeSharedData {
    key: Mutex<Vec<u8>>,
    authorized_counter: Mutex<u16>,
    device_id: String,
}

impl AuthorizeSharedData {
    fn new(id: String) -> AuthorizeSharedData {
        AuthorizeSharedData {
            key: Mutex::new(vec![0; 32]),
            authorized_counter: Mutex::new(0u16),
            device_id: id,
        }
    }
}

async fn write_key(
    shared: Arc<AuthorizeSharedData>,
    new_value: Vec<u8>,
    req: CharacteristicWriteRequest,
) -> ReqResult<()> {
    println!("Key write request {:?} with value {:x?}", &req, &new_value);
    let offset = req.offset as usize;
    let len = new_value.len();
    if len + offset > 32 {
        println!("Key write invalid length.");
        return Err(ReqError::NotSupported.into());
    }
    let mut key = shared.key.lock().await;
    key.splice(offset..offset + len, new_value.iter().cloned());
    let hash = sha3::Sha3_256::digest(shared.device_id.as_bytes());
    if hash.to_vec() == *key {
        println!("Authorization granted.");
        let mut counter = shared.authorized_counter.lock().await;
        *counter = AUTHORIZE_COUNT;
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
                            let shared = shared.clone();
                            write_key(shared, new_value, req).boxed()
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
        let shared = self.shared.clone();
        let mut authorized_counter = shared.authorized_counter.lock().await;
        if *authorized_counter != 0 {
            *authorized_counter -= 1;
            if *authorized_counter == 0 {
                println!("Authorization expired.");
            }
        }
    }
}

#[async_trait]
impl Authorized for AuthorizeService {
    async fn is_authorized(&self) -> bool {
        return *self.shared.clone().authorized_counter.lock().await != 0;
    }
}
