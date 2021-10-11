pub mod authorize;
pub mod connect;
pub mod scan;

use authorize::AuthorizeService;
use bluer::{adv::Advertisement, gatt::local::Application};
use clap::{AppSettings, Clap};
use connect::ConnectService;
use log::{debug, info};
use scan::ScanService;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::time::interval;

#[derive(Clap)]
#[clap(version = "0.1.4", author = "Roland Erk <roland.erk@conplement.de")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(short, long, default_value = "wlan0")]
    interface: String,
    #[clap(short, long)]
    device_id: String,
}

const MANUFACTURER_ID: u16 = 0xc6c6;
const MANUFACTURER_ID_VAL: [u8; 4] = [0x21, 0x22, 0x23, 0x24];

async fn get_adapter() -> Result<(bluer::Adapter, String), String> {
    let session = bluer::Session::new().await.map_err(|e| e.to_string())?;
    debug!("got session");
    let adapter_names = session.adapter_names().await.map_err(|e| e.to_string())?;
    debug!("got adapter");
    let adapter_name = adapter_names.first();
    match adapter_name {
        Some(s) => Ok((
            session.adapter(s).map_err(|e| e.to_string())?,
            s.to_string(),
        )),
        None => Err("No adapter found".to_string()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opts: Opts = Opts::parse();

    let adapter: bluer::Adapter;
    let adapter_name: String;
    loop {
        match get_adapter().await {
            Ok((a, n)) => {
                adapter = a;
                adapter_name = n.to_string();
            }
            Err(_e) => {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        break;
    }
    adapter.set_powered(true).await?;

    info!(
        "Advertising on Bluetooth adapter {} with address {}",
        &adapter_name,
        adapter.address().await?
    );
    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(MANUFACTURER_ID, MANUFACTURER_ID_VAL.to_vec());
    let le_advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![scan::SCAN_SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some("DmWifiConfig".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(le_advertisement).await?;

    debug!(
        "Adv instances {}",
        adapter.active_advertising_instances().await?
    );

    info!(
        "Serving GATT service on Bluetooth adapter {}",
        &adapter_name
    );

    let authorize_service = Arc::new(Mutex::new(AuthorizeService::new(opts.device_id.clone())));
    let mut scan_service = ScanService::new(opts.interface.clone(), authorize_service.clone());
    let mut connect_service =
        ConnectService::new(opts.interface.clone(), authorize_service.clone());

    let app = Application {
        services: vec![
            scan_service.service_entry(),
            connect_service.service_entry(),
            authorize_service.clone().lock().await.service_entry(),
        ],
    };
    let _app_handle = adapter.serve_gatt_application(app).await?;

    let mut interval = interval(Duration::from_secs(1));

    loop {
        interval.tick().await; // blocks for 1s
        connect_service.tick().await;
        authorize_service.clone().lock().await.tick().await;
    }
}
