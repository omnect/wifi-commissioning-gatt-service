pub mod authorize;
pub mod connect;
pub mod scan;

use authorize::AuthorizeService;
use bluer::{adv::Advertisement, gatt::local::Application};
use clap::Parser;
use connect::ConnectService;
use log::{debug, info};
use scan::ScanService;
use std::{collections::BTreeMap, env, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::time::interval;

#[derive(Parser)]
#[clap(version, author)]
struct Opts {
    /// (wireless) network interface name
    #[clap(short, long, default_value = "wlan0")]
    interface: String,

    /// secret shared between client and server used for BLE communication
    #[clap(short, long)]
    ble_secret: String,
}

static DEFAULT_SCAN_SERVICE_BEACON: &str = "omnectWifiConfig";

// company ID: 0xffff == default for company not member in Bluetooth SIG
const MANUFACTURER_ID: u16 = 0xffff;
// manufacturer data: "_cp_"
const MANUFACTURER_ID_VAL: [u8; 4] = [0x5f, 0x63, 0x70, 0x5f];

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
                adapter_name = n;
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
    let local_name =
        env::var("SCAN_SERVICE_BEACON").unwrap_or((*DEFAULT_SCAN_SERVICE_BEACON).to_string());
    let le_advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![scan::SCAN_SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some(local_name),
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

    let authorize_service = Arc::new(Mutex::new(AuthorizeService::new(opts.ble_secret.clone())));
    let mut scan_service = ScanService::new(opts.interface.clone(), authorize_service.clone());
    let mut connect_service =
        ConnectService::new(opts.interface.clone(), authorize_service.clone());

    let app = Application {
        services: vec![
            scan_service.service_entry(),
            connect_service.service_entry(),
            authorize_service.clone().lock().await.service_entry(),
        ],
        _non_exhaustive: (),
    };
    let _app_handle = adapter.serve_gatt_application(app).await?;

    let mut interval = interval(Duration::from_secs(1));

    #[cfg(feature = "systemd")]
    {
        sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    }

    loop {
        interval.tick().await; // blocks for 1s
        connect_service.tick().await;
        authorize_service.clone().lock().await.tick().await;
    }
}
