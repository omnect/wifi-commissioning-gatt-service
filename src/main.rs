pub mod connect;
pub mod scan;

use bluer::{adv::Advertisement, gatt::local::Application};
use connect::ConnectService;
use scan::ScanService;
use std::{collections::BTreeMap, time::Duration};
use tokio::time::interval;

const MANUFACTURER_ID: u16 = 0xc6c6;

async fn get_adapter() -> Result<(bluer::Adapter, String), String> {
    let session = bluer::Session::new().await.map_err(|e| e.to_string())?;
    println!("got session");
    let adapter_names = session.adapter_names().await.map_err(|e| e.to_string())?;
    println!("got adapter");
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
    env_logger::init();

    let adapter: bluer::Adapter;
    let adapter_name: String;
    loop {
        let adapter_and_name = get_adapter().await;
        match adapter_and_name {
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

    println!(
        "Advertising on Bluetooth adapter {} with address {}",
        &adapter_name,
        adapter.address().await?
    );
    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(MANUFACTURER_ID, vec![0x21, 0x22, 0x23, 0x24]);
    let le_advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![scan::SCAN_SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some("DmWifiConfig".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(le_advertisement).await?;

    println!(
        "Adv instances {}",
        adapter.active_advertising_instances().await?
    );

    println!(
        "Serving GATT service on Bluetooth adapter {}",
        &adapter_name
    );

    let mut scan_service = ScanService::new();
    let mut connect_service = ConnectService::new();

    // (initial) values for the characteristics

    let app = Application {
        services: vec![
            scan_service.service_entry(),
            connect_service.service_entry(),
        ],
    };
    let _app_handle = adapter.serve_gatt_application(app).await?;

    let mut interval = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                connect_service.tick().await;
            }
        }
    }

    // println!("Removing service and advertisement");
    // drop(app_handle);
    // drop(adv_handle);
    // sleep(Duration::from_secs(1)).await;

    // Ok(())
}
