// This work is based on the example 'Read Characteristic Value Changed' 
// contributed by the Google Chrome Team at 
// https://googlechrome.github.io/samples/web-bluetooth/
// It has been modified by the Silicon Labs Apps Team to support an 
// application of Wi-Fi commissioning using Web BLE.
// It is made available as an example under the terms of the 
// Apache License, Version 2.0


// Wi-Fi Scanner Service BLE GATT Services And Characteristic UUIDs
const SVC_WIFI_SCANNER_UUID             = 'd69a37ee-1d8a-4329-bd24-25db4af3c863';
const CHR_WIFI_SCANNER_STATE_UUID       = '811ce666-22e0-4a6d-a50f-0c78e076faa0';
const CHR_WIFI_SCANNER_RESULT_UUID      = '811ce666-22e0-4a6d-a50f-0c78e076faa2';
const CHR_WIFI_SCANNER_SELECT_UUID      = '811ce666-22e0-4a6d-a50f-0c78e076faa1';

// Wi-Fi Configurator Service BLE GATT Services And Characteristic UUIDs
const SVC_WIFI_CONFIG_UUID              = 'd69a37ee-1d8a-4329-bd24-25db4af3c864';
const CHR_WIFI_CONFIG_STATE_UUID        = '811ce666-22e0-4a6d-a50f-0c78e076faa3';
const CHR_WIFI_CONFIG_SSID_UUID         = '811ce666-22e0-4a6d-a50f-0c78e076faa4';
const CHR_WIFI_CONFIG_PASSWORD_UUID     = '811ce666-22e0-4a6d-a50f-0c78e076faa5';

const SVC_WIFI_AUTH_UUID                = 'd69a37ee-1d8a-4329-bd24-25db4af3c865';
const CHR_WIFI_AUTH_KEY_UUID            = '811ce666-22e0-4a6d-a50f-0c78e076faa6';

// Wi-Fi Scanner State Machine States
const WIFI_SCANNER_STATE_IDLE     = 0;
const WIFI_SCANNER_STATE_SCAN     = 1;
const WIFI_SCANNER_STATE_SCANNED  = 2;
const WIFI_SCANNER_STATE_ERROR    = 3;

// Wi-Fi Config State Machine States
const WIFI_CONFIG_STATE_IDLE      = 0;
const WIFI_CONFIG_STATE_CONNECT   = 1;
const WIFI_CONFIG_STATE_JOINED    = 2;
const WIFI_CONFIG_STATE_ERROR     = 3;

const BLE_SECRET = 'some-random-id';

// Global Variables
var bluetoothDevice;
var wifiScannerStateCharacteristic;
var wifiConfigStateCharacteristic;
var accessPointsObj = [];


// This function requests BLE devices nearby 
// with the device prefix name 'DmWifiConfig'.
async function requestDevice() {
  log('> Requesting Bluetooth Devices DmWifiConfig*...');
  bluetoothDevice = await navigator.bluetooth.requestDevice({
      filters: [{namePrefix: 'DmWifiConfig'}],
      optionalServices: [SVC_WIFI_SCANNER_UUID, SVC_WIFI_CONFIG_UUID, SVC_WIFI_AUTH_UUID]
      });
  bluetoothDevice.addEventListener('gattserverdisconnected', onDisconnected);
}


// This function handles the event 'gattserverdisconnected'
async function onDisconnected() {
  log('> Bluetooth Device disconnected');
  try {
    await connectDeviceAndCacheCharacteristics()
  } catch (error) {
    log('> Error: ' + error);
  }
}


// This function connects the web browser to the BLE device and
// gets the Services and their corresponding Characteristics.
async function connectDeviceAndCacheCharacteristics() {
  if (bluetoothDevice.gatt.connected && 
      wifiScannerStateCharacteristic &&
      wifiConfigStateCharacteristic) {
    return;
  }

  log('> Connecting to GATT Server...');
  const server = await bluetoothDevice.gatt.connect();

  log('> Getting the Wi-Fi Scanner Service...');
  const wifiScannerService = await server.getPrimaryService(SVC_WIFI_SCANNER_UUID);

  log('> Getting the Wi-Fi Scanner Characteristics...');
  wifiScannerStateCharacteristic = await wifiScannerService.getCharacteristic(CHR_WIFI_SCANNER_STATE_UUID);
  wifiScannerStateCharacteristic.addEventListener('characteristicvaluechanged',
      handleWiFiScannerStateChanged);

  wifiScannerAP_Result_Characteristic = await wifiScannerService.getCharacteristic(CHR_WIFI_SCANNER_RESULT_UUID);

  wifiScannerAP_Select_Characteristic = await wifiScannerService.getCharacteristic(CHR_WIFI_SCANNER_SELECT_UUID);

  log('> Getting the Wi-Fi Configurator Service...');
  const wifiConfigService = await server.getPrimaryService(SVC_WIFI_CONFIG_UUID);

  log('> Getting the Wi-Fi Configurator Characteristics...');
  wifiConfigStateCharacteristic = await wifiConfigService.getCharacteristic(CHR_WIFI_CONFIG_STATE_UUID);
  wifiConfigStateCharacteristic.addEventListener('characteristicvaluechanged',
      handleWiFiConfigStateChanged);

  wifiConfigSSIDCharacteristic = await wifiConfigService.getCharacteristic(CHR_WIFI_CONFIG_SSID_UUID);
  wifiConfigPskCharacteristic = await wifiConfigService.getCharacteristic(CHR_WIFI_CONFIG_PASSWORD_UUID);

  const wifiAuthService = await server.getPrimaryService(SVC_WIFI_AUTH_UUID);
  wifiAuthKeyCharacteristic = await wifiAuthService.getCharacteristic(CHR_WIFI_AUTH_KEY_UUID);
  var hash = sha3_256(BLE_SECRET);
  console.log(hash);
  var hash_ab = new Uint8Array(hash.match(/[\da-f]{2}/gi).map(function (value) {
		return parseInt(value, 16)
  }))
  await wifiAuthKeyCharacteristic.writeValue(hash_ab);
}


// This function will be called when 'readValue' resolves and the
// characteristic value changes since 'characteristicvaluechanged' event
// listener has been added. 
function handleWiFiScannerStateChanged(event) {
  let wifiScannerState = event.target.value.getUint8(0);
  log('> Wi-Fi Scanner State is ' + wifiScannerState);

  switch (wifiScannerState) {
    case WIFI_SCANNER_STATE_IDLE:
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      break;

    case WIFI_SCANNER_STATE_SCANNED:
      readWiFiScannerResults();
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      document.querySelector('#btnSend').disabled = false;
      document.querySelector('#selAccessPoint').disabled = false;
      document.querySelector('#txtPassword').disabled = false;
      break;

    case WIFI_SCANNER_STATE_ERROR:
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      break;
  }
}


// This function will be called when 'readValue' resolves and the
// characteristic value changes since 'characteristicvaluechanged' event
// listener has been added. 
function handleWiFiConfigStateChanged(event) {
  let wifiConfigState = event.target.value.getUint8(0);
  log('> Wi-Fi Config State is ' + wifiConfigState);

  switch (wifiConfigState) {
    case WIFI_CONFIG_STATE_IDLE:
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      break;

    case WIFI_CONFIG_STATE_CONNECT:
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      document.querySelector('#btnSend').disabled = false;
      document.querySelector('#selAccessPoint').disabled = false;
      document.querySelector('#txtPassword').disabled = false;
      break;

    case WIFI_CONFIG_STATE_JOINED:
      joinedEventHandler();
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      document.querySelector('#btnSend').disabled = false;
      document.querySelector('#selAccessPoint').disabled = false;
      document.querySelector('#txtPassword').disabled = false;
      break;

    case WIFI_CONFIG_STATE_ERROR:
      document.querySelector('#btnConnect').disabled = true;
      document.querySelector('#btnScan').disabled = false;
      document.querySelector('#btnReset').disabled = false;
      document.querySelector('#btnSend').disabled = false;
      document.querySelector('#selAccessPoint').disabled = false;
      document.querySelector('#txtPassword').disabled = false;
      break;
  }
}

// This function reads the Wi-Fi scanner results,
// prevents any further notifications and resets 
// the scanner service to the idle state. 
async function readWiFiScannerResults() {
  try {

    if (!bluetoothDevice) {
      await requestDevice();
    }
    await connectDeviceAndCacheCharacteristics();

	result_all = "";
    log('> Reading Wi-Fi Scanner Results...');
	value = await wifiScannerAP_Select_Characteristic.readValue();
	max_records = value.getUint8(0);
	console.log(`Number of result records: ${max_records}`);
	var enc = new TextDecoder("utf-8");
	for (let i = 0; i < max_records; i++) {
		const select_value = Uint8Array.of(i);
		await wifiScannerAP_Select_Characteristic.writeValue(select_value)
		result_part = await wifiScannerAP_Result_Characteristic.readValue();
		str = enc.decode(new Uint8Array(result_part.buffer));
		console.log(`Result part ${str}`);
		result_all += str;
	}

	log('> Results: ' + result_all);
      
    try {
      var obj = JSON.parse(result_all);
      log('> Results: ' + JSON.stringify(obj, undefined, 2));
      if (obj.length > 0) {
        obj.sort((a, b) => (Number(a.rssi) < Number(b.rssi)) ? 1 : -1);
        var x = document.getElementById("selAccessPoint");
        while (x.firstChild) {
          x.removeChild(x.firstChild);
        }
        for (i = 0; i < obj.length; i++) {
          var option = document.createElement("option");
          option.text = obj[i].ssid;
          option.value = obj[i].ssid;
          x.add(option);
        }
      }
    } catch (e) {
      log('> Error: ' + e.name + ': ' + e.message);
    }
	
    log('> Stop Wi-Fi Scanner State Notifications...');
    await wifiScannerStateCharacteristic.stopNotifications();

    // Reset the Wi-Fi scanner state back to idle
    var wifiScannerState = Uint8Array.of(WIFI_SCANNER_STATE_IDLE);
    await wifiScannerStateCharacteristic.writeValue(wifiScannerState);

    // Read the Wi-Fi scanner state to confirm
    await wifiScannerStateCharacteristic.readValue();

  } catch (error) {
    log('> Error: ' + error);
  }
}

async function joinedEventHandler() {
  log('> Connected to AP.');
  log('> Stop Wi-Fi Config State Notifications...');
  await wifiConfigStateCharacteristic.stopNotifications();
}


// This function clears the list of Access Points
function removeAllAccessPoints() {
  var x = document.getElementById("selAccessPoint");
  while (x.firstChild) {
    x.removeChild(x.firstChild);
  }
  accessPointsObj = [];
}


// This function handles the click event of the button 'Connect'.
async function onConnectButtonClick() {
  try {
    if (!bluetoothDevice) {
      await requestDevice();
    }
    await connectDeviceAndCacheCharacteristics();

    log('> Reading Wi-Fi Scanner State...');
    await wifiScannerStateCharacteristic.readValue();
  } catch (error) {
    log('> Error: ' + error);
  }
}


// This function handles the click event of the button 'Reset Device'.
function onResetButtonClick() {
  // Disable/Enable the buttons
  document.querySelector('#btnConnect').disabled = false;
  document.querySelector('#btnScan').disabled = true;
  document.querySelector('#btnReset').disabled = true;
  document.querySelector('#btnSend').disabled = true;
  document.querySelector('#selAccessPoint').disabled = true;
  document.querySelector('#txtPassword').disabled = true;

  removeAllAccessPoints();

  if (wifiScannerStateCharacteristic) {
    wifiScannerStateCharacteristic.removeEventListener('characteristicvaluechanged',
        handleWiFiScannerStateChanged);
        wifiScannerStateCharacteristic = null;
  }
  // Note that it doesn't disconnect device.
  bluetoothDevice = null;
  log('> Bluetooth Device reset');
}


// This function handles the click event of the button 'Start Scan'.
async function onScanButtonClick() {
  try {
    if (!bluetoothDevice) {
      await requestDevice();
    }
    await connectDeviceAndCacheCharacteristics();

    log('> Starting a Wi-Fi Scan...');

    document.querySelector('#btnScan').disabled = true;
    document.querySelector('#btnSend').disabled = true;
    removeAllAccessPoints();
    document.querySelector('#selAccessPoint').disabled = true;
    document.querySelector('#txtPassword').disabled = true;

    log('> Starting Wi-Fi Scanner State Notifications...');
    await wifiScannerStateCharacteristic.startNotifications();

    log('> Writing Wi-Fi Scanner State...');
    var wifiScannerState = Uint8Array.of(WIFI_SCANNER_STATE_SCAN);
    await wifiScannerStateCharacteristic.writeValue(wifiScannerState);

  } catch (error) {
    log('> Error: ' + error);
  }
}

async function onPskGenerated(psk)
{
  try {
	log('> Sending SSID and PSK...');

	var ssid = document.querySelector('#selAccessPoint').value;
	var psk_ab = new Uint8Array(psk.match(/[\da-f]{2}/gi).map(function (value) {
		return parseInt(value, 16)
	}))
	var enc = new TextEncoder();
	var ssid_ab = enc.encode(ssid);
	
	await wifiConfigSSIDCharacteristic.writeValue(ssid_ab.buffer);
	
	await wifiConfigPskCharacteristic.writeValue(psk_ab.buffer);

    log('> Starting Wi-Fi Config State Notifications...');
    await wifiConfigStateCharacteristic.startNotifications();

    log('> Writing Wi-Fi Config State...');
    var wifiConfigState = Uint8Array.of(WIFI_CONFIG_STATE_CONNECT);
    await wifiConfigStateCharacteristic.writeValue(wifiConfigState);
  } catch (error) {
    log('> Error: ' + error);
  }
}

// This function handles the click event of the button 'Save Access Point'.
async function onSendButtonClick() {
  try {
    if (!bluetoothDevice) {
      await requestDevice();
    }
    await connectDeviceAndCacheCharacteristics();

    document.querySelector('#btnScan').disabled = true;
    document.querySelector('#btnSend').disabled = true;
    document.querySelector('#selAccessPoint').disabled = true;
    document.querySelector('#txtPassword').disabled = true;

	var passphrase = document.querySelector('#txtPassword').value;
	var ssid = document.querySelector('#selAccessPoint').value;

    log('> Generating PSK for ' + ssid + " and " + passphrase);

	// Sanity checks
	if (!passphrase || !ssid)
		return log('> Please select AP and specify passphrase');

	var psk = "invalid";
	var pskgen = new PBKDF2(passphrase, ssid, 4096, 256 / 8);
	var progress = function(percent_done) { };
	pskgen.deriveKey(progress, onPskGenerated);
  } catch (error) {
    log('> Error: ' + error);
  }
}


// This function handles the click event of the button 'Join Access Point'.
async function onJoinButtonClick() {
  try {
    if (!bluetoothDevice) {
      await requestDevice();
    }
    await connectDeviceAndCacheCharacteristics();

    log('> Joining Access Point...');

    document.querySelector('#btnScan').disabled = true;
    document.querySelector('#btnSend').disabled = true;
    document.querySelector('#selAccessPoint').disabled = true;
    document.querySelector('#txtPassword').disabled = true;

    log('> Starting Wi-Fi Config State Notifications...');
    await wifiConfigStateCharacteristic.startNotifications();

    log('> Writing Wi-Fi Config State...');
    var wifiConfigState = Uint8Array.of(WIFI_CONFIG_STATE_JOIN);
    await wifiConfigStateCharacteristic.writeValue(wifiConfigState);

  } catch (error) {
    log('> Error: ' + error);
  }
}
