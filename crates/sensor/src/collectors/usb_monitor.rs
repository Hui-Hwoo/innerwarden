//! USB device monitoring collector.
//!
//! Monitors udev events for USB device insertion/removal via /dev/input
//! and /sys/bus/usb/devices enumeration. Detects BadUSB, rubber ducky,
//! unauthorized storage devices.
//!
//! For servers, ANY USB insertion is suspicious and worth alerting on.

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::info;

/// Known suspicious USB device indicators.
const SUSPICIOUS_VENDORS: &[&str] = &[
    "hak5",      // Rubber Ducky, Bash Bunny
    "0x1337",    // Common attacker vendor ID spoof
    "ducky",     // Rubber Ducky variants
    "teensy",    // Teensy board (HID attack tool)
    "digispark", // Digispark (cheap HID attack)
];

/// Run USB monitoring by polling /sys/bus/usb/devices.
pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("usb_monitor: starting (interval: {interval_secs}s)");

    let mut known_devices: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Initial scan
    let initial = scan_usb_devices();
    for dev in &initial {
        known_devices.insert(dev.path.clone());
    }
    info!("usb_monitor: baseline {} USB devices", known_devices.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = scan_usb_devices();
        let now = Utc::now();

        // Detect new devices
        for dev in &current {
            if !known_devices.contains(&dev.path) {
                known_devices.insert(dev.path.clone());

                let severity = classify_device(dev);
                let event = build_usb_inserted_event(dev, &host_id, now, severity);

                let _ = tx.send(event).await;
            }
        }

        // Detect removed devices
        let current_paths: std::collections::HashSet<String> =
            current.iter().map(|d| d.path.clone()).collect();
        let removed: Vec<String> = known_devices
            .iter()
            .filter(|p| !current_paths.contains(*p))
            .cloned()
            .collect();

        for path in &removed {
            known_devices.remove(path);

            let event = build_usb_removed_event(path, &host_id, now);

            let _ = tx.send(event).await;
        }
    }
}

#[derive(Debug)]
struct UsbDevice {
    path: String,
    vendor_id: String,
    product_id: String,
    vendor_name: String,
    product_name: String,
    serial: String,
    device_class: String,
    interface_class: Vec<String>,
    bus: String,
    port: String,
}

fn scan_usb_devices() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let usb_path = std::path::Path::new("/sys/bus/usb/devices");

    let Ok(entries) = std::fs::read_dir(usb_path) else {
        return devices;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip interfaces (contain :), only want devices (like 1-1, 2-1.3)
        if name.contains(':') || name == "usb1" || name == "usb2" {
            continue;
        }

        let read = |file: &str| -> String {
            std::fs::read_to_string(path.join(file))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let vendor_id = normalize_usb_id(&read("idVendor"));
        if vendor_id.is_empty() {
            continue; // Not a real USB device entry
        }

        // Collect interface classes
        let mut interface_class = Vec::new();
        if let Ok(intf_entries) = std::fs::read_dir(&path) {
            for ie in intf_entries.flatten() {
                let ie_name = ie.file_name().to_string_lossy().to_string();
                if ie_name.contains(':') {
                    let ic = std::fs::read_to_string(ie.path().join("bInterfaceClass"))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if !ic.is_empty() {
                        interface_class.push(ic);
                    }
                }
            }
        }

        devices.push(UsbDevice {
            path: path.to_string_lossy().to_string(),
            vendor_id,
            product_id: normalize_usb_id(&read("idProduct")),
            vendor_name: read("manufacturer"),
            product_name: read("product"),
            serial: read("serial"),
            device_class: read("bDeviceClass"),
            interface_class,
            bus: read("busnum"),
            port: read("devpath"),
        });
    }

    devices
}

fn classify_device(dev: &UsbDevice) -> Severity {
    // Suspicious vendor first (highest priority)
    let vendor_lower = dev.vendor_name.to_lowercase();
    if SUSPICIOUS_VENDORS.iter().any(|s| vendor_lower.contains(s)) {
        return Severity::Critical;
    }
    // HID device on a server = very suspicious (possible BadUSB)
    if dev.device_class == "03" || dev.interface_class.contains(&"03".to_string()) {
        return Severity::High;
    }
    // Mass storage = potential data exfiltration
    if dev.device_class == "08" || dev.interface_class.contains(&"08".to_string()) {
        return Severity::High;
    }
    Severity::Medium
}

fn normalize_usb_id(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

fn usb_device_signals(dev: &UsbDevice) -> Vec<String> {
    let mut signals = Vec::new();

    if dev.device_class == "03" || dev.interface_class.contains(&"03".to_string()) {
        signals.push("hid_device".into()); // HID = keyboard/mouse = possible BadUSB
    }
    if dev.device_class == "08" || dev.interface_class.contains(&"08".to_string()) {
        signals.push("mass_storage".into());
    }
    let vendor_lower = dev.vendor_name.to_lowercase();
    if SUSPICIOUS_VENDORS.iter().any(|s| vendor_lower.contains(s)) {
        signals.push("suspicious_vendor".into());
    }
    if dev.serial.is_empty() || dev.serial == "0" {
        signals.push("no_serial".into()); // Spoofed devices often lack serial
    }

    signals
}

fn build_usb_inserted_event(
    dev: &UsbDevice,
    host_id: &str,
    ts: chrono::DateTime<Utc>,
    severity: Severity,
) -> Event {
    let signals = usb_device_signals(dev);
    Event {
        ts,
        host: host_id.to_string(),
        source: "usb_monitor".into(),
        kind: "hardware.usb_inserted".into(),
        severity,
        summary: format!(
            "USB device inserted: {} {} (vendor:{}, product:{})",
            dev.vendor_name, dev.product_name, dev.vendor_id, dev.product_id
        ),
        details: serde_json::json!({
            "action": "add",
            "vendor_id": dev.vendor_id,
            "product_id": dev.product_id,
            "vendor_name": dev.vendor_name,
            "product_name": dev.product_name,
            "serial": dev.serial,
            "device_class": dev.device_class,
            "interface_classes": dev.interface_class,
            "bus": dev.bus,
            "port": dev.port,
            "signals": signals,
        }),
        tags: vec!["hardware".into(), "usb".into()],
        entities: vec![EntityRef::path(dev.path.clone())],
    }
}

fn build_usb_removed_event(path: &str, host_id: &str, ts: chrono::DateTime<Utc>) -> Event {
    Event {
        ts,
        host: host_id.to_string(),
        source: "usb_monitor".into(),
        kind: "hardware.usb_removed".into(),
        severity: Severity::Info,
        summary: format!("USB device removed: {path}"),
        details: serde_json::json!({
            "action": "remove",
            "path": path,
        }),
        tags: vec!["hardware".into(), "usb".into()],
        entities: vec![EntityRef::path(path.to_string())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_device(device_class: &str, interface_class: Vec<&str>) -> UsbDevice {
        UsbDevice {
            path: "/sys/bus/usb/devices/1-1".into(),
            vendor_id: "1234".into(),
            product_id: "5678".into(),
            vendor_name: "Generic".into(),
            product_name: "USB Device".into(),
            serial: "serial-1".into(),
            device_class: device_class.into(),
            interface_class: interface_class.into_iter().map(str::to_string).collect(),
            bus: "1".into(),
            port: "1".into(),
        }
    }

    #[test]
    fn test_classify_hid() {
        let dev = usb_device("03", vec![]);
        assert_eq!(classify_device(&dev), Severity::High);
    }

    #[test]
    fn test_classify_hak5() {
        let dev = UsbDevice {
            path: "/sys/bus/usb/devices/1-2".into(),
            vendor_id: "1337".into(),
            product_id: "0001".into(),
            vendor_name: "Hak5 LLC".into(),
            product_name: "USB Rubber Ducky".into(),
            serial: String::new(),
            device_class: "00".into(),
            interface_class: vec!["03".into()],
            bus: "1".into(),
            port: "2".into(),
        };
        assert_eq!(classify_device(&dev), Severity::Critical);
    }

    #[test]
    fn classify_mass_storage_device_class_as_high() {
        let dev = usb_device("08", vec![]);

        assert_eq!(classify_device(&dev), Severity::High);
    }

    #[test]
    fn classify_mass_storage_interface_class_as_high() {
        let dev = usb_device("00", vec!["08"]);

        assert_eq!(classify_device(&dev), Severity::High);
    }

    #[test]
    fn classify_generic_device_as_medium() {
        let dev = usb_device("00", vec!["ff"]);

        assert_eq!(classify_device(&dev), Severity::Medium);
    }

    #[test]
    fn inserted_event_includes_ids_and_signals() {
        let mut dev = usb_device("03", vec![]);
        dev.vendor_id = "1a2b".into();
        dev.product_id = "00ff".into();
        dev.serial.clear();

        let event = build_usb_inserted_event(&dev, "host-a", Utc::now(), classify_device(&dev));

        assert_eq!(event.kind, "hardware.usb_inserted");
        assert_eq!(event.details["action"], "add");
        assert_eq!(event.details["vendor_id"], "1a2b");
        assert_eq!(event.details["product_id"], "00ff");
        assert!(event.details["signals"]
            .as_array()
            .expect("signals array")
            .contains(&serde_json::json!("hid_device")));
        assert!(event.details["signals"]
            .as_array()
            .expect("signals array")
            .contains(&serde_json::json!("no_serial")));
    }

    #[test]
    fn removed_event_uses_remove_kind_and_path_entity() {
        let event = build_usb_removed_event("/sys/bus/usb/devices/1-9", "host-a", Utc::now());

        assert_eq!(event.kind, "hardware.usb_removed");
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.details["action"], "remove");
        assert_eq!(event.details["path"], "/sys/bus/usb/devices/1-9");
    }

    #[test]
    fn normalizes_mixed_case_usb_ids() {
        assert_eq!(normalize_usb_id("0x1A2B"), "1a2b");
        assert_eq!(normalize_usb_id("0X00Ff\n"), "00ff");
    }
}
