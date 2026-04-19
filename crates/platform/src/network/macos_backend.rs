#[cfg(any(target_os = "macos", test))]
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "macos", test))]
use ssh_core::network::{InterfaceType, NetworkInterface};
#[cfg(any(target_os = "macos", test))]
use ssh_core::scanner::NeighborEvidence;
#[cfg(any(target_os = "macos", test))]
use tokio::process::Command;

#[cfg(any(target_os = "macos", test))]
use super::NeighborEvidenceRow;

#[cfg(any(target_os = "macos", test))]
const MACOS_ARP_HELPER_ENV: &str = "LANSCANNER_MACOS_ARP_HELPER";
#[cfg(any(target_os = "macos", test))]
const MACOS_ARP_HELPER_NAME: &str = "lanscanner-macos-arp-helper";
#[cfg(any(target_os = "macos", test))]
const MACOS_INTERFACE_HELPER_CONTRACT: &str = "interface-snapshot-v1";
#[cfg(any(target_os = "macos", test))]
const MACOS_ARP_HELPER_CONTRACT: &str = "neighbor-snapshot-v1";

#[cfg(any(target_os = "macos", test))]
pub(super) async fn collect_neighbor_rows_with_native_helper() -> Vec<NeighborEvidenceRow> {
    let Some(helper_path) = resolve_native_helper_path() else {
        return Vec::new();
    };

    let Ok(output) = Command::new(&helper_path)
        .args(["neighbors", "--contract", MACOS_ARP_HELPER_CONTRACT])
        .output()
        .await
    else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_native_helper_row)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
pub(super) async fn collect_interfaces_with_native_helper() -> Vec<NetworkInterface> {
    let Some(helper_path) = resolve_native_helper_path() else {
        return Vec::new();
    };

    let Ok(output) = Command::new(&helper_path)
        .args(["interfaces", "--contract", MACOS_INTERFACE_HELPER_CONTRACT])
        .output()
        .await
    else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_native_helper_interface_row)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn resolve_native_helper_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(MACOS_ARP_HELPER_ENV) {
        let path = PathBuf::from(path);
        if is_executable_file(&path) {
            return Some(path);
        }
    }

    let current_exe = std::env::current_exe().ok()?;
    let base_dir = current_exe.parent()?;
    let candidates = [
        base_dir.join(MACOS_ARP_HELPER_NAME),
        base_dir.join("../Resources").join(MACOS_ARP_HELPER_NAME),
        base_dir.join("../Helpers").join(MACOS_ARP_HELPER_NAME),
    ];

    candidates.into_iter().find(|path| is_executable_file(path))
}

#[cfg(any(target_os = "macos", test))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(any(target_os = "macos", test))]
fn parse_native_helper_row(line: &str) -> Option<NeighborEvidenceRow> {
    let mut parts = line.split('|');
    let ip = parts.next()?.trim();
    let mac = parts.next()?.trim();
    let hostname = parts.next().unwrap_or_default().trim();
    let mdns_name = parts.next().unwrap_or_default().trim();

    if !super::neighbor_rows::is_valid_neighbor_ip(ip) {
        return None;
    }

    let mac_address = super::neighbor_rows::normalize_neighbor_mac(mac)?;
    let hostname = normalize_helper_label(hostname)
        .or_else(|| normalize_helper_label(mdns_name))
        .map(str::to_owned);
    let mdns_name = normalize_helper_label(mdns_name)
        .filter(|name| name.ends_with(".local"))
        .map(str::to_owned);

    Some(NeighborEvidenceRow {
        ip: ip.to_owned(),
        evidence: NeighborEvidence::new(Some(mac_address), hostname, mdns_name),
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_native_helper_interface_row(line: &str) -> Option<NetworkInterface> {
    let mut parts = line.split('|');
    let id = parts.next()?.trim();
    let name = parts.next()?.trim();
    let ipv4 = parts.next()?.trim();
    let prefix = parts.next()?.trim();
    let _mac = parts.next().unwrap_or_default().trim();
    let iface_type = parts.next().unwrap_or_default().trim();
    let _is_primary = parts.next().unwrap_or_default().trim();

    if id.is_empty() || name.is_empty() || ipv4.is_empty() {
        return None;
    }

    let prefix = prefix.parse::<u8>().ok()?;
    let iface_type = parse_interface_type(iface_type);

    Some(NetworkInterface {
        id: id.to_owned(),
        name: name.to_owned(),
        ip_range: format!("{ipv4}/{prefix}"),
        iface_type,
        local_ip: ipv4.to_owned(),
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_interface_type(raw: &str) -> InterfaceType {
    match raw.trim().to_ascii_lowercase().as_str() {
        "wifi" => InterfaceType::Wifi,
        "ethernet" => InterfaceType::Ethernet,
        "docker" => InterfaceType::Docker,
        _ => InterfaceType::Other,
    }
}

#[cfg(any(target_os = "macos", test))]
fn normalize_helper_label(value: &str) -> Option<&str> {
    let value = value.trim();
    if matches!(value, "" | "-" | "?" | "<nil>") {
        return None;
    }
    super::neighbor_rows::trim_neighbor_hostname(value)
}

#[cfg(test)]
mod tests {
    use super::{parse_native_helper_interface_row, parse_native_helper_row};
    use ssh_core::network::InterfaceType;

    #[test]
    fn parses_native_helper_row_with_mdns_name() {
        let row = parse_native_helper_row("192.168.31.5|b8:27:eb:11:22:33|raspi|raspi.local")
            .expect("helper row should parse");

        assert_eq!(row.ip, "192.168.31.5");
        assert_eq!(
            row.evidence.mac_address.as_deref(),
            Some("B8:27:EB:11:22:33")
        );
        assert_eq!(row.evidence.hostname.as_deref(), Some("raspi"));
        assert_eq!(row.evidence.mdns_name.as_deref(), Some("raspi.local"));
    }

    #[test]
    fn ignores_helper_rows_without_valid_mac() {
        assert!(parse_native_helper_row("192.168.31.5|(incomplete)|raspi|raspi.local").is_none());
    }

    #[test]
    fn parses_native_helper_interface_row() {
        let row =
            parse_native_helper_interface_row("en0|Wi-Fi (en0)|192.168.31.10|24|AA:BB:CC:DD:EE:FF|wifi|1")
                .expect("interface row should parse");

        assert_eq!(row.id, "en0");
        assert_eq!(row.name, "Wi-Fi (en0)");
        assert_eq!(row.local_ip, "192.168.31.10");
        assert_eq!(row.ip_range, "192.168.31.10/24");
        assert_eq!(row.iface_type, InterfaceType::Wifi);
    }
}
