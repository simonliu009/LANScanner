use std::collections::HashMap;

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Fill, Length, Theme, border};
use ssh_core::scanner::{
    Device, DeviceStatus, NeighborEvidence, vendor_name_from_mac_address,
};

use crate::theme::{self, AppLanguage, colors, fonts, icons::{self, FrameSpec, Glyph}};

const LIST_OUTER_PADDING_X: f32 = 10.0;
const LIST_OUTER_PADDING_Y: f32 = 6.0;
const LIST_ITEM_HEIGHT: f32 = 46.0;
const LIST_ITEM_HORIZONTAL_PADDING: f32 = 8.0;
const LIST_ITEM_RADIUS: f32 = 9.0;
const HEADER_HEIGHT: f32 = 28.0;
const COLUMN_GAP: f32 = 10.0;
const TABLE_TEXT_SIZE: f32 = 11.0;
const TABLE_MIN_WIDTH_BASIC: f32 = 1040.0;
const TABLE_MIN_WIDTH_EXTENDED: f32 = 2100.0;
const DEVICE_COL_FILL: u16 = 4;
const NETWORK_NAME_COL_FILL: u16 = 4;
const IP_COL_FILL: u16 = 3;
const MAC_COL_FILL: u16 = 3;
const HOSTNAME_COL_FILL: u16 = 3;
const VENDOR_COL_FILL: u16 = 4;
const DNS_COL_FILL: u16 = 3;
const MDNS_COL_FILL: u16 = 3;
const SMB_NAME_COL_FILL: u16 = 3;
const SMB_DOMAIN_COL_FILL: u16 = 3;
const STATUS_COL_FILL: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultColumn {
    MacAddress,
    Hostname,
    Vendor,
    DnsName,
    MdnsName,
    SmbName,
    SmbDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultColumnVisibility {
    pub mac_address: bool,
    pub hostname: bool,
    pub vendor: bool,
    pub dns_name: bool,
    pub mdns_name: bool,
    pub smb_name: bool,
    pub smb_domain: bool,
}

impl Default for ResultColumnVisibility {
    fn default() -> Self {
        Self {
            mac_address: false,
            hostname: false,
            vendor: false,
            dns_name: false,
            mdns_name: false,
            smb_name: false,
            smb_domain: false,
        }
    }
}

impl ResultColumnVisibility {
    pub fn is_visible(&self, column: ResultColumn) -> bool {
        match column {
            ResultColumn::MacAddress => self.mac_address,
            ResultColumn::Hostname => self.hostname,
            ResultColumn::Vendor => self.vendor,
            ResultColumn::DnsName => self.dns_name,
            ResultColumn::MdnsName => self.mdns_name,
            ResultColumn::SmbName => self.smb_name,
            ResultColumn::SmbDomain => self.smb_domain,
        }
    }

    pub fn set_visible(&mut self, column: ResultColumn, visible: bool) {
        match column {
            ResultColumn::MacAddress => self.mac_address = visible,
            ResultColumn::Hostname => self.hostname = visible,
            ResultColumn::Vendor => self.vendor = visible,
            ResultColumn::DnsName => self.dns_name = visible,
            ResultColumn::MdnsName => self.mdns_name = visible,
            ResultColumn::SmbName => self.smb_name = visible,
            ResultColumn::SmbDomain => self.smb_domain = visible,
        }
    }

    pub fn has_any_optional_column(&self) -> bool {
        self.mac_address
            || self.hostname
            || self.vendor
            || self.dns_name
            || self.mdns_name
            || self.smb_name
            || self.smb_domain
    }
}

pub enum PlaceholderState {
    Idle,
    RefreshingNetworks {
        spinner_frame: &'static str,
    },
    Scanning {
        spinner_frame: &'static str,
        progress: Option<(usize, usize)>,
    },
    EmptyResults,
}

#[derive(Debug, Clone, Copy)]
enum PlaceholderVisual {
    Glyph(Glyph),
    RotatingRefresh(&'static str),
}

pub fn view<'a, Message>(
    devices: &'a [Device],
    evidence_by_ip: &'a HashMap<String, NeighborEvidence>,
    visible_columns: ResultColumnVisibility,
    selected_device_id: Option<&'a str>,
    local_ip: Option<&'a str>,
    app_language: AppLanguage,
    on_select: impl Fn(String) -> Message + Copy + 'a,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    if devices.is_empty() {
        return placeholder(PlaceholderState::EmptyResults, app_language);
    }

    let header = device_table_header(app_language, visible_columns);
    let mut ordered_devices = devices.iter().collect::<Vec<_>>();
    ordered_devices.sort_by_key(|device| local_ip != Some(device.ip.as_str()));

    let items = ordered_devices.into_iter().fold(
        column!().spacing(2).padding([LIST_OUTER_PADDING_Y, LIST_OUTER_PADDING_X]),
        |column, device| {
            let is_selected = selected_device_id == Some(device.id.as_str());
            let is_local = local_ip == Some(device.ip.as_str());
            let is_emphasized = is_selected || is_local;
            let select_message = on_select(device.id.clone());
            let evidence = evidence_by_ip.get(device.ip.as_str());
            let mut item_row =
                row![
                    device_name_cell(device, evidence, is_emphasized, is_local),
                    network_name_cell(evidence, is_emphasized),
                    device_ip_cell(&device.ip, is_emphasized),
                ]
                .spacing(COLUMN_GAP)
                .align_y(Alignment::Center);

            for column in optional_columns(visible_columns) {
                item_row =
                    item_row.push(result_column_cell(column, evidence, is_emphasized));
            }

            let item = button(
                item_row
                    .push(device_status_cell(device.status, app_language))
                    .height(LIST_ITEM_HEIGHT),
            )
            .width(Fill)
            .padding([0.0, LIST_ITEM_HORIZONTAL_PADDING])
            .style(move |theme: &Theme, status| {
                let palette = colors::palette(theme);
                let is_dark = palette.card == colors::DARK.card;

                let background = if is_selected || is_local {
                    if is_dark {
                        colors::DARK_SELECTION
                    } else {
                        colors::LIGHT_SELECTION
                    }
                } else {
                    match status {
                        button::Status::Hovered | button::Status::Pressed => {
                            if is_dark {
                                colors::DARK_ROW_HOVER
                            } else {
                                colors::LIGHT_ROW_HOVER
                            }
                        }
                        _ => iced::Color::TRANSPARENT,
                    }
                };

                button::Style {
                    snap: false,
                    background: Some(iced::Background::Color(background)),
                    text_color: palette.text,
                    border: iced::Border {
                        color: if is_selected || is_local {
                            if is_dark {
                                colors::rgba(0x3B, 0x82, 0xF6, 0.4)
                            } else {
                                colors::rgba(0x3B, 0x82, 0xF6, 0.2)
                            }
                        } else {
                            iced::Color::TRANSPARENT
                        },
                        width: if is_selected || is_local { 1.0 } else { 0.0 },
                        radius: border::radius(LIST_ITEM_RADIUS),
                    },
                    shadow: iced::Shadow::default(),
                }
            })
            .on_press(select_message);

            column.push(item)
        },
    );

    let table = column![
        header,
        scrollable(items)
            .width(Fill)
            .height(Fill)
            .style(theme::styles::custom_scrollbar)
    ]
    .spacing(0)
    .width(Length::Fixed(if visible_columns.has_any_optional_column() {
        TABLE_MIN_WIDTH_EXTENDED
    } else {
        TABLE_MIN_WIDTH_BASIC
    }))
    .height(Fill);

    scrollable(table)
        .direction(scrollable::Direction::Both {
            vertical: scrollable::Scrollbar::default(),
            horizontal: scrollable::Scrollbar::default(),
        })
        .width(Fill)
        .height(Fill)
        .style(theme::styles::custom_scrollbar)
        .into()
}

fn device_table_header<'a, Message>(
    app_language: AppLanguage,
    visible_columns: ResultColumnVisibility,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(header_row(app_language, visible_columns))
    .padding(iced::Padding {
        top: 6.0,
        right: LIST_OUTER_PADDING_X + LIST_ITEM_HORIZONTAL_PADDING,
        bottom: 4.0,
        left: LIST_OUTER_PADDING_X + LIST_ITEM_HORIZONTAL_PADDING,
    })
    .height(Length::Fixed(HEADER_HEIGHT))
    .into()
}

fn header_row<'a, Message>(
    app_language: AppLanguage,
    visible_columns: ResultColumnVisibility,
) -> iced::widget::Row<'a, Message>
where
    Message: 'a,
{
    let mut row = row![
        table_header_cell(localized(app_language, "设备名", "Device Name"), DEVICE_COL_FILL),
        table_header_cell(
            localized(app_language, "网络名称", "Network Name"),
            NETWORK_NAME_COL_FILL,
        ),
        table_header_cell(localized(app_language, "IP 地址", "IP Address"), IP_COL_FILL),
    ]
    .spacing(COLUMN_GAP)
    .align_y(Alignment::Center);

    for column in optional_columns(visible_columns) {
        row = row.push(table_header_cell(
            result_column_label(column, app_language),
            result_column_fill(column),
        ));
    }

    row.push(table_header_cell(
            localized(app_language, "状态", "Status"),
            STATUS_COL_FILL,
        ))
}

fn optional_columns(visible_columns: ResultColumnVisibility) -> impl Iterator<Item = ResultColumn> {
    [
        ResultColumn::MacAddress,
        ResultColumn::Hostname,
        ResultColumn::Vendor,
        ResultColumn::DnsName,
        ResultColumn::MdnsName,
        ResultColumn::SmbName,
        ResultColumn::SmbDomain,
    ]
    .into_iter()
    .filter(move |column| visible_columns.is_visible(*column))
}

fn result_column_cell<'a, Message>(
    column: ResultColumn,
    evidence: Option<&'a NeighborEvidence>,
    is_selected: bool,
) -> Element<'a, Message>
where
    Message: 'a,
{
    let value = match column {
        ResultColumn::MacAddress => evidence
            .and_then(|item| item.mac_address.as_deref())
            .unwrap_or("-"),
        ResultColumn::Hostname => evidence.and_then(|item| item.hostname.as_deref()).unwrap_or("-"),
        ResultColumn::Vendor => evidence
            .and_then(|item| item.mac_address.as_deref())
            .and_then(vendor_name_from_mac_address)
            .unwrap_or("-"),
        ResultColumn::DnsName => evidence.and_then(|item| item.dns_name.as_deref()).unwrap_or("-"),
        ResultColumn::MdnsName => evidence.and_then(|item| item.mdns_name.as_deref()).unwrap_or("-"),
        ResultColumn::SmbName => evidence.and_then(|item| item.smb_name.as_deref()).unwrap_or("-"),
        ResultColumn::SmbDomain => evidence
            .and_then(|item| item.smb_domain.as_deref())
            .unwrap_or("-"),
    };

    plain_text_cell(value, result_column_fill(column), is_selected)
}

fn result_column_fill(column: ResultColumn) -> u16 {
    match column {
        ResultColumn::MacAddress => MAC_COL_FILL,
        ResultColumn::Hostname => HOSTNAME_COL_FILL,
        ResultColumn::Vendor => VENDOR_COL_FILL,
        ResultColumn::DnsName => DNS_COL_FILL,
        ResultColumn::MdnsName => MDNS_COL_FILL,
        ResultColumn::SmbName => SMB_NAME_COL_FILL,
        ResultColumn::SmbDomain => SMB_DOMAIN_COL_FILL,
    }
}

fn result_column_label(column: ResultColumn, app_language: AppLanguage) -> &'static str {
    match column {
        ResultColumn::MacAddress => localized(app_language, "MAC", "MAC"),
        ResultColumn::Hostname => localized(app_language, "主机名", "Hostname"),
        ResultColumn::Vendor => localized(app_language, "厂商", "Vendor"),
        ResultColumn::DnsName => localized(app_language, "DNS 名称", "DNS Name"),
        ResultColumn::MdnsName => localized(app_language, "mDNS 名称", "mDNS Name"),
        ResultColumn::SmbName => localized(app_language, "SMB 名称", "SMB Name"),
        ResultColumn::SmbDomain => localized(app_language, "SMB 域", "SMB Domain"),
    }
}

fn table_header_cell<'a, Message>(label: &'static str, fill: u16) -> Element<'a, Message>
where
    Message: 'a,
{
    container(
        text(label)
            .font(fonts::monospace())
            .size(TABLE_TEXT_SIZE)
            .style(|theme: &Theme| theme::text_muted(theme)),
    )
    .width(Length::FillPortion(fill))
    .center_y(Length::Fixed(HEADER_HEIGHT))
    .into()
}

fn device_name_cell<'a, Message>(
    device: &'a Device,
    evidence: Option<&'a NeighborEvidence>,
    is_emphasized: bool,
    is_local: bool,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(
        text(device_name_label(device, evidence, is_local))
            .font(fonts::monospace())
            .size(TABLE_TEXT_SIZE)
            .style(move |theme: &Theme| {
                let palette = colors::palette(theme);

                if is_emphasized {
                    theme::solid_text(palette.primary)
                } else {
                    theme::text_primary(theme)
                }
            }),
    )
    .width(Length::FillPortion(DEVICE_COL_FILL))
    .center_y(Length::Fixed(LIST_ITEM_HEIGHT))
    .into()
}

fn network_name_cell<'a, Message>(
    evidence: Option<&'a NeighborEvidence>,
    is_emphasized: bool,
) -> Element<'a, Message>
where
    Message: 'a,
{
    plain_text_cell(
        network_name_label(evidence).unwrap_or("-"),
        NETWORK_NAME_COL_FILL,
        is_emphasized,
    )
}

fn device_ip_cell<'a, Message>(
    ip: &'a str,
    is_emphasized: bool,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(
        text(ip)
            .font(fonts::monospace())
            .size(TABLE_TEXT_SIZE)
            .style(move |theme: &Theme| {
                if is_emphasized {
                    theme::solid_text(colors::rgb(0x1D, 0x4E, 0x89))
                } else {
                    theme::text_muted(theme)
                }
            }),
    )
    .width(Length::FillPortion(IP_COL_FILL))
    .center_y(Length::Fixed(LIST_ITEM_HEIGHT))
    .into()
}

fn plain_text_cell<'a, Message>(
    value: &'a str,
    fill: u16,
    is_selected: bool,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(
        text(value)
            .font(fonts::monospace())
            .size(TABLE_TEXT_SIZE)
            .style(move |theme: &Theme| {
                if is_selected {
                    theme::solid_text(colors::rgb(0x1D, 0x4E, 0x89))
                } else {
                    theme::text_muted(theme)
                }
            }),
    )
    .width(Length::FillPortion(fill))
    .clip(true)
    .center_y(Length::Fixed(LIST_ITEM_HEIGHT))
    .into()
}

fn device_status_cell<'a, Message>(
    status: DeviceStatus,
    app_language: AppLanguage,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(
        text(device_status_label(status, app_language))
            .font(fonts::monospace())
            .size(TABLE_TEXT_SIZE)
            .style(move |theme: &Theme| match status {
                DeviceStatus::Ready => theme::solid_text(colors::rgb(0x16, 0xA3, 0x4A)),
                DeviceStatus::Denied | DeviceStatus::Error => {
                    theme::solid_text(colors::rgb(0xDC, 0x26, 0x26))
                }
                DeviceStatus::Untested => theme::text_muted(theme),
            }),
    )
        .width(Length::FillPortion(STATUS_COL_FILL))
        .align_x(iced::alignment::Horizontal::Left)
        .center_y(Length::Fixed(LIST_ITEM_HEIGHT))
        .into()
}

fn device_name_label(
    device: &Device,
    evidence: Option<&NeighborEvidence>,
    is_local: bool,
) -> String {
    if is_local {
        return String::from("[本机]");
    }

    let full_name = device.name.as_str();
    let Some(network_name) = network_name_label(evidence) else {
        return device.name.clone();
    };

    let suffix = format!(" ({network_name})");
    full_name
        .strip_suffix(suffix.as_str())
        .unwrap_or(full_name)
        .to_owned()
}

fn network_name_label(evidence: Option<&NeighborEvidence>) -> Option<&str> {
    evidence
        .and_then(|item| item.mdns_name.as_deref())
        .or_else(|| evidence.and_then(|item| item.dns_name.as_deref()))
        .or_else(|| evidence.and_then(|item| item.hostname.as_deref()))
}

fn device_status_label(status: DeviceStatus, app_language: AppLanguage) -> &'static str {
    match (status, app_language) {
        (DeviceStatus::Untested, AppLanguage::Chinese) => "未检测",
        (DeviceStatus::Untested, AppLanguage::English) => "UNTESTED",
        (DeviceStatus::Ready, AppLanguage::Chinese) => "就绪",
        (DeviceStatus::Ready, AppLanguage::English) => "READY",
        (DeviceStatus::Denied, AppLanguage::Chinese) => "拒绝",
        (DeviceStatus::Denied, AppLanguage::English) => "DENIED",
        (DeviceStatus::Error, AppLanguage::Chinese) => "错误",
        (DeviceStatus::Error, AppLanguage::English) => "ERROR",
    }
}

fn localized(language: AppLanguage, chinese: &'static str, english: &'static str) -> &'static str {
    match language {
        AppLanguage::Chinese => chinese,
        AppLanguage::English => english,
    }
}

pub fn placeholder<'a, Message>(
    state: PlaceholderState,
    app_language: AppLanguage,
) -> Element<'a, Message>
where
    Message: 'a,
{
    container(empty_state_panel(state, app_language))
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .padding(18)
        .into()
}

fn empty_state_panel<'a, Message: 'a>(
    state: PlaceholderState,
    app_language: AppLanguage,
) -> Element<'a, Message> {
    if matches!(state, PlaceholderState::Idle) {
        return idle_state_panel(app_language);
    }

    let (visual, chip_label, accent, title, description) = match state {
        PlaceholderState::Idle => unreachable!(),
        PlaceholderState::RefreshingNetworks { spinner_frame } => (
            PlaceholderVisual::RotatingRefresh(spinner_frame),
            refreshing_networks_chip_label(app_language),
            colors::rgb(0x3B, 0x82, 0xF6),
            refreshing_networks_title(app_language),
            refreshing_networks_description(app_language),
        ),
        PlaceholderState::Scanning {
            spinner_frame,
            progress,
        } => (
            PlaceholderVisual::RotatingRefresh(spinner_frame),
            scanning_chip_label(app_language),
            colors::rgb(0x3B, 0x82, 0xF6),
            scanning_title(app_language),
            match progress {
                Some((scanned, total)) if total > 0 => {
                    scanning_progress_description(app_language, scanned, total)
                }
                _ => scanning_description(app_language),
            },
        ),
        PlaceholderState::EmptyResults => (
            PlaceholderVisual::Glyph(Glyph::Search),
            empty_results_chip_label(app_language),
            colors::rgb(0xEA, 0x58, 0x0C),
            empty_results_title(app_language),
            empty_results_description(app_language),
        ),
    };

    container(
        column![
            status_chip(visual, chip_label, accent),
            empty_state_icon(visual, accent),
            text(title)
                .font(fonts::semibold())
                .size(14)
                .style(|theme: &Theme| theme::text_primary(theme)),
            text(description)
                .size(12)
                .style(|theme: &Theme| theme::text_muted(theme)),
        ]
        .spacing(12)
        .align_x(Alignment::Center),
    )
    .width(Length::Fixed(236.0))
    .padding([22, 20])
    .style(|theme: &Theme| {
        let palette = colors::palette(theme);

        container::Style::default()
            .background(palette.card)
            .border(iced::Border {
                color: palette.border,
                width: 1.0,
                radius: border::radius(16),
            })
    })
    .into()
}

fn idle_state_panel<'a, Message: 'a>(app_language: AppLanguage) -> Element<'a, Message> {
    const PANEL_WIDTH: f32 = 208.0;
    const ICON_SIZE: f32 = 58.0;
    const ICON_GLYPH: f32 = 20.0;
    const TITLE_SIZE: f32 = 12.0;

    let tone = colors::rgb(0x8A, 0x93, 0xA1);
    let background = colors::rgba(0x8A, 0x93, 0xA1, 0.08);

    let icon = icons::framed(
        Glyph::Search,
        FrameSpec {
            width: ICON_SIZE,
            height: ICON_SIZE,
            icon_size: ICON_GLYPH,
            tone,
            background,
            border_color: colors::rgba(0x8A, 0x93, 0xA1, 0.12),
            radius: 8.0,
        },
    );

    let panel = container(
        column![
            container(icon).width(Fill).center_x(Fill),
            container(
                text(idle_state_title(app_language))
                    .font(fonts::semibold())
                    .size(TITLE_SIZE)
                    .style(move |_| theme::solid_text(tone)),
            )
            .width(Fill)
            .center_x(Fill),
        ]
        .spacing(10)
        .align_x(Alignment::Center),
    )
    .width(Length::Fixed(PANEL_WIDTH))
    .padding([2, 2]);

    container(panel)
        .width(Fill)
        .padding(iced::Padding {
            top: 0.0,
            right: 0.0,
            bottom: 12.0,
            left: 0.0,
        })
        .center_x(Fill)
        .into()
}

fn empty_state_icon<'a, Message: 'a>(
    visual: PlaceholderVisual,
    tone: iced::Color,
) -> Element<'a, Message> {
    let icon = placeholder_visual_centered(visual, tone, 48.0, 16.0);

    container(icon)
        .width(48)
        .height(48)
        .center_x(Length::Fixed(48.0))
        .center_y(Length::Fixed(48.0))
        .style(move |_| {
            container::Style::default()
                .background(colors::rgba(
                    (tone.r * 255.0).round() as u8,
                    (tone.g * 255.0).round() as u8,
                    (tone.b * 255.0).round() as u8,
                    0.12,
                ))
                .border(iced::Border {
                    color: colors::rgba(
                        (tone.r * 255.0).round() as u8,
                        (tone.g * 255.0).round() as u8,
                        (tone.b * 255.0).round() as u8,
                        0.22,
                    ),
                    width: 1.0,
                    radius: border::radius(16),
                })
        })
        .into()
}

fn idle_state_title(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "尚未进行扫描",
        AppLanguage::English => "No Scan Yet",
    }
}

fn refreshing_networks_chip_label(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "同步网卡",
        AppLanguage::English => "Refreshing Networks",
    }
}

fn refreshing_networks_title(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "正在准备扫描上下文",
        AppLanguage::English => "Preparing Scan Context",
    }
}

fn refreshing_networks_description(app_language: AppLanguage) -> String {
    match app_language {
        AppLanguage::Chinese => {
            String::from("正在读取本机网络接口与目标网段，完成后即可选择可扫描网卡。")
        }
        AppLanguage::English => String::from(
            "Reading local network interfaces and target subnets. You can start scanning as soon as the list is ready.",
        ),
    }
}

fn scanning_chip_label(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "扫描进行中",
        AppLanguage::English => "Scanning",
    }
}

fn scanning_title(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "结果列表等待回填",
        AppLanguage::English => "Waiting For Results",
    }
}

fn scanning_description(app_language: AppLanguage) -> String {
    match app_language {
        AppLanguage::Chinese => {
            String::from("扫描任务刚刚启动，正在建立目标列表并等待第一批结果返回。")
        }
        AppLanguage::English => String::from(
            "The scan has just started. Building the target list and waiting for the first results.",
        ),
    }
}

fn scanning_progress_description(
    app_language: AppLanguage,
    scanned: usize,
    total: usize,
) -> String {
    match app_language {
        AppLanguage::Chinese => {
            format!("当前扫描进度 {scanned}/{total}，发现的设备会在这里逐步回到列表。")
        }
        AppLanguage::English => format!(
            "Progress {scanned}/{total}. Newly discovered devices will appear here as the scan continues."
        ),
    }
}

fn empty_results_chip_label(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "本轮未发现设备",
        AppLanguage::English => "No Devices Found",
    }
}

fn empty_results_title(app_language: AppLanguage) -> &'static str {
    match app_language {
        AppLanguage::Chinese => "列表保持为空",
        AppLanguage::English => "The List Is Empty",
    }
}

fn empty_results_description(app_language: AppLanguage) -> String {
    match app_language {
        AppLanguage::Chinese => {
            String::from("当前网段没有发现在线设备，可以切换网卡或稍后重新扫描。")
        }
        AppLanguage::English => String::from(
            "No online devices were found on this subnet. Try another interface or scan again later.",
        ),
    }
}

fn status_chip<'a, Message: 'a>(
    visual: PlaceholderVisual,
    label: &'static str,
    tone: iced::Color,
) -> Element<'a, Message> {
    container(
        row![
            container(placeholder_visual_centered(visual, tone, 10.0, 6.5))
                .width(14)
                .height(14)
                .center_x(Length::Fixed(14.0))
                .center_y(Length::Fixed(14.0))
                .style(move |theme| {
                    let is_dark = colors::palette(theme).card == colors::DARK.card;
                    container::Style::default()
                        .background(if is_dark {
                            colors::DARK_ACCENT_SOFT
                        } else {
                            colors::LIGHT_ACCENT_SOFT
                        })
                        .border(iced::Border {
                            color: colors::rgba(
                                (tone.r * 255.0).round() as u8,
                                (tone.g * 255.0).round() as u8,
                                (tone.b * 255.0).round() as u8,
                                0.32,
                            ),
                            width: 1.0,
                            radius: border::radius(999),
                        })
                }),
            text(label)
                .font(fonts::body())
                .size(11)
                .style(move |_| theme::solid_text(tone)),
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([5, 9])
    .style(move |theme| {
        let is_dark = colors::palette(theme).card == colors::DARK.card;
        container::Style::default()
            .background(if is_dark {
                colors::DARK_ACCENT_SOFT
            } else {
                colors::LIGHT_ACCENT_SOFT
            })
            .border(iced::Border {
                color: colors::rgba(
                    (tone.r * 255.0).round() as u8,
                    (tone.g * 255.0).round() as u8,
                    (tone.b * 255.0).round() as u8,
                    0.24,
                ),
                width: 1.0,
                radius: border::radius(999),
            })
    })
    .into()
}

fn placeholder_visual_centered<'a, Message: 'a>(
    visual: PlaceholderVisual,
    tone: iced::Color,
    slot: f32,
    size: f32,
) -> Element<'a, Message> {
    match visual {
        PlaceholderVisual::Glyph(glyph) => icons::centered(glyph, slot, size, tone),
        PlaceholderVisual::RotatingRefresh(frame) => {
            icons::rotating_refresh_centered(frame, slot, size, tone)
        }
    }
}
