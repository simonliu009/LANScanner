use iced::widget::{Space, button, checkbox, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Theme, border};
use ui::device_list::ResultColumn;
use ui::theme::{self, AppLanguage, colors};

use crate::message::Message;

use super::super::{ScanResultFilter, ShellApp};

pub(super) fn scan_result_filter_controls(app: &ShellApp) -> Element<'_, Message> {
    if !app.has_scanned {
        return Space::new()
            .width(Length::Shrink)
            .height(Length::Shrink)
            .into();
    }

    let controls = row![
        scan_result_filter_button(
            localized(app.app_language, "全部在线", "All Online"),
            app.scan_result_filter == ScanResultFilter::AllOnline,
            Message::ShowAllOnlineResults
        ),
        scan_result_filter_button(
            localized(app.app_language, "SSH", "SSH"),
            app.scan_result_filter == ScanResultFilter::SshReady,
            Message::ShowSshReadyResults
        ),
        scan_result_filter_button(
            localized(
                app.app_language,
                if app.result_column_visibility.has_any_optional_column() {
                    "列"
                } else {
                    "选择列"
                },
                if app.result_column_visibility.has_any_optional_column() {
                    "Columns"
                } else {
                    "Choose Columns"
                },
            ),
            app.result_column_selector_open || app.result_column_visibility.has_any_optional_column(),
            Message::ToggleResultColumnSelector,
        ),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let content = if app.result_column_selector_open {
        column![controls, result_column_selector(app)]
            .spacing(8)
            .align_x(Alignment::End)
    } else {
        column![controls].spacing(0).align_x(Alignment::End)
    };

    container(content)
    .padding([3, 4])
    .style(|theme: &Theme| {
        let palette = colors::palette(theme);
        container::Style::default()
            .background(palette.input)
            .border(iced::Border {
                color: palette.border,
                width: 1.0,
                radius: border::radius(999),
            })
    })
    .into()
}

fn result_column_selector(app: &ShellApp) -> Element<'_, Message> {
    let visibility = app.result_column_visibility;
    let entries = [
        (ResultColumn::MacAddress, visibility.mac_address),
        (ResultColumn::Hostname, visibility.hostname),
        (ResultColumn::Vendor, visibility.vendor),
        (ResultColumn::DnsName, visibility.dns_name),
        (ResultColumn::MdnsName, visibility.mdns_name),
        (ResultColumn::SmbName, visibility.smb_name),
        (ResultColumn::SmbDomain, visibility.smb_domain),
    ];

    let selector_row = entries.into_iter().fold(
        row!().spacing(14).align_y(Alignment::Center),
        |row, (result_column, is_checked)| {
            row.push(column_toggle(app.app_language, result_column, is_checked))
        },
    );

    let selector = column![
        selector_hint(app.app_language),
        scrollable(selector_row)
            .direction(scrollable::Direction::Horizontal(
                scrollable::Scrollbar::default(),
            ))
            .width(Length::Fill)
    ]
    .spacing(6)
    .width(Length::Fill);

    container(selector)
        .padding([8, 10])
        .width(Length::Fill)
        .style(|theme: &Theme| {
            let palette = colors::palette(theme);
            container::Style::default()
                .background(palette.card)
                .border(iced::Border {
                    color: palette.border,
                    width: 1.0,
                    radius: border::radius(12),
                })
        })
        .into()
}

fn selector_hint(language: AppLanguage) -> Element<'static, Message> {
    text(localized(
        language,
        "勾选需要显示的列",
        "Check columns to show",
    ))
    .size(11)
    .style(|theme: &Theme| theme::text_muted(theme))
    .into()
}

fn column_toggle(
    language: AppLanguage,
    column: ResultColumn,
    is_checked: bool,
) -> Element<'static, Message> {
    checkbox(is_checked)
        .label(result_column_label(language, column))
        .size(14)
        .spacing(6)
        .text_size(12)
        .style(|theme: &Theme, status| {
            let palette = colors::palette(theme);
            let base = iced::widget::checkbox::primary(theme, status);
            iced::widget::checkbox::Style {
                background: base.background,
                icon_color: colors::LIGHT.card,
                border: iced::Border {
                    color: palette.border,
                    width: 1.0,
                    radius: border::radius(4),
                },
                text_color: Some(palette.text),
            }
        })
        .on_toggle(move |checked| Message::SetResultColumnVisible(column, checked))
        .into()
}

fn result_column_label(language: AppLanguage, column: ResultColumn) -> &'static str {
    match column {
        ResultColumn::MacAddress => localized(language, "MAC 地址", "MAC Address"),
        ResultColumn::Hostname => localized(language, "主机名", "Hostname"),
        ResultColumn::Vendor => localized(language, "厂商", "Vendor"),
        ResultColumn::DnsName => localized(language, "DNS 名称", "DNS Name"),
        ResultColumn::MdnsName => localized(language, "mDNS 名称", "mDNS Name"),
        ResultColumn::SmbName => localized(language, "SMB 名称", "SMB Name"),
        ResultColumn::SmbDomain => localized(language, "SMB 域", "SMB Domain"),
    }
}

fn scan_result_filter_button<'a>(
    label: &'static str,
    is_active: bool,
    message: Message,
) -> Element<'a, Message> {
    button(
        text(label)
            .size(12)
            .font(ui::theme::fonts::semibold())
            .style(move |theme: &Theme| {
                if is_active {
                    theme::solid_text(colors::LIGHT.card)
                } else {
                    theme::text_muted(theme)
                }
            }),
    )
    .padding([5, 14])
    .style(move |theme: &Theme, status| {
        let palette = colors::palette(theme);
        let is_dark = palette.card == colors::DARK.card;
        let background = if is_active {
            match status {
                button::Status::Pressed => colors::rgb(0x1D, 0x4E, 0xD8),
                button::Status::Hovered => colors::rgb(0x25, 0x63, 0xEB),
                _ => colors::BRAND_BLUE,
            }
        } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
            if is_dark {
                colors::rgba(0xFF, 0xFF, 0xFF, 0.08)
            } else {
                colors::rgba(0xE5, 0xE7, 0xEB, 0.90)
            }
        } else {
            iced::Color::TRANSPARENT
        };
        button::Style {
            snap: false,
            background: Some(iced::Background::Color(background)),
            text_color: if is_active {
                colors::LIGHT.card
            } else {
                palette.muted_text
            },
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: border::radius(999),
            },
            shadow: iced::Shadow::default(),
        }
    })
    .on_press(message)
    .into()
}

fn localized(language: AppLanguage, chinese: &'static str, english: &'static str) -> &'static str {
    match language {
        AppLanguage::Chinese => chinese,
        AppLanguage::English => english,
    }
}
