use ui::credential_card::{
    CARD_PADDING as CREDENTIAL_CARD_PADDING, COLLAPSED_COLUMN_WIDTH, USER_DROPDOWN_TOP_OFFSET,
};
use ui::scan_card::{
    TOOLBAR_DROPDOWN_WIDTH, TOOLBAR_REFRESH_BUTTON_EDGE, TOOLBAR_SCAN_BUTTON_WIDTH, TOOLBAR_SPACING,
};
use ui::widgets::dropdown::{MENU_GAP, TRIGGER_HEIGHT};

pub(super) const WINDOW_PADDING: f32 = 0.0;
const WINDOW_MIN_WIDTH: f32 = 1050.0;
const TITLEBAR_HEIGHT: f32 = 54.0;
const CONTENT_TOP_PADDING: f32 = 20.0;
pub(super) const CONTENT_PADDING: f32 = 20.0;
pub(super) const LEFT_COLUMN_WIDTH: f32 = 320.0;
pub(super) const LEFT_COLUMN_SPACING: f32 = 20.0;
pub(super) const CONTENT_SPACING: f32 = 20.0;
pub(super) const RIGHT_PANEL_PADDING: f32 = 0.0;
const TITLEBAR_HORIZONTAL_PADDING: f32 = 20.0;
const TITLEBAR_TOOL_BUTTON_EDGE: f32 = 36.0;
const TITLEBAR_TOOL_SPACING: f32 = 5.0;
const TITLEBAR_CONTROL_BUTTON_EDGE: f32 = 36.0;
const TITLEBAR_CONTROL_SPACING: f32 = 3.0;

fn top_toolbar_width() -> f32 {
    TOOLBAR_DROPDOWN_WIDTH
        + TOOLBAR_SPACING
        + TOOLBAR_REFRESH_BUTTON_EDGE
        + TOOLBAR_SPACING
        + TOOLBAR_SCAN_BUTTON_WIDTH
        + TITLEBAR_TOOL_SPACING
        + TITLEBAR_TOOL_BUTTON_EDGE
        + TITLEBAR_TOOL_SPACING
        + TITLEBAR_TOOL_BUTTON_EDGE
        + TITLEBAR_TOOL_SPACING
        + TITLEBAR_TOOL_BUTTON_EDGE
        + TITLEBAR_TOOL_SPACING
        + TITLEBAR_CONTROL_BUTTON_EDGE
        + TITLEBAR_CONTROL_SPACING
        + TITLEBAR_CONTROL_BUTTON_EDGE
        + TITLEBAR_CONTROL_SPACING
        + TITLEBAR_CONTROL_BUTTON_EDGE
}

pub(super) fn scan_dropdown_left() -> f32 {
    WINDOW_MIN_WIDTH - TITLEBAR_HORIZONTAL_PADDING - top_toolbar_width()
}

pub(super) fn scan_dropdown_top() -> f32 {
    ((TITLEBAR_HEIGHT - TRIGGER_HEIGHT) / 2.0) + TRIGGER_HEIGHT + MENU_GAP
}

pub(super) fn scan_dropdown_width() -> f32 {
    TOOLBAR_DROPDOWN_WIDTH
}

pub(super) fn credential_dropdown_left() -> f32 {
    WINDOW_PADDING + CONTENT_TOP_PADDING + f32::from(CREDENTIAL_CARD_PADDING)
}

pub(super) fn credential_dropdown_top() -> f32 {
    WINDOW_PADDING
        + TITLEBAR_HEIGHT
        + CONTENT_TOP_PADDING
        + USER_DROPDOWN_TOP_OFFSET
        + TRIGGER_HEIGHT
        + MENU_GAP
}

pub(super) fn credential_dropdown_width(collapsed: bool) -> f32 {
    left_column_width(collapsed) - (f32::from(CREDENTIAL_CARD_PADDING) * 2.0)
}
pub(super) fn left_column_width(collapsed: bool) -> f32 {
    if collapsed {
        COLLAPSED_COLUMN_WIDTH
    } else {
        LEFT_COLUMN_WIDTH
    }
}
