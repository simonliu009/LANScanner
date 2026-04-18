# Changelog

All notable changes to this project will be documented in this file.

## [0.2.13] - 2026-04-18

### Changed

- Removed duplicated and unused connection helper code paths that were no longer part of the active launch flow.
- Deleted unused placeholder message handling and obsolete device-detail badge helpers, and cleaned up related imports.
- Kept the project building cleanly after the result-table refactor by trimming dead code introduced during the previous release step.

## [0.2.12] - 2026-04-18

### Changed

- Reworked the scan results header controls into a single always-visible row with `All Online`, `SSH`, and all optional column checkboxes shown together.
- Changed the result table from proportional column sizing to fixed per-column widths so enabling extra columns no longer causes existing columns to jump.
- Added draggable resize handles on the result table headers so operators can adjust column widths directly.

## [0.2.11] - 2026-04-18

### Fixed

- Kept the scan result table header fixed while vertically scrolling the device rows.
- Improved MAC enrichment by re-reading neighbor table evidence after active host discovery so reachable devices are less likely to miss MAC addresses.
- Improved hostname discovery by adding active hostname resolution paths, including mDNS address resolution on Linux and additional hostname sources on Windows.
- Kept the scan action button at a fixed width and prevented its label from wrapping.

## [0.2.10] - 2026-04-18

### Changed

- Reworked the scan result column controls into a two-row header layout with the filter buttons grouped on the left and the optional column checkboxes shown persistently on the right.
- Removed the old column-selector toggle flow and updated the result header sizing so the full checkbox area stays visible.
- Enlarged the credential sidebar collapse button and adjusted its alignment so it sits vertically centered within the header row.

## [0.2.9] - 2026-04-18

### Changed

- Changed the scan results table to show column selectors in a single horizontal row of checkboxes.
- Split the original mixed device label into separate `Device Name` and `Network Name` columns, and fixed the local machine row to display `[本机]` as its base device name.

## [0.2.8] - 2026-04-18

### Changed

- Replaced the all-at-once expanded scan result view with per-column checkboxes so operators can reveal only the fields they need.
- Removed the inaccurate device type column and fixed expanded table header alignment so headers always match the rendered data columns.

## [0.2.7] - 2026-04-18

### Changed

- Pinned the local device to the top of the scan results table and applied full-row highlighting instead of partial emphasis.

## [0.2.6] - 2026-04-18

### Changed

- Reworked scan results into a sortable, monospace table with collapsible extended columns and horizontal scrolling support.
- Changed the credential panel collapse behavior to a left-right layout so the scan results can use more horizontal space.

## [0.2.5] - 2026-04-18

### Fixed

- Aligned the app package version, release metadata, and generated desktop bundle versions with the `v0.2.5` release.

## [0.1.0] - 2026-04-07

### Added

- Initial public open-source release of the Rust + iced LANScanner desktop application.
- Workspace structure with `crates/app`, `crates/core`, `crates/platform`, and `crates/ui`.
- LAN device discovery, SSH verification, credential management, and key handling flows.
- External launcher integration for tools such as VSCode, MobaXterm, VNC Viewer, and RustDesk.
- Windows build entrypoint under `tools/build/windows.ps1`.
