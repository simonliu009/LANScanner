# Changelog

All notable changes to this project will be documented in this file.

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
