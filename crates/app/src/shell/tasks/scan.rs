use std::collections::HashMap;

use iced::Task;
use iced::futures::SinkExt;
use iced::task::Handle;
use platform::network as platform_network;
use ssh_core::network::NetworkInterface;
use ssh_core::scanner::{
    LayeredScanDevice, NeighborEvidence, TcpProbeReport,
    build_layered_scan_devices_from_probe_report,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::message::Message;

pub(super) fn spawn_scan_task(
    network: NetworkInterface,
    cancel_token: CancellationToken,
    session_id: u64,
) -> (Task<Message>, Handle) {
    let stream = iced::stream::channel::<Message>(100, async move |mut output| {
        let (candidate_tx, mut candidate_rx) = mpsc::unbounded_channel();
        let worker_network = network.clone();
        let worker = tokio::spawn(async move {
            platform_network::discover_online_neighbor_candidates_streaming(
                &worker_network.local_ip,
                &worker_network.ip_range,
                candidate_tx,
            )
            .await
        });

        while let Some(candidate) = candidate_rx.recv().await {
            if cancel_token.is_cancelled() {
                return;
            }

            let ip = candidate.ip.clone();
            let evidence = candidate.evidence.clone();
            if output
                .send(Message::ScanOnlineDatasetReady {
                    session_id,
                    evidence_by_ip: std::iter::once((ip.clone(), evidence.clone())).collect(),
                })
                .await
                .is_err()
            {
                return;
            }

            let device = layered_device_from_candidate(ip, evidence);
            if output
                .send(Message::ScanDeviceDiscovered { session_id, device })
                .await
                .is_err()
            {
                return;
            }
        }

        let candidates = worker.await.unwrap_or_default();
        let (online_ips, evidence_by_ip) = platform_network::split_neighbor_candidates(candidates);

        if cancel_token.is_cancelled() {
            return;
        }

        if output
            .send(Message::ScanOnlineDatasetReady {
                session_id,
                evidence_by_ip,
            })
            .await
            .is_err()
        {
            return;
        }

        let total = online_ips.len();
        if total == 0 {
            let _ = output
                .send(Message::ScanProgress {
                    session_id,
                    scanned: 0,
                    total: 0,
                })
                .await;
            let _ = output.send(Message::ScanFinished { session_id }).await;
            return;
        }
        let _ = output
            .send(Message::ScanProgress {
                session_id,
                scanned: total,
                total,
            })
            .await;

        let _ = output.send(Message::ScanFinished { session_id }).await;
    });

    Task::run(stream, |message| message).abortable()
}

fn layered_device_from_candidate(ip: String, evidence: NeighborEvidence) -> LayeredScanDevice {
    let mut evidence_by_ip = HashMap::with_capacity(1);
    evidence_by_ip.insert(ip.clone(), evidence);
    build_layered_scan_devices_from_probe_report(
        vec![ip],
        &TcpProbeReport::default(),
        evidence_by_ip,
    )
    .online_devices
    .into_iter()
    .next()
    .expect("single candidate should produce one layered device")
}

pub(super) fn spawn_ssh_probe_task(
    network: NetworkInterface,
    candidate_ips: Vec<String>,
    cancel_token: CancellationToken,
    session_id: u64,
) -> (Task<Message>, Handle) {
    let stream = iced::stream::channel::<Message>(100, async move |mut output| {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let worker_network = network.clone();
        let worker_token = cancel_token.clone();
        let worker = tokio::spawn(async move {
            ssh_core::scanner::scan_subnet_report(
                &worker_network.local_ip,
                &worker_network.ip_range,
                candidate_ips,
                move |scanned, total| {
                    let _ = progress_tx.send((scanned, total));
                },
                worker_token,
            )
            .await
        });

        while let Some((scanned, total)) = progress_rx.recv().await {
            if cancel_token.is_cancelled() {
                return;
            }
            if output
                .send(Message::ScanProgress {
                    session_id,
                    scanned,
                    total,
                })
                .await
                .is_err()
            {
                return;
            }
        }

        if cancel_token.is_cancelled() {
            return;
        }

        let report = worker.await.unwrap_or_default();
        if cancel_token.is_cancelled() {
            return;
        }
        if output
            .send(Message::ScanSshProbeFinished { session_id, report })
            .await
            .is_err()
        {
            return;
        }
        let _ = output.send(Message::ScanFinished { session_id }).await;
    });

    Task::run(stream, |message| message).abortable()
}
