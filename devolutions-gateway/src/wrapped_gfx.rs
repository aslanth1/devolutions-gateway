use std::any::TypeId;
use std::sync::{Arc, Mutex};

use ironrdp_connector::legacy;
use ironrdp_core::{Decode as _, ReadCursor, decode, impl_as_any};
use ironrdp_dvc::{DrdynvcClient, DvcMessage, DvcProcessor};
use ironrdp_graphics::zgfx;
use ironrdp_pdu::rdp::vc::dvc::gfx;
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{PduResult, mcs};
use ironrdp_svc::StaticChannelSet;
use tracing::{debug, info, warn};
use uuid::Uuid;

const DRDYNVC_CHANNEL_NAME: &str = "drdynvc";
const RDPGFX_DVC_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

pub(crate) struct WrappedGfxExtractor {
    drdynvc_channel_index: Option<usize>,
    client_pdu_buffer: Vec<u8>,
    server_pdu_buffer: Vec<u8>,
    static_channels: StaticChannelSet,
    extracted_rdpegfx_pdus: Arc<Mutex<Vec<Vec<u8>>>>,
    stats: Arc<Mutex<WrappedGfxStats>>,
}

impl WrappedGfxExtractor {
    pub(crate) fn new() -> Self {
        let extracted_rdpegfx_pdus = Arc::new(Mutex::new(Vec::new()));
        let stats = Arc::new(Mutex::new(WrappedGfxStats::default()));
        let mut static_channels = StaticChannelSet::new();
        static_channels.insert(DrdynvcClient::new().with_dynamic_channel(RdpgfxServerTap::new(
            Arc::clone(&extracted_rdpegfx_pdus),
            Arc::clone(&stats),
        )));

        Self {
            drdynvc_channel_index: None,
            client_pdu_buffer: Vec::new(),
            server_pdu_buffer: Vec::new(),
            static_channels,
            extracted_rdpegfx_pdus,
            stats,
        }
    }

    pub(crate) fn observe_client_packet(&mut self, data: &[u8]) {
        self.with_stats(|stats| stats.client_packet_count = stats.client_packet_count.saturating_add(1));
        self.client_pdu_buffer.extend_from_slice(data);

        while let Some(frame) = self.take_next_client_frame() {
            if self.drdynvc_channel_index.is_some() {
                continue;
            }

            let Ok(connect_initial) = decode::<X224<ironrdp_pdu::x224::X224Data<'_>>>(&frame) else {
                continue;
            };
            let Ok(connect_initial) = decode::<mcs::ConnectInitial>(connect_initial.0.data.as_ref()) else {
                continue;
            };
            self.with_stats(|stats| stats.connect_initial_count = stats.connect_initial_count.saturating_add(1));

            let Some(ref network) = connect_initial.conference_create_request.gcc_blocks().network else {
                continue;
            };

            self.drdynvc_channel_index = network
                .channels
                .iter()
                .position(|channel| channel.name.as_str() == Some(DRDYNVC_CHANNEL_NAME));

            match self.drdynvc_channel_index {
                Some(index) => {
                    let channel_names = network
                        .channels
                        .iter()
                        .map(|channel| format!("{:?}", channel.name))
                        .collect::<Vec<_>>();
                    info!(
                        drdynvc_channel_index = index,
                        channel_count = channel_names.len(),
                        channel_names = ?channel_names,
                        "Learned drdynvc static-channel position from ConnectInitial",
                    );
                }
                None => {
                    let channel_names = network
                        .channels
                        .iter()
                        .map(|channel| format!("{:?}", channel.name))
                        .collect::<Vec<_>>();
                    warn!(
                        channel_count = channel_names.len(),
                        channel_names = ?channel_names,
                        "ConnectInitial did not request the drdynvc static channel",
                    );
                }
            }
        }
    }

    pub(crate) fn observe_server_packet(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.with_stats(|stats| stats.server_packet_count = stats.server_packet_count.saturating_add(1));
        self.server_pdu_buffer.extend_from_slice(data);

        while let Some(frame) = self.take_next_server_frame() {
            self.maybe_attach_drdynvc_channel_id(&frame);

            let Some(drdynvc_channel_id) = self.static_channels.get_channel_id_by_type::<DrdynvcClient>() else {
                continue;
            };

            let Ok(data_ctx) = legacy::decode_send_data_indication(&frame) else {
                continue;
            };
            self.with_stats(|stats| {
                stats.send_data_indication_count = stats.send_data_indication_count.saturating_add(1);
                stats.remember_send_data_channel_id(data_ctx.channel_id);
            });

            if data_ctx.channel_id != drdynvc_channel_id {
                continue;
            }
            self.with_stats(|stats| {
                stats.matched_drdynvc_payload_count = stats.matched_drdynvc_payload_count.saturating_add(1);
            });

            debug!(
                channel_id = drdynvc_channel_id,
                payload_len = data_ctx.user_data.len(),
                "Dispatching wrapped drdynvc static-channel payload",
            );

            let Some(channel) = self.static_channels.get_by_channel_id_mut(drdynvc_channel_id) else {
                continue;
            };

            match channel.process(data_ctx.user_data) {
                Ok(responses) => {
                    self.with_stats(|stats| {
                        stats.drdynvc_response_count = stats
                            .drdynvc_response_count
                            .saturating_add(u64::try_from(responses.len()).unwrap_or(u64::MAX));
                    });
                    if !responses.is_empty() {
                        debug!(
                            channel_id = drdynvc_channel_id,
                            response_count = responses.len(),
                            "Wrapped drdynvc observer synthesized client responses while tapping server traffic",
                        );
                    }
                }
                Err(error) => {
                    self.with_stats(|stats| {
                        stats.drdynvc_process_error_count = stats.drdynvc_process_error_count.saturating_add(1);
                    });
                    warn!(
                        channel_id = drdynvc_channel_id,
                        error = %error,
                        "Failed to process wrapped drdynvc static-channel payload",
                    );
                }
            }
        }

        self.drain_extracted_pdus()
    }

    pub(crate) fn log_summary(&self, session_id: Uuid) {
        let stats = self.snapshot_stats();
        let stage = self.current_stage(&stats);
        let drdynvc_channel_id = self.static_channels.get_channel_id_by_type::<DrdynvcClient>();
        let pending_extracted_pdu_count = self
            .extracted_rdpegfx_pdus
            .lock()
            .expect("wrapped RDPEGFX extractor mutex poisoned")
            .len();

        info!(
            session_id = %session_id,
            stage = stage.as_str(),
            client_packet_count = stats.client_packet_count,
            server_packet_count = stats.server_packet_count,
            client_frame_count = stats.client_frame_count,
            server_frame_count = stats.server_frame_count,
            client_parse_drop_count = stats.client_parse_drop_count,
            server_parse_drop_count = stats.server_parse_drop_count,
            connect_initial_count = stats.connect_initial_count,
            connect_response_count = stats.connect_response_count,
            drdynvc_channel_index = self.drdynvc_channel_index,
            drdynvc_channel_id,
            send_data_indication_count = stats.send_data_indication_count,
            last_send_data_channel_ids = ?stats.last_send_data_channel_ids,
            matched_drdynvc_payload_count = stats.matched_drdynvc_payload_count,
            drdynvc_process_error_count = stats.drdynvc_process_error_count,
            drdynvc_response_count = stats.drdynvc_response_count,
            rdpgfx_dynamic_channel_open_count = stats.rdpgfx_dynamic_channel_open_count,
            rdpgfx_dynamic_channel_ids = ?stats.rdpgfx_dynamic_channel_ids,
            rdpgfx_dynamic_payload_count = stats.rdpgfx_dynamic_payload_count,
            rdpgfx_raw_decode_success_count = stats.rdpgfx_raw_decode_success_count,
            rdpgfx_zgfx_decode_success_count = stats.rdpgfx_zgfx_decode_success_count,
            rdpgfx_decode_error_count = stats.rdpgfx_decode_error_count,
            extracted_pdu_count = stats.extracted_pdu_count,
            pending_extracted_pdu_count,
            client_buffer_len = self.client_pdu_buffer.len(),
            server_buffer_len = self.server_pdu_buffer.len(),
            "Wrapped graphics extractor summary",
        );
    }

    fn maybe_attach_drdynvc_channel_id(&mut self, data: &[u8]) {
        if self.static_channels.get_channel_id_by_type::<DrdynvcClient>().is_some() {
            return;
        }

        let Some(drdynvc_channel_index) = self.drdynvc_channel_index else {
            return;
        };

        let Ok(connect_response) = decode::<X224<ironrdp_pdu::x224::X224Data<'_>>>(data) else {
            return;
        };
        let Ok(connect_response) = decode::<mcs::ConnectResponse>(connect_response.0.data.as_ref()) else {
            return;
        };
        self.with_stats(|stats| stats.connect_response_count = stats.connect_response_count.saturating_add(1));

        let Some(channel_id) = connect_response
            .conference_create_response
            .gcc_blocks()
            .network
            .channel_ids
            .get(drdynvc_channel_index)
            .copied()
        else {
            warn!(
                drdynvc_channel_index,
                channel_count = connect_response
                    .conference_create_response
                    .gcc_blocks()
                    .network
                    .channel_ids
                    .len(),
                "ConnectResponse did not contain the drdynvc static-channel slot",
            );
            return;
        };

        self.static_channels
            .attach_channel_id(TypeId::of::<DrdynvcClient>(), channel_id);
        info!(
            channel_id,
            drdynvc_channel_index,
            channel_count = connect_response
                .conference_create_response
                .gcc_blocks()
                .network
                .channel_ids
                .len(),
            "Attached drdynvc static-channel ID from ConnectResponse",
        );
    }

    fn drain_extracted_pdus(&self) -> Vec<Vec<u8>> {
        let mut extracted_rdpegfx_pdus = self
            .extracted_rdpegfx_pdus
            .lock()
            .expect("wrapped RDPEGFX extractor mutex poisoned");
        std::mem::take(&mut *extracted_rdpegfx_pdus)
    }

    fn with_stats(&self, update: impl FnOnce(&mut WrappedGfxStats)) {
        let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
        update(&mut stats);
    }

    fn snapshot_stats(&self) -> WrappedGfxStats {
        self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned").clone()
    }

    fn current_stage(&self, stats: &WrappedGfxStats) -> WrappedGfxStage {
        if self.drdynvc_channel_index.is_none() {
            WrappedGfxStage::AwaitingConnectInitial
        } else if self.static_channels.get_channel_id_by_type::<DrdynvcClient>().is_none() {
            WrappedGfxStage::AwaitingConnectResponse
        } else if stats.matched_drdynvc_payload_count == 0 {
            WrappedGfxStage::AwaitingDrdynvcStaticPayload
        } else if stats.rdpgfx_dynamic_channel_open_count == 0 {
            WrappedGfxStage::AwaitingRdpgfxDynamicChannel
        } else if stats.rdpgfx_dynamic_payload_count == 0 {
            WrappedGfxStage::AwaitingRdpgfxPayload
        } else if stats.extracted_pdu_count == 0 {
            WrappedGfxStage::AwaitingDecodedRdpegfx
        } else {
            WrappedGfxStage::ExtractingRdpegfx
        }
    }

    fn take_next_client_frame(&mut self) -> Option<Vec<u8>> {
        match Self::take_next_rdp_frame(&mut self.client_pdu_buffer, "client_to_server") {
            NextFrame::Frame(frame) => {
                self.with_stats(|stats| stats.client_frame_count = stats.client_frame_count.saturating_add(1));
                Some(frame)
            }
            NextFrame::InvalidPrefixDropped => {
                self.with_stats(|stats| {
                    stats.client_parse_drop_count = stats.client_parse_drop_count.saturating_add(1);
                });
                None
            }
            NextFrame::NeedMoreData => None,
        }
    }

    fn take_next_server_frame(&mut self) -> Option<Vec<u8>> {
        match Self::take_next_rdp_frame(&mut self.server_pdu_buffer, "server_to_client") {
            NextFrame::Frame(frame) => {
                self.with_stats(|stats| stats.server_frame_count = stats.server_frame_count.saturating_add(1));
                Some(frame)
            }
            NextFrame::InvalidPrefixDropped => {
                self.with_stats(|stats| {
                    stats.server_parse_drop_count = stats.server_parse_drop_count.saturating_add(1);
                });
                None
            }
            NextFrame::NeedMoreData => None,
        }
    }

    fn take_next_rdp_frame(buffer: &mut Vec<u8>, direction: &'static str) -> NextFrame {
        match ironrdp_pdu::find_size(buffer) {
            Ok(Some(info)) => {
                if info.length == 0 {
                    let prefix_len = buffer.len().min(16);
                    let prefix = buffer[..prefix_len]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    warn!(
                        direction,
                        buffer_len = buffer.len(),
                        prefix_hex = %prefix,
                        "Wrapped graphics extractor dropped a zero-length RDP frame prefix",
                    );
                    buffer.clear();
                    return NextFrame::InvalidPrefixDropped;
                }

                if buffer.len() < info.length {
                    return NextFrame::NeedMoreData;
                }

                NextFrame::Frame(buffer.drain(..info.length).collect())
            }
            Ok(None) => NextFrame::NeedMoreData,
            Err(error) => {
                let prefix_len = buffer.len().min(16);
                let prefix = buffer[..prefix_len]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                warn!(
                    direction,
                    buffer_len = buffer.len(),
                    prefix_hex = %prefix,
                    error = %error,
                    "Wrapped graphics extractor dropped an invalid RDP frame prefix",
                );
                buffer.clear();
                NextFrame::InvalidPrefixDropped
            }
        }
    }
}

impl Default for WrappedGfxExtractor {
    fn default() -> Self {
        Self::new()
    }
}

struct RdpgfxServerTap {
    extracted_rdpegfx_pdus: Arc<Mutex<Vec<Vec<u8>>>>,
    stats: Arc<Mutex<WrappedGfxStats>>,
    zgfx_decompressor: zgfx::Decompressor,
    zgfx_scratch: Vec<u8>,
}

impl RdpgfxServerTap {
    const ZGFX_SINGLE_DESCRIPTOR: u8 = 0xe0;
    const ZGFX_MULTIPART_DESCRIPTOR: u8 = 0xe1;

    fn new(extracted_rdpegfx_pdus: Arc<Mutex<Vec<Vec<u8>>>>, stats: Arc<Mutex<WrappedGfxStats>>) -> Self {
        Self {
            extracted_rdpegfx_pdus,
            stats,
            zgfx_decompressor: Default::default(),
            zgfx_scratch: Vec::new(),
        }
    }

    fn looks_like_zgfx(payload: &[u8]) -> bool {
        matches!(
            payload.first().copied(),
            Some(Self::ZGFX_SINGLE_DESCRIPTOR | Self::ZGFX_MULTIPART_DESCRIPTOR)
        )
    }

    fn push_extracted_pdu(&self, pdu_bytes: Vec<u8>) {
        let mut extracted_rdpegfx_pdus = self
            .extracted_rdpegfx_pdus
            .lock()
            .expect("wrapped RDPEGFX extractor mutex poisoned");
        extracted_rdpegfx_pdus.push(pdu_bytes);
        let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
        stats.extracted_pdu_count = stats.extracted_pdu_count.saturating_add(1);
    }

    fn split_rdpegfx_payload(payload: &[u8]) -> PduResult<Vec<&[u8]>> {
        let mut cursor = ReadCursor::new(payload);
        let mut pdus = Vec::new();

        while !cursor.is_empty() {
            let start = cursor.pos();
            gfx::ServerPdu::decode(&mut cursor).map_err(|error| ironrdp_pdu::decode_err!(error))?;
            let end = cursor.pos();
            pdus.push(&payload[start..end]);
        }

        Ok(pdus)
    }

    fn extract_rdpegfx_payload(&self, channel_id: u32, payload: &[u8], transport: &'static str) -> PduResult<()> {
        let pdus = Self::split_rdpegfx_payload(payload)?;

        debug!(
            channel_id,
            transport,
            payload_len = payload.len(),
            extracted_pdu_count = pdus.len(),
            "Split wrapped RDPGFX payload into discrete server PDUs",
        );

        for pdu in pdus {
            self.push_extracted_pdu(pdu.to_vec());
        }

        Ok(())
    }
}

impl_as_any!(RdpgfxServerTap);

impl DvcProcessor for RdpgfxServerTap {
    fn channel_name(&self) -> &str {
        RDPGFX_DVC_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
        stats.rdpgfx_dynamic_channel_open_count = stats.rdpgfx_dynamic_channel_open_count.saturating_add(1);
        stats.remember_rdpgfx_dynamic_channel_id(channel_id);
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        {
            let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
            stats.rdpgfx_dynamic_payload_count = stats.rdpgfx_dynamic_payload_count.saturating_add(1);
            stats.remember_rdpgfx_dynamic_channel_id(channel_id);
        }

        match gfx::ServerPdu::decode(&mut ReadCursor::new(payload)) {
            Ok(_pdu) => {
                let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
                stats.rdpgfx_raw_decode_success_count = stats.rdpgfx_raw_decode_success_count.saturating_add(1);
                drop(stats);
                self.extract_rdpegfx_payload(channel_id, payload, "raw")?;
                Ok(Vec::new())
            }
            Err(_raw_error) if Self::looks_like_zgfx(payload) => {
                self.zgfx_scratch.clear();

                match self.zgfx_decompressor.decompress(payload, &mut self.zgfx_scratch) {
                    Ok(bytes_written) => {
                        let decoded = &self.zgfx_scratch[..bytes_written];
                        match gfx::ServerPdu::decode(&mut ReadCursor::new(decoded)) {
                            Ok(_pdu) => {
                                let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
                                stats.rdpgfx_zgfx_decode_success_count =
                                    stats.rdpgfx_zgfx_decode_success_count.saturating_add(1);
                                drop(stats);
                                debug!(
                                    channel_id,
                                    payload_len = payload.len(),
                                    decompressed_len = bytes_written,
                                    "Extracted ZGFX-wrapped RDPGFX payload from drdynvc",
                                );
                                self.extract_rdpegfx_payload(channel_id, decoded, "zgfx")?;
                                Ok(Vec::new())
                            }
                            Err(decompressed_error) => {
                                let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
                                stats.rdpgfx_decode_error_count = stats.rdpgfx_decode_error_count.saturating_add(1);
                                warn!(
                                    channel_id,
                                    payload_len = payload.len(),
                                    decompressed_len = bytes_written,
                                    error = %decompressed_error,
                                    "Failed to decode decompressed wrapped RDPGFX payload",
                                );
                                Err(ironrdp_pdu::decode_err!(decompressed_error))
                            }
                        }
                    }
                    Err(zgfx_error) => {
                        let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
                        stats.rdpgfx_decode_error_count = stats.rdpgfx_decode_error_count.saturating_add(1);
                        warn!(
                            channel_id,
                            payload_len = payload.len(),
                            error = %zgfx_error,
                            "Failed to decompress wrapped RDPGFX payload",
                        );
                        Err(ironrdp_pdu::decode_err!(zgfx_error))
                    }
                }
            }
            Err(raw_error) => {
                let mut stats = self.stats.lock().expect("wrapped RDPEGFX stats mutex poisoned");
                stats.rdpgfx_decode_error_count = stats.rdpgfx_decode_error_count.saturating_add(1);
                warn!(
                    channel_id,
                    payload_len = payload.len(),
                    error = %raw_error,
                    "Failed to decode wrapped RDPGFX payload",
                );
                Err(ironrdp_pdu::decode_err!(raw_error))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WrappedGfxStats {
    client_packet_count: u64,
    server_packet_count: u64,
    client_frame_count: u64,
    server_frame_count: u64,
    client_parse_drop_count: u64,
    server_parse_drop_count: u64,
    connect_initial_count: u64,
    connect_response_count: u64,
    send_data_indication_count: u64,
    matched_drdynvc_payload_count: u64,
    drdynvc_process_error_count: u64,
    drdynvc_response_count: u64,
    rdpgfx_dynamic_channel_open_count: u64,
    rdpgfx_dynamic_payload_count: u64,
    rdpgfx_raw_decode_success_count: u64,
    rdpgfx_zgfx_decode_success_count: u64,
    rdpgfx_decode_error_count: u64,
    extracted_pdu_count: u64,
    last_send_data_channel_ids: Vec<u16>,
    rdpgfx_dynamic_channel_ids: Vec<u32>,
}

impl WrappedGfxStats {
    const HISTORY_LIMIT: usize = 8;

    fn remember_send_data_channel_id(&mut self, channel_id: u16) {
        Self::push_history(&mut self.last_send_data_channel_ids, channel_id);
    }

    fn remember_rdpgfx_dynamic_channel_id(&mut self, channel_id: u32) {
        Self::push_history(&mut self.rdpgfx_dynamic_channel_ids, channel_id);
    }

    fn push_history<T>(history: &mut Vec<T>, value: T) {
        if history.len() == Self::HISTORY_LIMIT {
            history.remove(0);
        }
        history.push(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrappedGfxStage {
    AwaitingConnectInitial,
    AwaitingConnectResponse,
    AwaitingDrdynvcStaticPayload,
    AwaitingRdpgfxDynamicChannel,
    AwaitingRdpgfxPayload,
    AwaitingDecodedRdpegfx,
    ExtractingRdpegfx,
}

impl WrappedGfxStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingConnectInitial => "awaiting-connect-initial",
            Self::AwaitingConnectResponse => "awaiting-connect-response",
            Self::AwaitingDrdynvcStaticPayload => "awaiting-drdynvc-static-payload",
            Self::AwaitingRdpgfxDynamicChannel => "awaiting-rdpgfx-dynamic-channel",
            Self::AwaitingRdpgfxPayload => "awaiting-rdpgfx-payload",
            Self::AwaitingDecodedRdpegfx => "awaiting-decoded-rdpegfx",
            Self::ExtractingRdpegfx => "extracting-rdpegfx",
        }
    }
}

enum NextFrame {
    Frame(Vec<u8>),
    NeedMoreData,
    InvalidPrefixDropped,
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::rdp::vc::dvc::gfx::{CreateSurfacePdu, PixelFormat, ServerPdu, StartFramePdu, Timestamp};

    use super::RdpgfxServerTap;

    #[test]
    fn split_rdpegfx_payload_splits_concatenated_server_pdus() {
        let start_frame = encode_vec(&ServerPdu::StartFrame(StartFramePdu {
            timestamp: Timestamp {
                milliseconds: 12,
                seconds: 34,
                minutes: 5,
                hours: 1,
            },
            frame_id: 7,
        }))
        .expect("encode start frame");
        let create_surface = encode_vec(&ServerPdu::CreateSurface(CreateSurfacePdu {
            surface_id: 9,
            width: 1280,
            height: 720,
            pixel_format: PixelFormat::ARgb,
        }))
        .expect("encode create surface");

        let mut payload = Vec::new();
        payload.extend_from_slice(&start_frame);
        payload.extend_from_slice(&create_surface);

        let split = RdpgfxServerTap::split_rdpegfx_payload(&payload).expect("split payload");

        assert_eq!(split.len(), 2);
        assert_eq!(split[0], start_frame.as_slice());
        assert_eq!(split[1], create_surface.as_slice());
    }
}
