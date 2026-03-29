use ironrdp_core::{Decode, Encode, EncodeResult, ReadCursor, WriteCursor, impl_as_any};
use ironrdp_dvc::{DrdynvcClient, DvcClientProcessor, DvcEncode, DvcMessage, DvcProcessor};
use ironrdp_pdu::rdp::vc::dvc::gfx::{
    CapabilitiesAdvertisePdu, CapabilitiesV10Flags, CapabilitySet, ClientPdu, FrameAcknowledgePdu, QueueDepth,
    ServerPdu,
};
use ironrdp_pdu::{PduResult, decode_err};

pub const MANUAL_LAB_IRONRDP_RDPGFX_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ManualLabIronRdpRdpgfxProbeSummary {
    pub capabilities_advertise_count: u32,
    pub capabilities_confirm_count: u32,
    pub reset_graphics_count: u32,
    pub start_frame_count: u32,
    pub end_frame_count: u32,
    pub wire_to_surface1_count: u32,
    pub wire_to_surface2_count: u32,
    pub frame_ack_count: u32,
}

pub struct ManualLabIronRdpRdpgfxProbe {
    summary: ManualLabIronRdpRdpgfxProbeSummary,
    total_frames_decoded: u32,
}

impl ManualLabIronRdpRdpgfxProbe {
    #[must_use]
    pub fn new() -> Self {
        Self {
            summary: ManualLabIronRdpRdpgfxProbeSummary::default(),
            total_frames_decoded: 0,
        }
    }

    #[must_use]
    pub fn summary(&self) -> ManualLabIronRdpRdpgfxProbeSummary {
        self.summary
    }

    #[must_use]
    pub fn protocol_marker_detected(&self) -> bool {
        self.summary.capabilities_confirm_count > 0
            || self.summary.reset_graphics_count > 0
            || self.summary.start_frame_count > 0
            || self.summary.end_frame_count > 0
            || self.summary.wire_to_surface1_count > 0
            || self.summary.wire_to_surface2_count > 0
    }

    fn capabilities_advertise_message() -> ManualLabIronRdpRdpgfxMessage {
        ManualLabIronRdpRdpgfxMessage(ClientPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(vec![
            CapabilitySet::V10 {
                flags: CapabilitiesV10Flags::empty(),
            },
        ])))
    }

    fn frame_acknowledge_message(&mut self, frame_id: u32) -> ManualLabIronRdpRdpgfxMessage {
        self.total_frames_decoded = self.total_frames_decoded.saturating_add(1);
        self.summary.frame_ack_count = self.summary.frame_ack_count.saturating_add(1);

        ManualLabIronRdpRdpgfxMessage(ClientPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::AvailableBytes(65_536),
            frame_id,
            total_frames_decoded: self.total_frames_decoded,
        }))
    }
}

impl Default for ManualLabIronRdpRdpgfxProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl_as_any!(ManualLabIronRdpRdpgfxProbe);

impl DvcProcessor for ManualLabIronRdpRdpgfxProbe {
    fn channel_name(&self) -> &str {
        MANUAL_LAB_IRONRDP_RDPGFX_CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.summary.capabilities_advertise_count = self.summary.capabilities_advertise_count.saturating_add(1);
        Ok(vec![Box::new(Self::capabilities_advertise_message())])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let server_pdu = ServerPdu::decode(&mut ReadCursor::new(payload)).map_err(|error| decode_err!(error))?;

        match server_pdu {
            ServerPdu::CapabilitiesConfirm(_) => {
                self.summary.capabilities_confirm_count = self.summary.capabilities_confirm_count.saturating_add(1);
                Ok(Vec::new())
            }
            ServerPdu::ResetGraphics(_) => {
                self.summary.reset_graphics_count = self.summary.reset_graphics_count.saturating_add(1);
                Ok(Vec::new())
            }
            ServerPdu::StartFrame(_) => {
                self.summary.start_frame_count = self.summary.start_frame_count.saturating_add(1);
                Ok(Vec::new())
            }
            ServerPdu::EndFrame(end_frame) => {
                self.summary.end_frame_count = self.summary.end_frame_count.saturating_add(1);
                Ok(vec![Box::new(self.frame_acknowledge_message(end_frame.frame_id))])
            }
            ServerPdu::WireToSurface1(_) => {
                self.summary.wire_to_surface1_count = self.summary.wire_to_surface1_count.saturating_add(1);
                Ok(Vec::new())
            }
            ServerPdu::WireToSurface2(_) => {
                self.summary.wire_to_surface2_count = self.summary.wire_to_surface2_count.saturating_add(1);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }
}

impl DvcClientProcessor for ManualLabIronRdpRdpgfxProbe {}

#[must_use]
pub fn manual_lab_ironrdp_rdpgfx_dvc_client() -> DrdynvcClient {
    DrdynvcClient::new().with_dynamic_channel(ManualLabIronRdpRdpgfxProbe::new())
}

struct ManualLabIronRdpRdpgfxMessage(ClientPdu);

impl Encode for ManualLabIronRdpRdpgfxMessage {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.0.encode(dst)
    }

    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl DvcEncode for ManualLabIronRdpRdpgfxMessage {}
