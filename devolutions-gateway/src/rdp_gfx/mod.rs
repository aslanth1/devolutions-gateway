//! RDPEGFX overlay and steganography filter
//!
//! This crate implements visual manipulation of RDP graphics:
//! - Low-contrast overlays (microtext, single-frame flashes)
//! - Steganographic embedding (LSB manipulation)
//! - Framebuffer maintenance for compositing

pub mod avc;
pub mod clearcodec;
pub mod framebuffer;
mod nsc;
pub mod overlay;
pub mod protocol;
pub mod rfx;
pub mod stego;

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use avc::SurfaceAvcDecoders;
use bytes::BytesMut;
use clearcodec::SurfaceClearCodecDecoders;
pub use framebuffer::Framebuffer;
use ironrdp_graphics::image_processing::{ImageRegion, ImageRegionMut, PixelFormat as GraphicsPixelFormat};
use ironrdp_graphics::rdp6::BitmapStreamDecoder;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::vc::dvc::gfx::{Codec1Type, Codec2Type, PixelFormat, Point};
pub use protocol::{GfxPduHeader, GfxPduType, RDPEGFX_HEADER_LEN, parse_gfx_pdu_header};
use protocol::{ParsedGfxPdu, parse_gfx_pdu};
use rfx::SurfaceRemoteFxDecoders;
use tracing::{debug, info, warn};

const ALPHA_CODEC_SIGNATURE: u16 = 0x414C;

/// Configuration for GFX filter
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct GfxConfig {
    /// Enable visual overlays
    pub overlay: bool,
    /// Enable steganography
    pub stego: bool,
    /// Regions to exclude from overlays (e.g., "password_fields", "taskbar")
    #[serde(default)]
    pub no_overlay_regions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceUpdate {
    pub source: &'static str,
    pub surface_id: u16,
    pub surface_width: u32,
    pub surface_height: u32,
    pub rectangle: InclusiveRectangle,
    pub rgba_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceSnapshot {
    pub surface_id: u16,
    pub width: u32,
    pub height: u32,
    pub rgba_data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CachedSurfaceTile {
    cache_key: u64,
    width: u32,
    height: u32,
    rgba_data: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct GfxWarningSummary {
    wire_to_surface1_unknown_surface_count: u64,
    wire_to_surface2_metadata_unknown_surface_count: u64,
    wire_to_surface2_update_unknown_surface_count: u64,
    delete_encoding_context_unknown_surface_or_context_count: u64,
    surface_to_cache_unknown_surface_count: u64,
    cache_to_surface_unknown_cache_slot_count: u64,
    cache_to_surface_unknown_surface_count: u64,
    wire_to_surface1_update_failed_count: u64,
    wire_to_surface1_decode_skipped_count: u64,
    wire_to_surface2_decode_skipped_count: u64,
    surface_to_cache_capture_skipped_count: u64,
    cache_to_surface_replay_skipped_count: u64,
}

impl GfxWarningSummary {
    fn total_warning_count(self) -> u64 {
        self.wire_to_surface1_unknown_surface_count
            .saturating_add(self.wire_to_surface2_metadata_unknown_surface_count)
            .saturating_add(self.wire_to_surface2_update_unknown_surface_count)
            .saturating_add(self.delete_encoding_context_unknown_surface_or_context_count)
            .saturating_add(self.surface_to_cache_unknown_surface_count)
            .saturating_add(self.cache_to_surface_unknown_cache_slot_count)
            .saturating_add(self.cache_to_surface_unknown_surface_count)
            .saturating_add(self.wire_to_surface1_update_failed_count)
            .saturating_add(self.wire_to_surface1_decode_skipped_count)
            .saturating_add(self.wire_to_surface2_decode_skipped_count)
            .saturating_add(self.surface_to_cache_capture_skipped_count)
            .saturating_add(self.cache_to_surface_replay_skipped_count)
    }
}

/// RDPEGFX filter for visual manipulation
pub struct GfxFilter {
    config: GfxConfig,
    surfaces: HashMap<u16, Framebuffer>,
    surface_cache: HashMap<u16, CachedSurfaceTile>,
    surface_codec_contexts: HashMap<u16, HashSet<u32>>,
    avc_decoders: SurfaceAvcDecoders,
    clearcodec_decoders: SurfaceClearCodecDecoders,
    rfx_decoders: SurfaceRemoteFxDecoders,
    planar_decoder: BitmapStreamDecoder,
    pending_surface_updates: Vec<SurfaceUpdate>,
    session_id: String,
    server_chunk_count: u64,
    rdpegfx_pdu_count: u64,
    surface_update_count: u64,
    warning_summary: GfxWarningSummary,
    warning_summary_emitted: bool,
    parse_miss_log_budget: u8,
    rgba_coverage_log_budget: u8,
}

enum ServerChunkHandling {
    NotGfx,
    PassThrough,
    Rewritten,
}

impl GfxFilter {
    /// Create a new GFX filter
    pub fn new(config: GfxConfig, session_id: String) -> Self {
        info!(
            session_id = %session_id,
            overlay = config.overlay,
            stego = config.stego,
            "GFX filter initialized"
        );

        Self {
            config,
            surfaces: HashMap::new(),
            surface_cache: HashMap::new(),
            surface_codec_contexts: HashMap::new(),
            avc_decoders: SurfaceAvcDecoders::default(),
            clearcodec_decoders: SurfaceClearCodecDecoders::default(),
            rfx_decoders: SurfaceRemoteFxDecoders::default(),
            planar_decoder: BitmapStreamDecoder::default(),
            pending_surface_updates: Vec::new(),
            session_id,
            server_chunk_count: 0,
            rdpegfx_pdu_count: 0,
            surface_update_count: 0,
            warning_summary: GfxWarningSummary::default(),
            warning_summary_emitted: false,
            parse_miss_log_budget: 5,
            rgba_coverage_log_budget: 12,
        }
    }

    pub fn drain_surface_updates(&mut self) -> Vec<SurfaceUpdate> {
        let updates = std::mem::take(&mut self.pending_surface_updates);
        if !updates.is_empty() {
            self.surface_update_count = self
                .surface_update_count
                .saturating_add(u64::try_from(updates.len()).unwrap_or(u64::MAX));
            debug!(
                session_id = %self.session_id,
                update_count = updates.len(),
                "Drained pending RDPEGFX surface updates",
            );
        }
        updates
    }

    pub fn snapshot_surface(&self, surface_id: u16) -> Result<Option<SurfaceSnapshot>> {
        let Some(framebuffer) = self.surfaces.get(&surface_id) else {
            return Ok(None);
        };

        let width = framebuffer.width();
        let height = framebuffer.height();
        let rgba_data = framebuffer.copy_region(0, 0, width, height)?;

        Ok(Some(SurfaceSnapshot {
            surface_id,
            width,
            height,
            rgba_data,
        }))
    }

    pub fn log_summary(&mut self, session_id: uuid::Uuid) {
        let session_id = session_id.to_string();
        let emitted_surface_update_count = self
            .surface_update_count
            .saturating_add(u64::try_from(self.pending_surface_updates.len()).unwrap_or(u64::MAX));
        info!(
            session_id = %session_id,
            server_chunk_count = self.server_chunk_count,
            rdpegfx_pdu_count = self.rdpegfx_pdu_count,
            emitted_surface_update_count,
            pending_surface_update_count = self.pending_surface_updates.len(),
            surface_count = self.surfaces.len(),
            cached_tile_count = self.surface_cache.len(),
            codec_context_surface_count = self.surface_codec_contexts.len(),
            "GFX filter summary"
        );
        self.emit_warning_summary(&session_id);
    }

    fn increment_warning(counter: &mut u64) {
        *counter = counter.saturating_add(1);
    }

    fn emit_warning_summary(&mut self, session_id: &str) {
        if self.warning_summary_emitted {
            return;
        }

        let summary = self.warning_summary;
        info!(
            session_id = %session_id,
            total_warning_count = summary.total_warning_count(),
            wire_to_surface1_unknown_surface_count = summary.wire_to_surface1_unknown_surface_count,
            wire_to_surface2_metadata_unknown_surface_count =
                summary.wire_to_surface2_metadata_unknown_surface_count,
            wire_to_surface2_update_unknown_surface_count = summary.wire_to_surface2_update_unknown_surface_count,
            delete_encoding_context_unknown_surface_or_context_count =
                summary.delete_encoding_context_unknown_surface_or_context_count,
            surface_to_cache_unknown_surface_count = summary.surface_to_cache_unknown_surface_count,
            cache_to_surface_unknown_cache_slot_count = summary.cache_to_surface_unknown_cache_slot_count,
            cache_to_surface_unknown_surface_count = summary.cache_to_surface_unknown_surface_count,
            wire_to_surface1_update_failed_count = summary.wire_to_surface1_update_failed_count,
            wire_to_surface1_decode_skipped_count = summary.wire_to_surface1_decode_skipped_count,
            wire_to_surface2_decode_skipped_count = summary.wire_to_surface2_decode_skipped_count,
            surface_to_cache_capture_skipped_count = summary.surface_to_cache_capture_skipped_count,
            cache_to_surface_replay_skipped_count = summary.cache_to_surface_replay_skipped_count,
            "GFX warning summary"
        );

        self.warning_summary_emitted = true;
    }

    fn queue_surface_update(
        &mut self,
        source: &'static str,
        surface_id: u16,
        surface_width: u32,
        surface_height: u32,
        rectangle: InclusiveRectangle,
        rgba_data: Vec<u8>,
    ) {
        let update_width = u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1;
        let update_height = u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1;
        let update_area = u64::from(update_width) * u64::from(update_height);
        let surface_area = u64::from(surface_width) * u64::from(surface_height);
        let queued_surface_update_index = self
            .surface_update_count
            .saturating_add(u64::try_from(self.pending_surface_updates.len()).unwrap_or(u64::MAX))
            .saturating_add(1);

        if queued_surface_update_index <= 12 || update_area == surface_area || update_area <= 4096 {
            debug!(
                session_id = %self.session_id,
                queued_surface_update_index,
                source,
                surface_id,
                surface_width,
                surface_height,
                rect_left = rectangle.left,
                rect_top = rectangle.top,
                rect_right = rectangle.right,
                rect_bottom = rectangle.bottom,
                update_width,
                update_height,
                update_area,
                surface_area,
                "Queued RDPEGFX surface update",
            );
        }

        self.pending_surface_updates.push(SurfaceUpdate {
            source,
            surface_id,
            surface_width,
            surface_height,
            rectangle,
            rgba_data,
        });
    }

    fn maybe_log_rgba_coverage(
        &mut self,
        label: &'static str,
        surface_id: u16,
        width: u32,
        height: u32,
        rgba_data: &[u8],
    ) {
        if self.rgba_coverage_log_budget == 0 {
            return;
        }

        self.rgba_coverage_log_budget -= 1;

        let total_pixels = rgba_data.len() / 4;
        if total_pixels == 0 {
            return;
        }

        let non_black_pixels = rgba_data
            .chunks_exact(4)
            .filter(|px| px[0] != 0 || px[1] != 0 || px[2] != 0)
            .count();
        let alpha_pixels = rgba_data.chunks_exact(4).filter(|px| px[3] != 0).count();

        debug!(
            session_id = %self.session_id,
            label,
            surface_id,
            width,
            height,
            total_pixels,
            non_black_pixels,
            non_black_ratio = non_black_pixels as f64 / total_pixels as f64,
            alpha_pixels,
            alpha_ratio = alpha_pixels as f64 / total_pixels as f64,
            remaining_rgba_coverage_logs = self.rgba_coverage_log_budget,
            "Observed RGBA coverage for surface content",
        );
    }

    pub fn observe_bare_server_pdu(&mut self, data: &[u8]) -> Result<bool> {
        match self.handle_bare_server_chunk(data, false)? {
            ServerChunkHandling::NotGfx => Ok(false),
            ServerChunkHandling::PassThrough | ServerChunkHandling::Rewritten => Ok(true),
        }
    }

    /// Handle CreateSurface command
    fn handle_create_surface(&mut self, surface_id: u16, width: u32, height: u32) -> Result<()> {
        debug!(
            session_id = %self.session_id,
            surface_id = surface_id,
            width = width,
            height = height,
            "Created surface"
        );

        self.surfaces.insert(surface_id, Framebuffer::new(width, height)?);
        Ok(())
    }

    /// Handle DeleteSurface command
    fn handle_delete_surface(&mut self, surface_id: u16) -> Result<()> {
        if self.surfaces.remove(&surface_id).is_some() {
            self.avc_decoders.remove_surface(surface_id);
            self.clearcodec_decoders.remove_surface(surface_id);
            self.rfx_decoders.remove_surface(surface_id);
            self.surface_codec_contexts.remove(&surface_id);
            debug!(
                session_id = %self.session_id,
                surface_id = surface_id,
                "Deleted surface"
            );
        }

        Ok(())
    }

    fn handle_wire_to_surface_2_metadata(
        &mut self,
        surface_id: u16,
        codec_id: Codec2Type,
        codec_context_id: u32,
        pixel_format: PixelFormat,
        bitmap_data_len: usize,
    ) {
        if !self.surfaces.contains_key(&surface_id) {
            Self::increment_warning(&mut self.warning_summary.wire_to_surface2_metadata_unknown_surface_count);
            warn!(
                session_id = %self.session_id,
                surface_id,
                codec = ?codec_id,
                codec_context_id,
                "WireToSurface2 update for unknown surface"
            );
            return;
        }

        let active_context_count = {
            let contexts = self.surface_codec_contexts.entry(surface_id).or_default();
            contexts.insert(codec_context_id);
            contexts.len()
        };

        debug!(
            session_id = %self.session_id,
            surface_id,
            codec = ?codec_id,
            codec_context_id,
            pixel_format = ?pixel_format,
            bitmap_data_len,
            active_context_count,
            "Observed WireToSurface2 metadata"
        );
    }

    fn handle_delete_encoding_context(&mut self, surface_id: u16, codec_context_id: u32) {
        self.rfx_decoders.remove_context(surface_id, codec_context_id);
        let Some(contexts) = self.surface_codec_contexts.get_mut(&surface_id) else {
            Self::increment_warning(
                &mut self
                    .warning_summary
                    .delete_encoding_context_unknown_surface_or_context_count,
            );
            debug!(
                session_id = %self.session_id,
                surface_id,
                codec_context_id,
                "DeleteEncodingContext for unknown surface/context set"
            );
            return;
        };

        let removed = contexts.remove(&codec_context_id);
        let remaining_context_count = contexts.len();
        if contexts.is_empty() {
            self.surface_codec_contexts.remove(&surface_id);
        }

        debug!(
            session_id = %self.session_id,
            surface_id,
            codec_context_id,
            removed,
            remaining_context_count,
            "Observed DeleteEncodingContext metadata"
        );
    }

    fn handle_surface_to_cache(
        &mut self,
        surface_id: u16,
        cache_key: u64,
        cache_slot: u16,
        source_rectangle: &InclusiveRectangle,
    ) -> Result<()> {
        let (effective_rectangle, width, height, rgba_data) = {
            let Some(framebuffer) = self.surfaces.get(&surface_id) else {
                Self::increment_warning(&mut self.warning_summary.surface_to_cache_unknown_surface_count);
                warn!(
                    session_id = %self.session_id,
                    surface_id,
                    cache_slot,
                    cache_key,
                    "SurfaceToCache update for unknown surface"
                );
                return Ok(());
            };

            copy_surface_to_cache_region(framebuffer, source_rectangle)?
        };

        if effective_rectangle != *source_rectangle {
            debug!(
                session_id = %self.session_id,
                surface_id,
                cache_slot,
                cache_key,
                original_rect_left = source_rectangle.left,
                original_rect_top = source_rectangle.top,
                original_rect_right = source_rectangle.right,
                original_rect_bottom = source_rectangle.bottom,
                effective_rect_left = effective_rectangle.left,
                effective_rect_top = effective_rectangle.top,
                effective_rect_right = effective_rectangle.right,
                effective_rect_bottom = effective_rectangle.bottom,
                width,
                height,
                "Applied SurfaceToCache rectangle fallback"
            );
        }

        self.maybe_log_rgba_coverage("surface_to_cache", surface_id, width, height, &rgba_data);

        self.surface_cache.insert(
            cache_slot,
            CachedSurfaceTile {
                cache_key,
                width,
                height,
                rgba_data,
            },
        );

        debug!(
            session_id = %self.session_id,
            surface_id,
            cache_slot,
            cache_key,
            rect_left = effective_rectangle.left,
            rect_top = effective_rectangle.top,
            rect_right = effective_rectangle.right,
            rect_bottom = effective_rectangle.bottom,
            width,
            height,
            "Cached RDPEGFX surface region"
        );

        Ok(())
    }

    fn handle_cache_to_surface(
        &mut self,
        cache_slot: u16,
        surface_id: u16,
        destination_points: &[Point],
    ) -> Result<()> {
        let Some(cached_tile) = self.surface_cache.get(&cache_slot).cloned() else {
            Self::increment_warning(&mut self.warning_summary.cache_to_surface_unknown_cache_slot_count);
            warn!(
                session_id = %self.session_id,
                surface_id,
                cache_slot,
                "CacheToSurface update for unknown cache slot"
            );
            return Ok(());
        };

        if !self.surfaces.contains_key(&surface_id) {
            Self::increment_warning(&mut self.warning_summary.cache_to_surface_unknown_surface_count);
            warn!(
                session_id = %self.session_id,
                surface_id,
                cache_slot,
                "CacheToSurface update for unknown surface"
            );
            return Ok(());
        }

        for point in destination_points {
            let (surface_width, surface_height) = {
                let framebuffer = self.surfaces.get(&surface_id).expect("surface checked above");
                (framebuffer.width(), framebuffer.height())
            };
            let Some((clipped_width, clipped_height)) = clipped_region_size(
                surface_width,
                surface_height,
                u32::from(point.x),
                u32::from(point.y),
                cached_tile.width,
                cached_tile.height,
            ) else {
                debug!(
                    session_id = %self.session_id,
                    surface_id,
                    cache_slot,
                    cache_key = cached_tile.cache_key,
                    destination_x = point.x,
                    destination_y = point.y,
                    surface_width,
                    surface_height,
                    tile_width = cached_tile.width,
                    tile_height = cached_tile.height,
                    "CacheToSurface destination lies completely outside the framebuffer"
                );
                continue;
            };
            let rectangle = rectangle_from_origin_size(point.x, point.y, clipped_width, clipped_height)?;
            let rgba_data =
                crop_rgba_top_left_region(&cached_tile.rgba_data, cached_tile.width, clipped_width, clipped_height)?;
            self.maybe_log_rgba_coverage(
                "cache_to_surface",
                surface_id,
                clipped_width,
                clipped_height,
                &rgba_data,
            );
            {
                let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                framebuffer.update_region(
                    u32::from(point.x),
                    u32::from(point.y),
                    clipped_width,
                    clipped_height,
                    &rgba_data,
                )?;
            }

            self.queue_surface_update(
                "cache_to_surface",
                surface_id,
                surface_width,
                surface_height,
                rectangle,
                rgba_data,
            );
        }

        debug!(
            session_id = %self.session_id,
            surface_id,
            cache_slot,
            cache_key = cached_tile.cache_key,
            destination_count = destination_points.len(),
            tile_width = cached_tile.width,
            tile_height = cached_tile.height,
            "Replayed RDPEGFX cached surface region"
        );

        Ok(())
    }

    fn handle_evict_cache_entry(&mut self, cache_slot: u16) {
        let removed = self.surface_cache.remove(&cache_slot).is_some();
        debug!(
            session_id = %self.session_id,
            cache_slot,
            removed,
            "Evicted RDPEGFX cache slot"
        );
    }

    /// Process WireToSurface bitmap data
    fn process_wire_to_surface(
        &self,
        surface_id: u16,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if self.surfaces.contains_key(&surface_id) {
            // TODO: Decode bitmap, update framebuffer, apply transforms

            debug!(
                session_id = %self.session_id,
                surface_id = surface_id,
                x = x,
                y = y,
                width = width,
                height = height,
                data_len = data.len(),
                "Processing WireToSurface"
            );

            // For now, return data unmodified (pass-through)
            // Future: decode, apply overlay/stego, re-encode
            Ok(data.to_vec())
        } else {
            warn!(
                session_id = %self.session_id,
                surface_id = surface_id,
                "WireToSurface for unknown surface"
            );
            Ok(data.to_vec())
        }
    }

    fn handle_bare_server_chunk(&mut self, data: &[u8], allow_wire_rewrite: bool) -> Result<ServerChunkHandling> {
        let Some(pdu) = parse_gfx_pdu(data) else {
            return Ok(ServerChunkHandling::NotGfx);
        };

        self.rdpegfx_pdu_count = self.rdpegfx_pdu_count.saturating_add(1);
        debug!(
            session_id = %self.session_id,
            pdu_type = ?pdu.pdu_type(),
            data_len = data.len(),
            "Intercepted RDPEGFX PDU"
        );

        match pdu {
            ParsedGfxPdu::CreateSurface {
                surface_id,
                width,
                height,
                ..
            } => {
                if let Err(e) = self.handle_create_surface(surface_id, u32::from(width), u32::from(height)) {
                    warn!(error = ?e, "Failed to create surface");
                }
            }

            ParsedGfxPdu::DeleteSurface { surface_id, .. } => {
                if let Err(e) = self.handle_delete_surface(surface_id) {
                    warn!(error = ?e, "Failed to delete surface");
                }
            }

            ParsedGfxPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                destination_rectangle,
                bitmap_data,
                ..
            } => {
                let x = destination_rectangle.left;
                let y = destination_rectangle.top;
                let width = destination_rectangle
                    .right
                    .saturating_sub(destination_rectangle.left)
                    .saturating_add(1);
                let height = destination_rectangle
                    .bottom
                    .saturating_sub(destination_rectangle.top)
                    .saturating_add(1);
                if let Err(e) = self.update_surface_from_wire_to_surface_1(
                    surface_id,
                    codec_id,
                    pixel_format,
                    destination_rectangle,
                    &bitmap_data,
                ) {
                    Self::increment_warning(&mut self.warning_summary.wire_to_surface1_update_failed_count);
                    warn!(error = ?e, "Failed to update framebuffer from WireToSurface1");
                }
                if allow_wire_rewrite && (self.config.overlay || self.config.stego) {
                    match self.process_wire_to_surface(surface_id, x, y, width, height, &bitmap_data) {
                        Ok(modified_data) => {
                            let mut result = BytesMut::with_capacity(20 + modified_data.len());
                            result.extend_from_slice(&data[..20]);
                            result.extend_from_slice(&modified_data);

                            let _ = result.freeze();
                            return Ok(ServerChunkHandling::Rewritten);
                        }
                        Err(e) => {
                            warn!(error = ?e, "Failed to process WireToSurface, passing through");
                        }
                    }
                }
            }
            ParsedGfxPdu::WireToSurface2 {
                surface_id,
                codec_id,
                codec_context_id,
                pixel_format,
                bitmap_data,
                ..
            } => {
                self.handle_wire_to_surface_2_metadata(
                    surface_id,
                    codec_id,
                    codec_context_id,
                    pixel_format,
                    bitmap_data.len(),
                );
                if let Err(error) =
                    self.update_surface_from_wire_to_surface_2(surface_id, codec_id, codec_context_id, &bitmap_data)
                {
                    Self::increment_warning(&mut self.warning_summary.wire_to_surface2_decode_skipped_count);
                    debug!(
                        session_id = %self.session_id,
                        surface_id,
                        codec = ?codec_id,
                        codec_context_id,
                        error = ?error,
                        "WireToSurface2 framebuffer decode skipped"
                    );
                }
            }
            ParsedGfxPdu::DeleteEncodingContext {
                surface_id,
                codec_context_id,
                ..
            } => {
                self.handle_delete_encoding_context(surface_id, codec_context_id);
            }
            ParsedGfxPdu::SurfaceToCache {
                surface_id,
                cache_key,
                cache_slot,
                source_rectangle,
                ..
            } => {
                if let Err(error) = self.handle_surface_to_cache(surface_id, cache_key, cache_slot, &source_rectangle) {
                    Self::increment_warning(&mut self.warning_summary.surface_to_cache_capture_skipped_count);
                    debug!(
                        session_id = %self.session_id,
                        surface_id,
                        cache_slot,
                        cache_key,
                        source_rectangle = ?source_rectangle,
                        error = ?error,
                        "SurfaceToCache framebuffer capture skipped"
                    );
                }
            }
            ParsedGfxPdu::CacheToSurface {
                cache_slot,
                surface_id,
                destination_points,
                ..
            } => {
                if let Err(error) = self.handle_cache_to_surface(cache_slot, surface_id, &destination_points) {
                    Self::increment_warning(&mut self.warning_summary.cache_to_surface_replay_skipped_count);
                    debug!(
                        session_id = %self.session_id,
                        surface_id,
                        cache_slot,
                        destination_count = destination_points.len(),
                        error = ?error,
                        "CacheToSurface framebuffer replay skipped"
                    );
                }
            }
            ParsedGfxPdu::EvictCacheEntry { cache_slot, .. } => {
                self.handle_evict_cache_entry(cache_slot);
            }

            ParsedGfxPdu::Unsupported { .. } => {}
        }

        Ok(ServerChunkHandling::PassThrough)
    }

    fn log_server_chunk_parse_miss(&mut self, data: &[u8]) {
        if self.parse_miss_log_budget == 0 {
            return;
        }

        self.parse_miss_log_budget -= 1;

        let classify_result = match ironrdp_pdu::find_size(data) {
            Ok(Some(info)) => format!("action={:?}, length={}", info.action, info.length),
            Ok(None) => "incomplete-or-unknown-rdp-frame".to_owned(),
            Err(error) => format!("classification-error={error}"),
        };

        let prefix_len = data.len().min(16);
        let prefix = data[..prefix_len]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");

        debug!(
            session_id = %self.session_id,
            data_len = data.len(),
            classify_result,
            prefix_hex = %prefix,
            remaining_parse_miss_logs = self.parse_miss_log_budget,
            "Server chunk was not a bare RDPEGFX PDU",
        );
    }

    fn update_surface_from_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        codec_id: Codec1Type,
        pixel_format: PixelFormat,
        destination_rectangle: InclusiveRectangle,
        bitmap_data: &[u8],
    ) -> Result<()> {
        if !self.surfaces.contains_key(&surface_id) {
            Self::increment_warning(&mut self.warning_summary.wire_to_surface1_unknown_surface_count);
            warn!(
                session_id = %self.session_id,
                surface_id = surface_id,
                "WireToSurface1 update for unknown surface"
            );
            return Ok(());
        }

        match codec_id {
            Codec1Type::Uncompressed => {
                let original_rectangle = destination_rectangle;
                let rectangle =
                    normalized_uncompressed_wire_to_surface_1_rectangle(original_rectangle.clone(), bitmap_data.len())?;
                if rectangle != original_rectangle {
                    debug!(
                        session_id = %self.session_id,
                        surface_id,
                        codec_id = ?codec_id,
                        bitmap_data_len = bitmap_data.len(),
                        original_rect_left = original_rectangle.left,
                        original_rect_top = original_rectangle.top,
                        original_rect_right = original_rectangle.right,
                        original_rect_bottom = original_rectangle.bottom,
                        effective_rect_left = rectangle.left,
                        effective_rect_top = rectangle.top,
                        effective_rect_right = rectangle.right,
                        effective_rect_bottom = rectangle.bottom,
                        "Applied WireToSurface1 rectangle fallback"
                    );
                }
                let rgba_data = decode_uncompressed_wire_to_surface_1(pixel_format, &rectangle, bitmap_data)?;
                let (surface_width, surface_height) = {
                    let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                    let surface_width = framebuffer.width();
                    let surface_height = framebuffer.height();
                    framebuffer.update_region(
                        u32::from(rectangle.left),
                        u32::from(rectangle.top),
                        u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                        u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                        &rgba_data,
                    )?;
                    (surface_width, surface_height)
                };
                self.queue_surface_update(
                    "wire_to_surface1_uncompressed",
                    surface_id,
                    surface_width,
                    surface_height,
                    rectangle,
                    rgba_data,
                );
            }
            Codec1Type::Planar => {
                let rectangle = destination_rectangle;
                let rgba_data = decode_planar_wire_to_surface_1(&mut self.planar_decoder, &rectangle, bitmap_data)?;
                let (surface_width, surface_height) = {
                    let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                    let surface_width = framebuffer.width();
                    let surface_height = framebuffer.height();
                    framebuffer.update_region(
                        u32::from(rectangle.left),
                        u32::from(rectangle.top),
                        u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                        u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                        &rgba_data,
                    )?;
                    (surface_width, surface_height)
                };
                self.queue_surface_update(
                    "wire_to_surface1_planar",
                    surface_id,
                    surface_width,
                    surface_height,
                    rectangle,
                    rgba_data,
                );
            }
            Codec1Type::Alpha => {
                let rectangle = destination_rectangle;
                let alpha_data = decode_alpha_wire_to_surface_1(&rectangle, bitmap_data)?;
                let width = u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1;
                let height = u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1;
                let (surface_width, surface_height, rgba_data) = {
                    let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                    framebuffer.update_alpha_region(
                        u32::from(rectangle.left),
                        u32::from(rectangle.top),
                        width,
                        height,
                        &alpha_data,
                    )?;
                    let rgba_data =
                        framebuffer.copy_region(u32::from(rectangle.left), u32::from(rectangle.top), width, height)?;
                    (framebuffer.width(), framebuffer.height(), rgba_data)
                };
                self.queue_surface_update(
                    "wire_to_surface1_alpha",
                    surface_id,
                    surface_width,
                    surface_height,
                    rectangle,
                    rgba_data,
                );
            }
            Codec1Type::ClearCodec => {
                match self
                    .clearcodec_decoders
                    .decode_wire_to_surface_1(surface_id, &destination_rectangle, bitmap_data)
                {
                    Ok(decoded_regions) => {
                        for region in decoded_regions {
                            let rectangle = region.rectangle;
                            let (surface_width, surface_height) = {
                                let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                                let surface_width = framebuffer.width();
                                let surface_height = framebuffer.height();
                                framebuffer.update_region(
                                    u32::from(rectangle.left),
                                    u32::from(rectangle.top),
                                    u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                                    u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                                    &region.rgba_data,
                                )?;
                                (surface_width, surface_height)
                            };
                            self.queue_surface_update(
                                "wire_to_surface1_clearcodec",
                                surface_id,
                                surface_width,
                                surface_height,
                                rectangle,
                                region.rgba_data,
                            );
                        }
                    }
                    Err(error) => {
                        Self::increment_warning(&mut self.warning_summary.wire_to_surface1_decode_skipped_count);
                        debug!(
                            session_id = %self.session_id,
                            surface_id = surface_id,
                            codec = ?codec_id,
                            destination_rectangle = ?destination_rectangle,
                            error = ?error,
                            "WireToSurface1 framebuffer decode skipped"
                        );
                    }
                }
            }
            Codec1Type::RemoteFx => {
                let (surface_width, surface_height) = {
                    let framebuffer = self.surfaces.get(&surface_id).expect("surface checked above");
                    (
                        u16::try_from(framebuffer.width()).context("surface width exceeds u16 for RFX decode")?,
                        u16::try_from(framebuffer.height()).context("surface height exceeds u16 for RFX decode")?,
                    )
                };

                match self.rfx_decoders.decode_wire_to_surface_1(
                    surface_id,
                    surface_width,
                    surface_height,
                    &destination_rectangle,
                    bitmap_data,
                ) {
                    Ok(decoded_regions) => {
                        for region in decoded_regions {
                            let rectangle = region.rectangle;
                            let (surface_width, surface_height) = {
                                let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                                let surface_width = framebuffer.width();
                                let surface_height = framebuffer.height();
                                framebuffer.update_region(
                                    u32::from(rectangle.left),
                                    u32::from(rectangle.top),
                                    u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                                    u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                                    &region.rgba_data,
                                )?;
                                (surface_width, surface_height)
                            };
                            self.queue_surface_update(
                                "wire_to_surface1_remotefx",
                                surface_id,
                                surface_width,
                                surface_height,
                                rectangle,
                                region.rgba_data,
                            );
                        }
                    }
                    Err(error) => {
                        Self::increment_warning(&mut self.warning_summary.wire_to_surface1_decode_skipped_count);
                        debug!(
                            session_id = %self.session_id,
                            surface_id = surface_id,
                            codec = ?codec_id,
                            destination_rectangle = ?destination_rectangle,
                            error = ?error,
                            "WireToSurface1 framebuffer decode skipped"
                        );
                    }
                }
            }
            Codec1Type::Avc420 | Codec1Type::Avc444 | Codec1Type::Avc444v2 => {
                match self
                    .avc_decoders
                    .decode_wire_to_surface_1(surface_id, codec_id, bitmap_data)
                {
                    Ok(decoded_regions) => {
                        for region in decoded_regions {
                            let rectangle = region.rectangle;
                            let (surface_width, surface_height) = {
                                let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                                let surface_width = framebuffer.width();
                                let surface_height = framebuffer.height();
                                framebuffer.update_region(
                                    u32::from(rectangle.left),
                                    u32::from(rectangle.top),
                                    u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                                    u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                                    &region.rgba_data,
                                )?;
                                (surface_width, surface_height)
                            };
                            self.queue_surface_update(
                                "wire_to_surface1_avc",
                                surface_id,
                                surface_width,
                                surface_height,
                                rectangle,
                                region.rgba_data,
                            );
                        }
                    }
                    Err(error) => {
                        Self::increment_warning(&mut self.warning_summary.wire_to_surface1_decode_skipped_count);
                        debug!(
                            session_id = %self.session_id,
                            surface_id = surface_id,
                            codec = ?codec_id,
                            destination_rectangle = ?destination_rectangle,
                            error = ?error,
                            "WireToSurface1 framebuffer decode skipped"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn update_surface_from_wire_to_surface_2(
        &mut self,
        surface_id: u16,
        codec_id: Codec2Type,
        codec_context_id: u32,
        bitmap_data: &[u8],
    ) -> Result<()> {
        if !self.surfaces.contains_key(&surface_id) {
            Self::increment_warning(&mut self.warning_summary.wire_to_surface2_update_unknown_surface_count);
            warn!(
                session_id = %self.session_id,
                surface_id = surface_id,
                "WireToSurface2 update for unknown surface"
            );
            return Ok(());
        }

        match codec_id {
            Codec2Type::RemoteFxProgressive => {
                let (surface_width, surface_height) = {
                    let framebuffer = self.surfaces.get(&surface_id).expect("surface checked above");
                    (
                        u16::try_from(framebuffer.width()).context("surface width exceeds u16 for RFX decode")?,
                        u16::try_from(framebuffer.height()).context("surface height exceeds u16 for RFX decode")?,
                    )
                };

                for region in self.rfx_decoders.decode_wire_to_surface_2(
                    surface_id,
                    codec_context_id,
                    surface_width,
                    surface_height,
                    bitmap_data,
                )? {
                    let rectangle = region.rectangle;
                    let (surface_width, surface_height) = {
                        let framebuffer = self.surfaces.get_mut(&surface_id).expect("surface checked above");
                        let surface_width = framebuffer.width();
                        let surface_height = framebuffer.height();
                        framebuffer.update_region(
                            u32::from(rectangle.left),
                            u32::from(rectangle.top),
                            u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
                            u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
                            &region.rgba_data,
                        )?;
                        (surface_width, surface_height)
                    };
                    self.queue_surface_update(
                        "wire_to_surface2_remotefx_progressive",
                        surface_id,
                        surface_width,
                        surface_height,
                        rectangle,
                        region.rgba_data,
                    );
                }
            }
        }

        Ok(())
    }
}

impl GfxFilter {
    pub fn observe_server_to_client_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.server_chunk_count = self.server_chunk_count.saturating_add(1);

        match self.handle_bare_server_chunk(data, false)? {
            ServerChunkHandling::NotGfx => {
                self.log_server_chunk_parse_miss(data);
            }
            ServerChunkHandling::PassThrough | ServerChunkHandling::Rewritten => {}
        }

        Ok(())
    }
}

impl Drop for GfxFilter {
    fn drop(&mut self) {
        if self.server_chunk_count == 0 {
            return;
        }

        let session_id = self.session_id.as_str();
        let server_chunk_count = self.server_chunk_count;
        let rdpegfx_pdu_count = self.rdpegfx_pdu_count;
        let surface_update_count = self.surface_update_count;

        if rdpegfx_pdu_count == 0 {
            warn!(
                session_id = %session_id,
                server_chunk_count,
                surface_update_count,
                "GFX filter saw server traffic but no bare RDPEGFX PDUs",
            );
        } else {
            info!(
                session_id = %session_id,
                server_chunk_count,
                rdpegfx_pdu_count,
                surface_update_count,
                "GFX filter session summary",
            );
        }

        let session_id = self.session_id.clone();
        self.emit_warning_summary(&session_id);
    }
}

fn rectangle_from_origin_size(left: u16, top: u16, width: u32, height: u32) -> Result<InclusiveRectangle> {
    let right = u32::from(left)
        .checked_add(width)
        .and_then(|value| value.checked_sub(1))
        .context("cache replay rectangle right overflow")?;
    let bottom = u32::from(top)
        .checked_add(height)
        .and_then(|value| value.checked_sub(1))
        .context("cache replay rectangle bottom overflow")?;

    Ok(InclusiveRectangle {
        left,
        top,
        right: u16::try_from(right).context("cache replay rectangle right exceeds u16")?,
        bottom: u16::try_from(bottom).context("cache replay rectangle bottom exceeds u16")?,
    })
}

fn clipped_region_size(
    surface_width: u32,
    surface_height: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> Option<(u32, u32)> {
    if x >= surface_width || y >= surface_height {
        return None;
    }

    let remaining_width = surface_width.saturating_sub(x);
    let remaining_height = surface_height.saturating_sub(y);
    let clipped_width = width.min(remaining_width);
    let clipped_height = height.min(remaining_height);

    if clipped_width == 0 || clipped_height == 0 {
        None
    } else {
        Some((clipped_width, clipped_height))
    }
}

fn crop_rgba_top_left_region(source_data: &[u8], source_width: u32, width: u32, height: u32) -> Result<Vec<u8>> {
    let source_row_bytes = checked_rgba_row_bytes(source_width)?;
    let clipped_row_bytes = checked_rgba_row_bytes(width)?;
    let output_len = checked_rgba_buffer_len(width, height)?;
    let mut out = vec![0; output_len];

    for row in 0..usize::try_from(height).context("clipped height exceeds usize")? {
        let source_offset = row
            .checked_mul(source_row_bytes)
            .context("source RGBA row offset overflow")?;
        let dest_offset = row
            .checked_mul(clipped_row_bytes)
            .context("destination RGBA row offset overflow")?;
        let source_end = source_offset
            .checked_add(clipped_row_bytes)
            .context("source RGBA slice end overflow")?;
        let dest_end = dest_offset
            .checked_add(clipped_row_bytes)
            .context("destination RGBA slice end overflow")?;
        if source_end > source_data.len() {
            anyhow::bail!(
                "Cached RGBA tile too small for clipped crop: {} bytes available, need at least {}",
                source_data.len(),
                source_end
            );
        }
        out[dest_offset..dest_end].copy_from_slice(&source_data[source_offset..source_end]);
    }

    Ok(out)
}

fn checked_rgba_row_bytes(width: u32) -> Result<usize> {
    usize::try_from(
        u64::from(width)
            .checked_mul(4)
            .context("RGBA row byte count overflow")?,
    )
    .context("RGBA row byte count exceeds usize")
}

fn checked_rgba_buffer_len(width: u32, height: u32) -> Result<usize> {
    usize::try_from(
        u64::from(width)
            .checked_mul(u64::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .context("RGBA buffer length overflow")?,
    )
    .context("RGBA buffer length exceeds usize")
}

fn inclusive_rectangle_dimensions(rectangle: &InclusiveRectangle) -> (u32, u32) {
    (
        u32::from(rectangle.right.saturating_sub(rectangle.left)) + 1,
        u32::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1,
    )
}

fn maybe_shrink_inclusive_rectangle(rectangle: &InclusiveRectangle) -> Option<InclusiveRectangle> {
    if rectangle.right > rectangle.left && rectangle.bottom > rectangle.top {
        Some(InclusiveRectangle {
            left: rectangle.left,
            top: rectangle.top,
            right: rectangle.right - 1,
            bottom: rectangle.bottom - 1,
        })
    } else {
        None
    }
}

fn expected_uncompressed_wire_to_surface_1_len(rectangle: &InclusiveRectangle) -> Result<usize> {
    let (width, height) = inclusive_rectangle_dimensions(rectangle);

    checked_rgba_buffer_len(width, height).context("compute expected WireToSurface1 byte count")
}

fn normalized_uncompressed_wire_to_surface_1_rectangle(
    destination_rectangle: InclusiveRectangle,
    bitmap_data_len: usize,
) -> Result<InclusiveRectangle> {
    let expected_len = expected_uncompressed_wire_to_surface_1_len(&destination_rectangle)?;
    if bitmap_data_len == expected_len {
        return Ok(destination_rectangle);
    }

    let Some(shrunk_rectangle) = maybe_shrink_inclusive_rectangle(&destination_rectangle) else {
        anyhow::bail!(
            "uncompressed WireToSurface1 data size mismatch: got {} bytes, expected {}",
            bitmap_data_len,
            expected_len
        );
    };

    let shrunk_expected_len = expected_uncompressed_wire_to_surface_1_len(&shrunk_rectangle)?;
    if bitmap_data_len == shrunk_expected_len {
        return Ok(shrunk_rectangle);
    }

    anyhow::bail!(
        "uncompressed WireToSurface1 data size mismatch: got {} bytes, expected {}",
        bitmap_data_len,
        expected_len
    );
}

fn copy_surface_to_cache_region(
    framebuffer: &Framebuffer,
    source_rectangle: &InclusiveRectangle,
) -> Result<(InclusiveRectangle, u32, u32, Vec<u8>)> {
    let (width, height) = inclusive_rectangle_dimensions(source_rectangle);
    match framebuffer.copy_region(
        u32::from(source_rectangle.left),
        u32::from(source_rectangle.top),
        width,
        height,
    ) {
        Ok(rgba_data) => Ok((source_rectangle.clone(), width, height, rgba_data)),
        Err(error) => {
            let Some(shrunk_rectangle) = maybe_shrink_inclusive_rectangle(source_rectangle) else {
                return Err(error);
            };
            let (shrunk_width, shrunk_height) = inclusive_rectangle_dimensions(&shrunk_rectangle);
            let rgba_data = framebuffer.copy_region(
                u32::from(shrunk_rectangle.left),
                u32::from(shrunk_rectangle.top),
                shrunk_width,
                shrunk_height,
            )?;
            Ok((shrunk_rectangle, shrunk_width, shrunk_height, rgba_data))
        }
    }
}

fn decode_uncompressed_wire_to_surface_1(
    pixel_format: PixelFormat,
    destination_rectangle: &InclusiveRectangle,
    bitmap_data: &[u8],
) -> Result<Vec<u8>> {
    let (width, height) = inclusive_rectangle_dimensions(destination_rectangle);
    let byte_len = expected_uncompressed_wire_to_surface_1_len(destination_rectangle)?;

    if bitmap_data.len() != byte_len {
        anyhow::bail!(
            "uncompressed WireToSurface1 data size mismatch: got {} bytes, expected {}",
            bitmap_data.len(),
            byte_len
        );
    }

    let src_pixel_format = match pixel_format {
        PixelFormat::ARgb => GraphicsPixelFormat::ARgb32,
        PixelFormat::XRgb => GraphicsPixelFormat::XRgb32,
    };

    let source_width = u16::try_from(width).context("uncompressed WireToSurface1 width exceeds u16")?;
    let source_height = u16::try_from(height).context("uncompressed WireToSurface1 height exceeds u16")?;

    let source_region = InclusiveRectangle {
        left: 0,
        top: 0,
        right: source_width - 1,
        bottom: source_height - 1,
    };
    let mut rgba_data = vec![0; byte_len];
    ImageRegion {
        region: source_region.clone(),
        step: 0,
        pixel_format: src_pixel_format,
        data: bitmap_data,
    }
    .copy_to(&mut ImageRegionMut {
        region: source_region,
        step: 0,
        pixel_format: GraphicsPixelFormat::RgbA32,
        data: rgba_data.as_mut_slice(),
    })
    .context("convert uncompressed WireToSurface1 pixels to RGBA")?;

    Ok(rgba_data)
}

fn decode_planar_wire_to_surface_1(
    decoder: &mut BitmapStreamDecoder,
    destination_rectangle: &InclusiveRectangle,
    bitmap_data: &[u8],
) -> Result<Vec<u8>> {
    let width = usize::from(destination_rectangle.right.saturating_sub(destination_rectangle.left) + 1);
    let height = usize::from(destination_rectangle.bottom.saturating_sub(destination_rectangle.top) + 1);
    let rgb24_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(3))
        .context("planar WireToSurface1 RGB24 byte count overflow")?;

    let mut rgb24 = Vec::with_capacity(rgb24_len);
    decoder
        .decode_bitmap_stream_to_rgb24(bitmap_data, &mut rgb24, width, height)
        .context("decode planar WireToSurface1 bitmap stream")?;

    if rgb24.len() != rgb24_len {
        anyhow::bail!(
            "planar WireToSurface1 RGB24 size mismatch: got {} bytes, expected {}",
            rgb24.len(),
            rgb24_len
        );
    }

    let mut rgba = vec![0; width * height * 4];
    for (rgb, rgba_pixel) in rgb24.chunks_exact(3).zip(rgba.chunks_exact_mut(4)) {
        rgba_pixel[0] = rgb[0];
        rgba_pixel[1] = rgb[1];
        rgba_pixel[2] = rgb[2];
        rgba_pixel[3] = 0xFF;
    }

    Ok(rgba)
}

fn decode_alpha_wire_to_surface_1(destination_rectangle: &InclusiveRectangle, bitmap_data: &[u8]) -> Result<Vec<u8>> {
    if bitmap_data.len() < 4 {
        anyhow::bail!("alpha WireToSurface1 bitmap is too short");
    }

    let alpha_sig = u16::from_le_bytes([bitmap_data[0], bitmap_data[1]]);
    if alpha_sig != ALPHA_CODEC_SIGNATURE {
        anyhow::bail!(
            "alpha WireToSurface1 signature mismatch: got 0x{alpha_sig:04X}, expected 0x{ALPHA_CODEC_SIGNATURE:04X}"
        );
    }

    let compressed = u16::from_le_bytes([bitmap_data[2], bitmap_data[3]]);

    let width = usize::from(destination_rectangle.right.saturating_sub(destination_rectangle.left) + 1);
    let height = usize::from(destination_rectangle.bottom.saturating_sub(destination_rectangle.top) + 1);
    let expected_alpha_len = width
        .checked_mul(height)
        .context("alpha WireToSurface1 pixel count overflow")?;

    if compressed == 0 {
        let alpha_data = &bitmap_data[4..];
        if alpha_data.len() != expected_alpha_len {
            anyhow::bail!(
                "alpha WireToSurface1 size mismatch: got {} bytes, expected {}",
                alpha_data.len(),
                expected_alpha_len
            );
        }

        return Ok(alpha_data.to_vec());
    }

    decode_compressed_alpha_segments(&bitmap_data[4..], expected_alpha_len)
}

fn decode_compressed_alpha_segments(segments: &[u8], expected_alpha_len: usize) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(expected_alpha_len);
    let mut offset = 0usize;

    while decoded.len() < expected_alpha_len {
        let run_value = *segments
            .get(offset)
            .context("compressed Alpha-RLE segment is missing runValue")?;
        offset += 1;

        let run_length_factor_1 = *segments
            .get(offset)
            .context("compressed Alpha-RLE segment is missing runLengthFactor1")?;
        offset += 1;

        let run_length = if run_length_factor_1 < 0xFF {
            usize::from(run_length_factor_1)
        } else {
            let run_length_factor_2 = u16::from_le_bytes([
                *segments
                    .get(offset)
                    .context("compressed Alpha-RLE segment is missing runLengthFactor2 low byte")?,
                *segments
                    .get(offset + 1)
                    .context("compressed Alpha-RLE segment is missing runLengthFactor2 high byte")?,
            ]);
            offset += 2;

            if run_length_factor_2 < 0xFFFF {
                usize::from(run_length_factor_2)
            } else {
                let run_length_factor_3 = u32::from_le_bytes([
                    *segments
                        .get(offset)
                        .context("compressed Alpha-RLE segment is missing runLengthFactor3 byte 0")?,
                    *segments
                        .get(offset + 1)
                        .context("compressed Alpha-RLE segment is missing runLengthFactor3 byte 1")?,
                    *segments
                        .get(offset + 2)
                        .context("compressed Alpha-RLE segment is missing runLengthFactor3 byte 2")?,
                    *segments
                        .get(offset + 3)
                        .context("compressed Alpha-RLE segment is missing runLengthFactor3 byte 3")?,
                ]);
                offset += 4;
                usize::try_from(run_length_factor_3).context("compressed Alpha-RLE run length does not fit usize")?
            }
        };

        if run_length == 0 {
            anyhow::bail!("compressed Alpha-RLE segment has zero run length");
        }

        let end = decoded
            .len()
            .checked_add(run_length)
            .context("compressed Alpha-RLE output length overflow")?;
        if end > expected_alpha_len {
            anyhow::bail!(
                "compressed Alpha-RLE expanded to {} pixels, expected {}",
                end,
                expected_alpha_len
            );
        }

        decoded.resize(end, run_value);
    }

    if offset != segments.len() {
        anyhow::bail!(
            "compressed Alpha-RLE has {} trailing bytes after decoding {} pixels",
            segments.len().saturating_sub(offset),
            expected_alpha_len
        );
    }

    Ok(decoded)
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::bitmap::rdp6::{BitmapStream, BitmapStreamHeader, ColorPlaneDefinition};
    use ironrdp_pdu::geometry::InclusiveRectangle;
    use ironrdp_pdu::rdp::vc::dvc::gfx::{
        Avc420BitmapStream, CacheToSurfacePdu, Codec1Type, Codec2Type, CreateSurfacePdu, DeleteEncodingContextPdu,
        DeleteSurfacePdu, EvictCacheEntryPdu, PixelFormat, Point, QuantQuality, ServerPdu, SurfaceToCachePdu,
        WireToSurface1Pdu, WireToSurface2Pdu,
    };
    use openh264::encoder::Encoder;
    use openh264::formats::{RgbSliceU8, YUVBuffer};

    use super::*;

    #[test]
    fn test_gfx_filter_creation() {
        let config = GfxConfig {
            overlay: true,
            stego: false,
            no_overlay_regions: vec!["taskbar".to_string()],
        };

        let filter = GfxFilter::new(config.clone(), "test-session-123".to_string());

        assert_eq!(filter.name(), "gfx");
        assert_eq!(filter.config.overlay, true);
        assert_eq!(filter.config.stego, false);
        assert_eq!(filter.surfaces.len(), 0);
        assert!(filter.surface_cache.is_empty());
        assert!(filter.surface_codec_contexts.is_empty());
        assert!(filter.pending_surface_updates.is_empty());
    }

    #[test]
    fn test_surface_create_delete() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test-session".to_string());

        // Create surface
        filter.handle_create_surface(1, 1920, 1080).unwrap();
        assert_eq!(filter.surfaces.len(), 1);
        assert!(filter.surfaces.contains_key(&1));

        // Create another surface
        filter.handle_create_surface(2, 640, 480).unwrap();
        assert_eq!(filter.surfaces.len(), 2);

        // Delete surface
        filter.handle_delete_surface(1).unwrap();
        assert_eq!(filter.surfaces.len(), 1);
        assert!(!filter.surfaces.contains_key(&1));
        assert!(filter.surfaces.contains_key(&2));

        // Delete non-existent surface (should not error)
        filter.handle_delete_surface(99).unwrap();
        assert_eq!(filter.surfaces.len(), 1);
    }

    #[test]
    fn test_parse_gfx_pdu_types() {
        // CreateSurface (0x0009)
        let create_surface = vec![0x09, 0x00, 0x34, 0x12, 0x0F, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_gfx_pdu_header(&create_surface),
            Some(GfxPduHeader {
                pdu_type: GfxPduType::CreateSurface,
                flags: 0x1234,
                pdu_length: 15,
                ..
            })
        ));

        // DeleteSurface (0x000A)
        let delete_surface = vec![0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_gfx_pdu_header(&delete_surface),
            Some(GfxPduHeader {
                pdu_type: GfxPduType::DeleteSurface,
                pdu_length: 10,
                ..
            })
        ));

        // WireToSurface1 (0x0001)
        let wire_to_surface = vec![0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_gfx_pdu_header(&wire_to_surface),
            Some(GfxPduHeader {
                pdu_type: GfxPduType::WireToSurface1,
                pdu_length: 25,
                ..
            })
        ));

        // Unknown PDU
        let unknown = vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_gfx_pdu_header(&unknown).is_none());

        // Too short
        let too_short = vec![0x03, 0x00];
        assert!(parse_gfx_pdu_header(&too_short).is_none());
    }

    #[test]
    fn test_parse_gfx_pdu_create_surface_fields() {
        let create_surface = encode_vec(&ServerPdu::CreateSurface(CreateSurfacePdu {
            surface_id: 7,
            width: 1920,
            height: 1080,
            pixel_format: PixelFormat::ARgb,
        }))
        .expect("encode create surface");

        assert!(matches!(
            parse_gfx_pdu(&create_surface),
            Some(ParsedGfxPdu::CreateSurface {
                surface_id: 7,
                width: 1920,
                height: 1080,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_client_to_server_passthrough() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        let test_data = Bytes::from_static(b"client data");
        let result = filter.process_client_to_server(test_data.clone()).await.unwrap();

        assert_eq!(result, test_data);
    }

    #[tokio::test]
    async fn test_server_to_client_non_gfx_passthrough() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        // Non-GFX data
        let test_data = Bytes::from_static(b"some random RDP data");
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        assert_eq!(result, test_data);
    }

    #[tokio::test]
    async fn test_create_surface_pdu_processing() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::CreateSurface(CreateSurfacePdu {
                surface_id: 1,
                width: 1920,
                height: 1080,
                pixel_format: PixelFormat::ARgb,
            }))
            .expect("encode create surface"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        // Should pass through unchanged
        assert_eq!(result, test_data);

        // But should create surface
        assert_eq!(filter.surfaces.len(), 1);
        assert!(filter.surfaces.contains_key(&1));
    }

    #[tokio::test]
    async fn test_create_surface_pdu_rejects_oversized_surface_without_panicking() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::CreateSurface(CreateSurfacePdu {
                surface_id: 1,
                width: u16::MAX,
                height: u16::MAX,
                pixel_format: PixelFormat::ARgb,
            }))
            .expect("encode oversized create surface"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        assert_eq!(result, test_data);
        assert!(!filter.surfaces.contains_key(&1));
    }

    #[tokio::test]
    async fn test_delete_surface_pdu_processing() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        // Create a surface first
        filter.handle_create_surface(5, 640, 480).unwrap();
        assert_eq!(filter.surfaces.len(), 1);

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::DeleteSurface(DeleteSurfacePdu { surface_id: 5 })).expect("encode delete surface"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        // Should pass through unchanged
        assert_eq!(result, test_data);

        // But should delete surface
        assert_eq!(filter.surfaces.len(), 0);
    }

    #[tokio::test]
    async fn test_wire_to_surface2_tracks_codec_context_metadata() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(5, 640, 480).unwrap();

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface2(WireToSurface2Pdu {
                surface_id: 5,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: 0x5566_7788,
                pixel_format: PixelFormat::ARgb,
                bitmap_data: vec![0xAA, 0xBB, 0xCC],
            }))
            .expect("encode wire to surface2"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        assert_eq!(result, test_data);
        assert_eq!(
            filter.surface_codec_contexts.get(&5),
            Some(&HashSet::from([0x5566_7788]))
        );
    }

    #[tokio::test]
    async fn test_delete_encoding_context_removes_codec_context_metadata() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(7, 800, 600).unwrap();
        filter
            .surface_codec_contexts
            .insert(7, HashSet::from([0x0102_0304, 0x0506_0708]));

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::DeleteEncodingContext(DeleteEncodingContextPdu {
                surface_id: 7,
                codec_context_id: 0x0102_0304,
            }))
            .expect("encode delete encoding context"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        assert_eq!(result, test_data);
        assert_eq!(
            filter.surface_codec_contexts.get(&7),
            Some(&HashSet::from([0x0506_0708]))
        );
    }

    #[tokio::test]
    async fn test_warning_summary_tracks_missing_surface_and_cache_events() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(1, 8, 8).unwrap();
        {
            let surface = filter.surfaces.get_mut(&1).expect("surface");
            surface.set_pixel(0, 0, 1, 2, 3, 255).unwrap();
        }

        let surface_to_cache_unknown = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 99,
                cache_key: 0xAA,
                cache_slot: 1,
                source_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
            }))
            .expect("encode unknown-surface surface-to-cache"),
        );
        filter.process_server_to_client(surface_to_cache_unknown).await.unwrap();

        let cache_to_surface_unknown_slot = Bytes::from(
            encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
                cache_slot: 7,
                surface_id: 1,
                destination_points: vec![Point { x: 0, y: 0 }],
            }))
            .expect("encode unknown cache slot replay"),
        );
        filter
            .process_server_to_client(cache_to_surface_unknown_slot)
            .await
            .unwrap();

        let cache_seed = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 1,
                cache_key: 0xBB,
                cache_slot: 2,
                source_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
            }))
            .expect("encode cache seed"),
        );
        filter.process_server_to_client(cache_seed).await.unwrap();

        let cache_to_surface_unknown_surface = Bytes::from(
            encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
                cache_slot: 2,
                surface_id: 77,
                destination_points: vec![Point { x: 1, y: 1 }],
            }))
            .expect("encode unknown destination surface replay"),
        );
        filter
            .process_server_to_client(cache_to_surface_unknown_surface)
            .await
            .unwrap();

        let wire_to_surface1_unknown_surface = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 55,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
                bitmap_data: vec![0xFF, 0x01, 0x02, 0x03],
            }))
            .expect("encode unknown-surface wire-to-surface1"),
        );
        filter
            .process_server_to_client(wire_to_surface1_unknown_surface)
            .await
            .unwrap();

        let wire_to_surface2_unknown_surface = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface2(WireToSurface2Pdu {
                surface_id: 88,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: 0x0102_0304,
                pixel_format: PixelFormat::ARgb,
                bitmap_data: vec![0xAA],
            }))
            .expect("encode unknown-surface wire-to-surface2"),
        );
        filter
            .process_server_to_client(wire_to_surface2_unknown_surface)
            .await
            .unwrap();

        let summary = filter.warning_summary;
        assert_eq!(summary.surface_to_cache_unknown_surface_count, 1);
        assert_eq!(summary.cache_to_surface_unknown_cache_slot_count, 1);
        assert_eq!(summary.cache_to_surface_unknown_surface_count, 1);
        assert_eq!(summary.wire_to_surface1_unknown_surface_count, 1);
        assert_eq!(summary.wire_to_surface2_metadata_unknown_surface_count, 1);
        assert_eq!(summary.wire_to_surface2_update_unknown_surface_count, 1);
        assert_eq!(summary.total_warning_count(), 6);
    }

    #[tokio::test]
    async fn test_warning_summary_tracks_decode_and_replay_failures() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(1, 4, 4).unwrap();
        filter.handle_create_surface(2, 4, 4).unwrap();

        let wire_to_surface1_invalid_uncompressed = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 1,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 1,
                    bottom: 0,
                },
                bitmap_data: vec![0xFF, 0x01, 0x02, 0x03],
            }))
            .expect("encode invalid uncompressed wire-to-surface1"),
        );
        filter
            .process_server_to_client(wire_to_surface1_invalid_uncompressed)
            .await
            .unwrap();

        let wire_to_surface1_invalid_clearcodec = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 1,
                codec_id: Codec1Type::ClearCodec,
                pixel_format: PixelFormat::XRgb,
                destination_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
                bitmap_data: vec![0x00],
            }))
            .expect("encode invalid clearcodec wire-to-surface1"),
        );
        filter
            .process_server_to_client(wire_to_surface1_invalid_clearcodec)
            .await
            .unwrap();

        let wire_to_surface2_invalid = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface2(WireToSurface2Pdu {
                surface_id: 2,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: 0x0506_0708,
                pixel_format: PixelFormat::ARgb,
                bitmap_data: vec![0x00],
            }))
            .expect("encode invalid wire-to-surface2"),
        );
        filter.process_server_to_client(wire_to_surface2_invalid).await.unwrap();

        let surface_to_cache_capture_skipped = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 1,
                cache_key: 0xCC,
                cache_slot: 3,
                source_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 4,
                    bottom: 0,
                },
            }))
            .expect("encode surface-to-cache capture skip"),
        );
        filter
            .process_server_to_client(surface_to_cache_capture_skipped)
            .await
            .unwrap();

        filter.surface_cache.insert(
            9,
            CachedSurfaceTile {
                cache_key: 0xDD,
                width: 2,
                height: 2,
                rgba_data: vec![0x01, 0x02, 0x03],
            },
        );
        let cache_to_surface_replay_skipped = Bytes::from(
            encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
                cache_slot: 9,
                surface_id: 1,
                destination_points: vec![Point { x: 0, y: 0 }],
            }))
            .expect("encode cache-to-surface replay skip"),
        );
        filter
            .process_server_to_client(cache_to_surface_replay_skipped)
            .await
            .unwrap();

        let summary = filter.warning_summary;
        assert_eq!(summary.wire_to_surface1_update_failed_count, 1);
        assert_eq!(summary.wire_to_surface1_decode_skipped_count, 1);
        assert_eq!(summary.wire_to_surface2_decode_skipped_count, 1);
        assert_eq!(summary.surface_to_cache_capture_skipped_count, 1);
        assert_eq!(summary.cache_to_surface_replay_skipped_count, 1);
        assert_eq!(summary.total_warning_count(), 5);
    }

    #[tokio::test]
    async fn test_surface_to_cache_and_cache_to_surface_update_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(11, 16, 16).unwrap();
        {
            let surface = filter.surfaces.get_mut(&11).expect("surface");
            surface.set_pixel(1, 1, 10, 20, 30, 255).unwrap();
            surface.set_pixel(2, 1, 40, 50, 60, 255).unwrap();
            surface.set_pixel(1, 2, 70, 80, 90, 255).unwrap();
            surface.set_pixel(2, 2, 100, 110, 120, 255).unwrap();
        }

        let source_rectangle = InclusiveRectangle {
            left: 1,
            top: 1,
            right: 2,
            bottom: 2,
        };
        let surface_to_cache = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 11,
                cache_key: 0xAABB_CCDD_EEFF_0011,
                cache_slot: 2,
                source_rectangle: source_rectangle.clone(),
            }))
            .expect("encode surface to cache"),
        );
        let result = filter.process_server_to_client(surface_to_cache.clone()).await.unwrap();
        assert_eq!(result, surface_to_cache);

        let cache_to_surface = Bytes::from(
            encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
                cache_slot: 2,
                surface_id: 11,
                destination_points: vec![Point { x: 4, y: 5 }, Point { x: 8, y: 9 }],
            }))
            .expect("encode cache to surface"),
        );
        let result = filter.process_server_to_client(cache_to_surface.clone()).await.unwrap();
        assert_eq!(result, cache_to_surface);

        let updated = filter.surfaces.get(&11).expect("surface");
        assert_eq!(updated.get_pixel(4, 5), Some((10, 20, 30, 255)));
        assert_eq!(updated.get_pixel(5, 5), Some((40, 50, 60, 255)));
        assert_eq!(updated.get_pixel(4, 6), Some((70, 80, 90, 255)));
        assert_eq!(updated.get_pixel(5, 6), Some((100, 110, 120, 255)));
        assert_eq!(updated.get_pixel(8, 9), Some((10, 20, 30, 255)));
        assert_eq!(updated.get_pixel(9, 10), Some((100, 110, 120, 255)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 2);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 4,
                top: 5,
                right: 5,
                bottom: 6,
            }
        );
        assert_eq!(
            updates[1].rectangle,
            InclusiveRectangle {
                left: 8,
                top: 9,
                right: 9,
                bottom: 10,
            }
        );
        assert_eq!(
            updates[0].rgba_data,
            vec![10, 20, 30, 255, 40, 50, 60, 255, 70, 80, 90, 255, 100, 110, 120, 255,]
        );
        assert_eq!(updates[1].rgba_data, updates[0].rgba_data);
    }

    #[tokio::test]
    async fn test_surface_to_cache_uses_exclusive_style_fallback_when_source_rectangle_overruns_by_one() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(23, 4, 4).unwrap();
        {
            let surface = filter.surfaces.get_mut(&23).expect("surface");
            let mut value = 1u8;
            for y in 1..=3 {
                for x in 1..=3 {
                    surface.set_pixel(x, y, value, value.wrapping_add(1), value.wrapping_add(2), 255).unwrap();
                    value = value.wrapping_add(3);
                }
            }
        }

        let surface_to_cache = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 23,
                cache_key: 0x1020_3040_5060_7080,
                cache_slot: 4,
                source_rectangle: InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 4,
                    bottom: 4,
                },
            }))
            .expect("encode surface to cache"),
        );

        let result = filter.process_server_to_client(surface_to_cache.clone()).await.unwrap();
        assert_eq!(result, surface_to_cache);

        let cached_tile = filter.surface_cache.get(&4).expect("cached surface tile");
        assert_eq!(cached_tile.width, 3);
        assert_eq!(cached_tile.height, 3);
        assert_eq!(&cached_tile.rgba_data[0..4], &[1, 2, 3, 255]);
        assert_eq!(&cached_tile.rgba_data[cached_tile.rgba_data.len() - 4..], &[25, 26, 27, 255]);
    }

    #[tokio::test]
    async fn test_evict_cache_entry_drops_cached_surface_tile() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(12, 8, 8).unwrap();
        {
            let surface = filter.surfaces.get_mut(&12).expect("surface");
            surface.set_pixel(0, 0, 1, 2, 3, 255).unwrap();
        }

        let surface_to_cache = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 12,
                cache_key: 0x55,
                cache_slot: 7,
                source_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
            }))
            .expect("encode surface to cache"),
        );
        filter.process_server_to_client(surface_to_cache).await.unwrap();
        assert!(filter.surface_cache.contains_key(&7));

        let evict = Bytes::from(
            encode_vec(&ServerPdu::EvictCacheEntry(EvictCacheEntryPdu { cache_slot: 7 }))
                .expect("encode evict cache entry"),
        );
        let result = filter.process_server_to_client(evict.clone()).await.unwrap();
        assert_eq!(result, evict);
        assert!(!filter.surface_cache.contains_key(&7));
    }

    #[tokio::test]
    async fn test_cache_to_surface_clips_edge_tile_instead_of_skipping() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(13, 5, 5).unwrap();
        {
            let surface = filter.surfaces.get_mut(&13).expect("surface");
            surface.set_pixel(0, 0, 10, 20, 30, 255).unwrap();
            surface.set_pixel(1, 0, 40, 50, 60, 255).unwrap();
            surface.set_pixel(0, 1, 70, 80, 90, 255).unwrap();
            surface.set_pixel(1, 1, 100, 110, 120, 255).unwrap();
        }

        let surface_to_cache = Bytes::from(
            encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
                surface_id: 13,
                cache_key: 0x1234,
                cache_slot: 9,
                source_rectangle: InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 1,
                    bottom: 1,
                },
            }))
            .expect("encode surface to cache"),
        );
        filter.process_server_to_client(surface_to_cache).await.unwrap();

        let cache_to_surface = Bytes::from(
            encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
                cache_slot: 9,
                surface_id: 13,
                destination_points: vec![Point { x: 4, y: 4 }],
            }))
            .expect("encode cache to surface"),
        );
        filter.process_server_to_client(cache_to_surface).await.unwrap();

        let updated = filter.surfaces.get(&13).expect("surface");
        assert_eq!(updated.get_pixel(4, 4), Some((10, 20, 30, 255)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 4,
                top: 4,
                right: 4,
                bottom: 4,
            }
        );
        assert_eq!(updates[0].rgba_data, vec![10, 20, 30, 255]);
    }

    #[tokio::test]
    async fn test_wire_to_surface2_rfx_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(8, 64, 64).unwrap();
        let bitmap_data = rfx::encode_test_remote_fx_bitmap(64, 64, [220, 10, 10, 255], true);
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface2(WireToSurface2Pdu {
                surface_id: 8,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: 0x1122_3344,
                pixel_format: PixelFormat::ARgb,
                bitmap_data,
            }))
            .expect("encode wire to surface2"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&8).expect("surface");
        let inside = updated.get_pixel(10, 10).expect("updated pixel");
        assert!(inside.0 > inside.1);
        assert!(inside.0 > inside.2);
        assert_eq!(inside.3, 255);

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 8);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 0,
                top: 0,
                right: 63,
                bottom: 63,
            }
        );
    }

    #[tokio::test]
    async fn test_wire_to_surface_remotefx_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(9, 128, 128).unwrap();
        let rectangle = InclusiveRectangle {
            left: 11,
            top: 12,
            right: 74,
            bottom: 75,
        };
        let bitmap_data = rfx::encode_test_remote_fx_bitmap(64, 64, [10, 220, 10, 255], true);
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 9,
                codec_id: Codec1Type::RemoteFx,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle,
                bitmap_data,
            }))
            .expect("encode wire to surface1"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&9).expect("surface");
        let inside = updated.get_pixel(20, 20).expect("updated pixel");
        let outside = updated.get_pixel(5, 5).expect("outside pixel");
        assert!(inside.1 > inside.0);
        assert!(inside.1 > inside.2);
        assert_eq!(inside.3, 255);
        assert_eq!(outside, (0, 0, 0, 0));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 9);
        assert_eq!(updates[0].surface_width, 128);
        assert_eq!(updates[0].surface_height, 128);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 11,
                top: 12,
                right: 74,
                bottom: 75,
            }
        );
        assert_eq!(updates[0].rgba_data.len(), 64 * 64 * 4);
    }

    #[tokio::test]
    async fn test_wire_to_surface_passthrough_when_disabled() {
        let config = GfxConfig {
            overlay: false,
            stego: false,
            no_overlay_regions: vec![],
        };
        let mut filter = GfxFilter::new(config, "test".to_string());

        // Create a surface
        filter.handle_create_surface(1, 640, 480).unwrap();

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 1,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: InclusiveRectangle {
                    left: 10,
                    top: 20,
                    right: 29,
                    bottom: 39,
                },
                bitmap_data: vec![0x10, 0x20, 0x30, 0x40],
            }))
            .expect("encode wire to surface"),
        );
        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();

        // Should pass through unchanged when overlay/stego disabled
        assert_eq!(result, test_data);
    }

    #[tokio::test]
    async fn test_wire_to_surface_uncompressed_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(1, 16, 16).unwrap();

        let rectangle = InclusiveRectangle {
            left: 3,
            top: 4,
            right: 4,
            bottom: 4,
        };
        let bitmap_data = vec![
            0x80, 0x14, 0x1E, 0x28, // ARGB -> RGBA (20,30,40,128)
            0xFF, 0xC8, 0xD2, 0xDC, // ARGB -> RGBA (200,210,220,255)
        ];
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 1,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle.clone(),
                bitmap_data,
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&1).expect("surface");
        assert_eq!(updated.get_pixel(3, 4), Some((0x14, 0x1E, 0x28, 0x80)));
        assert_eq!(updated.get_pixel(4, 4), Some((0xC8, 0xD2, 0xDC, 0xFF)));
        assert_eq!(updated.get_pixel(2, 4), Some((0, 0, 0, 0)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 1);
        assert_eq!(updates[0].rectangle, rectangle);
        assert_eq!(
            updates[0].rgba_data,
            vec![0x14, 0x1E, 0x28, 0x80, 0xC8, 0xD2, 0xDC, 0xFF]
        );
    }

    #[tokio::test]
    async fn test_wire_to_surface_uncompressed_xrgb_forces_opaque_alpha() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(2, 8, 8).unwrap();

        let rectangle = InclusiveRectangle {
            left: 1,
            top: 1,
            right: 1,
            bottom: 1,
        };
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 2,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::XRgb,
                destination_rectangle: rectangle,
                bitmap_data: vec![0x00, 0x11, 0x22, 0x33],
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&2).expect("surface");
        assert_eq!(updated.get_pixel(1, 1), Some((0x11, 0x22, 0x33, 0xFF)));
    }

    #[tokio::test]
    async fn test_wire_to_surface_uncompressed_uses_exclusive_style_fallback_when_bitmap_len_matches() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(22, 8, 8).unwrap();

        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 22,
                codec_id: Codec1Type::Uncompressed,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 2,
                },
                bitmap_data: vec![0x44, 0x11, 0x22, 0x33],
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&22).expect("surface");
        assert_eq!(updated.get_pixel(1, 1), Some((0x11, 0x22, 0x33, 0x44)));
        assert_eq!(updated.get_pixel(2, 2), Some((0, 0, 0, 0)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 1,
                top: 1,
                right: 1,
                bottom: 1,
            }
        );
        assert_eq!(updates[0].rgba_data, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[tokio::test]
    async fn test_wire_to_surface_planar_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(3, 16, 16).unwrap();

        let rectangle = InclusiveRectangle {
            left: 5,
            top: 6,
            right: 6,
            bottom: 6,
        };
        let color_planes = vec![
            0x14, 0xC8, // R
            0x1E, 0xD2, // G
            0x28, 0xDC, // B
        ];
        let bitmap_data = encode_vec(&BitmapStream {
            header: BitmapStreamHeader {
                enable_rle_compression: false,
                use_alpha: false,
                color_plane_definition: ColorPlaneDefinition::Argb,
            },
            color_planes: &color_planes,
        })
        .expect("encode planar bitmap stream");
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 3,
                codec_id: Codec1Type::Planar,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle.clone(),
                bitmap_data,
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&3).expect("surface");
        assert_eq!(updated.get_pixel(5, 6), Some((0x14, 0x1E, 0x28, 0xFF)));
        assert_eq!(updated.get_pixel(6, 6), Some((0xC8, 0xD2, 0xDC, 0xFF)));
        assert_eq!(updated.get_pixel(4, 6), Some((0, 0, 0, 0)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 3);
        assert_eq!(updates[0].rectangle, rectangle);
        assert_eq!(
            updates[0].rgba_data,
            vec![0x14, 0x1E, 0x28, 0xFF, 0xC8, 0xD2, 0xDC, 0xFF]
        );
    }

    #[tokio::test]
    async fn test_wire_to_surface_alpha_updates_alpha_channel_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(4, 16, 16).unwrap();
        {
            let surface = filter.surfaces.get_mut(&4).expect("surface");
            surface.set_pixel(7, 8, 10, 20, 30, 40).unwrap();
            surface.set_pixel(8, 8, 50, 60, 70, 80).unwrap();
        }

        let rectangle = InclusiveRectangle {
            left: 7,
            top: 8,
            right: 8,
            bottom: 8,
        };
        let bitmap_data = vec![
            0x4C, 0x41, // alphaSig = 0x414C
            0x00, 0x00, // compressed = false
            0xAA, 0xBB, // alpha values
        ];
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 4,
                codec_id: Codec1Type::Alpha,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle.clone(),
                bitmap_data,
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&4).expect("surface");
        assert_eq!(updated.get_pixel(7, 8), Some((10, 20, 30, 0xAA)));
        assert_eq!(updated.get_pixel(8, 8), Some((50, 60, 70, 0xBB)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 4);
        assert_eq!(updates[0].rectangle, rectangle);
        assert_eq!(updates[0].rgba_data, vec![10, 20, 30, 0xAA, 50, 60, 70, 0xBB]);
    }

    #[tokio::test]
    async fn test_wire_to_surface_alpha_rle_updates_alpha_channel_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(4, 16, 16).unwrap();
        {
            let surface = filter.surfaces.get_mut(&4).expect("surface");
            surface.set_pixel(7, 8, 10, 20, 30, 40).unwrap();
            surface.set_pixel(8, 8, 50, 60, 70, 80).unwrap();
            surface.set_pixel(7, 9, 90, 100, 110, 120).unwrap();
            surface.set_pixel(8, 9, 130, 140, 150, 160).unwrap();
        }

        let rectangle = InclusiveRectangle {
            left: 7,
            top: 8,
            right: 8,
            bottom: 9,
        };
        let bitmap_data = vec![
            0x4C, 0x41, // alphaSig = 0x414C
            0x01, 0x00, // compressed = true
            0xAA, 0x02, // top row alpha
            0xBB, 0x02, // bottom row alpha
        ];
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 4,
                codec_id: Codec1Type::Alpha,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle.clone(),
                bitmap_data,
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&4).expect("surface");
        assert_eq!(updated.get_pixel(7, 8), Some((10, 20, 30, 0xAA)));
        assert_eq!(updated.get_pixel(8, 8), Some((50, 60, 70, 0xAA)));
        assert_eq!(updated.get_pixel(7, 9), Some((90, 100, 110, 0xBB)));
        assert_eq!(updated.get_pixel(8, 9), Some((130, 140, 150, 0xBB)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 4);
        assert_eq!(updates[0].rectangle, rectangle);
        assert_eq!(
            updates[0].rgba_data,
            vec![
                10, 20, 30, 0xAA, 50, 60, 70, 0xAA, 90, 100, 110, 0xBB, 130, 140, 150, 0xBB,
            ]
        );
    }

    #[test]
    fn test_decode_alpha_wire_to_surface_1_decodes_compressed_stream() {
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 1,
            bottom: 1,
        };

        let alpha = decode_alpha_wire_to_surface_1(&rectangle, &[0x4C, 0x41, 0x01, 0x00, 0xAA, 0x02, 0xBB, 0x02])
            .expect("decode compressed alpha bitmap stream");

        assert_eq!(alpha, vec![0xAA, 0xAA, 0xBB, 0xBB]);
    }

    #[tokio::test]
    async fn test_wire_to_surface_clearcodec_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(5, 32, 32).unwrap();

        let rectangle = InclusiveRectangle {
            left: 1,
            top: 2,
            right: 2,
            bottom: 3,
        };
        let mut bitmap_data = vec![
            0x01, 0x0E, // flags, sequence number
            0x03, 0x00, // glyph index
            0x00, 0x00, 0x00, 0x00, // residual bytes
            0x1B, 0x00, 0x00, 0x00, // bands bytes
            0x00, 0x00, 0x00, 0x00, // subcodec bytes
            0x00, 0x00, // xStart
            0x01, 0x00, // xEnd
            0x00, 0x00, // yStart
            0x01, 0x00, // yEnd
            0x00, // blue
            0x00, // green
            0x00, // red
            0x00, // vbar 0 yOn
            0x02, // vbar 0 yOff
            0x01, 0x02, 0x03, // vbar 0 row 0 BGR
            0x04, 0x05, 0x06, // vbar 0 row 1 BGR
            0x00, // vbar 1 yOn
            0x02, // vbar 1 yOff
            0x07, 0x08, 0x09, // vbar 1 row 0 BGR
            0x0A, 0x0B, 0x0C, // vbar 1 row 1 BGR
        ];
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 5,
                codec_id: Codec1Type::ClearCodec,
                pixel_format: PixelFormat::XRgb,
                destination_rectangle: rectangle.clone(),
                bitmap_data: std::mem::take(&mut bitmap_data),
            }))
            .expect("encode clearcodec wire to surface"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&5).expect("surface");
        assert_eq!(updated.get_pixel(1, 2), Some((3, 2, 1, 0xFF)));
        assert_eq!(updated.get_pixel(2, 2), Some((9, 8, 7, 0xFF)));
        assert_eq!(updated.get_pixel(1, 3), Some((6, 5, 4, 0xFF)));
        assert_eq!(updated.get_pixel(2, 3), Some((12, 11, 10, 0xFF)));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 5);
        assert_eq!(updates[0].rectangle, rectangle);
        assert_eq!(
            updates[0].rgba_data,
            vec![3, 2, 1, 0xFF, 9, 8, 7, 0xFF, 6, 5, 4, 0xFF, 12, 11, 10, 0xFF,]
        );
    }

    #[tokio::test]
    async fn test_wire_to_surface_avc420_updates_framebuffer_when_disabled() {
        let config = GfxConfig::default();
        let mut filter = GfxFilter::new(config, "test".to_string());

        filter.handle_create_surface(1, 64, 64).unwrap();

        let width = 16usize;
        let height = 16usize;
        let mut source_rgb = Vec::with_capacity(width * height * 3);
        for _ in 0..(width * height) {
            source_rgb.extend_from_slice(&[220, 10, 10]);
        }
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&source_rgb, (width, height)));
        let mut encoder = Encoder::new().expect("OpenH264 encoder");
        let encoded = encoder.encode(&yuv).expect("encode h264").to_vec();

        let rectangle = InclusiveRectangle {
            left: 8,
            top: 9,
            right: 23,
            bottom: 24,
        };
        let bitmap_stream = Avc420BitmapStream {
            rectangles: vec![rectangle.clone()],
            quant_qual_vals: vec![QuantQuality {
                quantization_parameter: 0,
                progressive: false,
                quality: 100,
            }],
            data: &encoded,
        };
        let bitmap_data = encode_vec(&bitmap_stream).expect("encode avc420 bitmap stream");
        let test_data = Bytes::from(
            encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
                surface_id: 1,
                codec_id: Codec1Type::Avc420,
                pixel_format: PixelFormat::ARgb,
                destination_rectangle: rectangle,
                bitmap_data,
            }))
            .expect("encode wire to surface pdu"),
        );

        let result = filter.process_server_to_client(test_data.clone()).await.unwrap();
        assert_eq!(result, test_data);

        let updated = filter.surfaces.get(&1).expect("surface");
        let inside = updated.get_pixel(10, 10).expect("updated pixel");
        let outside = updated.get_pixel(2, 2).expect("outside pixel");

        assert!(inside.0 > inside.1);
        assert_eq!(inside.3, 255);
        assert_eq!(outside, (0, 0, 0, 0));

        let updates = filter.drain_surface_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].surface_id, 1);
        assert_eq!(updates[0].surface_width, 64);
        assert_eq!(updates[0].surface_height, 64);
        assert_eq!(
            updates[0].rectangle,
            InclusiveRectangle {
                left: 8,
                top: 9,
                right: 23,
                bottom: 24,
            }
        );
        assert_eq!(updates[0].rgba_data.len(), 16 * 16 * 4);
        assert!(filter.drain_surface_updates().is_empty());
    }

    #[test]
    fn test_config_default() {
        let config = GfxConfig::default();
        assert_eq!(config.overlay, false);
        assert_eq!(config.stego, false);
        assert_eq!(config.no_overlay_regions.len(), 0);
    }
}
