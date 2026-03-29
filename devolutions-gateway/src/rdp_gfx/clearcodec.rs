#![allow(
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of,
    reason = "imported RDPEGFX ClearCodec decoder keeps upstream structure while playback is being proven"
)]

use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use ironrdp_pdu::geometry::InclusiveRectangle;
use tracing::debug;

use super::nsc::decode_nsc_bitmap_to_rgba;

pub const CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX: u8 = 0x01;
pub const CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_HIT: u8 = 0x02;
pub const CLEARCODEC_BITMAP_STREAM_FLAG_CACHE_RESET: u8 = 0x04;
pub const CLEARCODEC_BAND_HEADER_LEN: usize = 11;
const CLEARCODEC_VBAR_STORAGE_CAPACITY: u16 = 0x8000;
const CLEARCODEC_SHORT_VBAR_STORAGE_CAPACITY: u16 = 0x4000;
const CLEARCODEC_GLYPH_STORAGE_CAPACITY: u16 = 4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecBitmapStream<'a> {
    pub flags: u8,
    pub sequence_number: u8,
    pub glyph_index: Option<u16>,
    pub composite_payload: ClearCodecCompositePayload<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecCompositePayload<'a> {
    pub residual_data: &'a [u8],
    pub bands_data: &'a [u8],
    pub subcodec_data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecBandHeader {
    pub x_start: u16,
    pub x_end: u16,
    pub y_start: u16,
    pub y_end: u16,
    pub blue: u8,
    pub green: u8,
    pub red: u8,
}

impl ClearCodecBandHeader {
    pub fn vbar_count(&self) -> usize {
        usize::from(self.x_end.saturating_sub(self.x_start)) + 1
    }

    pub fn pixel_height(&self) -> usize {
        usize::from(self.y_end.saturating_sub(self.y_start)) + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecBand<'a> {
    pub header: ClearCodecBandHeader,
    pub vbars: Vec<ClearCodecVBar<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecRgbRunSegment {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub run_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedClearCodecResidual {
    pub segments: Vec<ClearCodecRgbRunSegment>,
    pub decoded_pixels: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearCodecVBar<'a> {
    CacheHit {
        vbar_index: u16,
    },
    ShortCacheHit {
        short_vbar_index: u16,
        short_vbar_y_on: u8,
    },
    ShortCacheMiss {
        short_vbar_y_on: u8,
        short_vbar_y_off: u8,
        short_vbar_pixels: &'a [u8],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedClearCodecRegion {
    pub rectangle: InclusiveRectangle,
    pub rgba_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCodecSubcodec<'a> {
    pub x_start: u16,
    pub y_start: u16,
    pub width: u16,
    pub height: u16,
    pub subcodec_id: u8,
    pub bitmap_data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredGlyphRegion {
    rectangle: InclusiveRectangle,
    rgba_data: Vec<u8>,
}

#[derive(Default)]
pub struct SurfaceClearCodecDecoders {
    contexts: HashMap<u16, ClearCodecDecodingContext>,
}

impl SurfaceClearCodecDecoders {
    pub fn remove_surface(&mut self, surface_id: u16) {
        self.contexts.remove(&surface_id);
    }

    pub fn decode_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        destination: &InclusiveRectangle,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedClearCodecRegion>> {
        let bitmap_stream = parse_clearcodec_bitmap_stream(bitmap_data)?;
        let decoder = self.contexts.entry(surface_id).or_default();
        decoder.decode(destination, &bitmap_stream)
    }
}

#[derive(Default)]
struct ClearCodecDecodingContext {
    vbar_storage: HashMap<u16, Vec<u8>>,
    short_vbar_storage: HashMap<u16, Vec<u8>>,
    glyph_storage: HashMap<u16, Vec<StoredGlyphRegion>>,
    vbar_cursor: u16,
    short_vbar_cursor: u16,
}

impl ClearCodecDecodingContext {
    fn decode(
        &mut self,
        destination: &InclusiveRectangle,
        bitmap_stream: &ClearCodecBitmapStream<'_>,
    ) -> Result<Vec<DecodedClearCodecRegion>> {
        if bitmap_stream.flags & CLEARCODEC_BITMAP_STREAM_FLAG_CACHE_RESET != 0 {
            self.reset_cache_cursors();
        }

        let glyph_index = bitmap_stream.glyph_index;
        let glyph_hit = bitmap_stream.flags & CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_HIT != 0;

        if glyph_hit && glyph_index.is_none() {
            bail!("ClearCodec glyph hit requires glyph index");
        }

        if glyph_hit {
            return self.decode_glyph_hit(destination, glyph_index.expect("validated glyph index"));
        }

        if glyph_index.is_some() {
            let destination_width = usize::from(destination.right.saturating_sub(destination.left)) + 1;
            let destination_height = usize::from(destination.bottom.saturating_sub(destination.top)) + 1;
            let area = destination_width
                .checked_mul(destination_height)
                .context("ClearCodec glyph area overflow")?;
            if area > 1024 {
                bail!("ClearCodec glyph bitmap area exceeds 1024 pixels");
            }
        }

        let subcodec_regions = parse_clearcodec_subcodecs_data(bitmap_stream.composite_payload.subcodec_data)?
            .into_iter()
            .map(|subcodec| {
                let subcodec_id = subcodec.subcodec_id;
                decode_clearcodec_subcodec_to_region(destination, &subcodec).map(|region| (subcodec_id, region))
            })
            .collect::<Result<Vec<_>>>()?;
        let subcodec_ids = subcodec_regions
            .iter()
            .map(|(subcodec_id, _)| format!("0x{subcodec_id:02x}"))
            .collect::<Vec<_>>();
        let subcodec_regions = subcodec_regions
            .into_iter()
            .map(|(_, region)| region)
            .collect::<Vec<_>>();

        let destination_width = usize::from(destination.right.saturating_sub(destination.left)) + 1;
        let destination_height = usize::from(destination.bottom.saturating_sub(destination.top)) + 1;
        let destination_area = destination_width
            .checked_mul(destination_height)
            .context("ClearCodec destination pixel count overflow")?;
        let bands = parse_clearcodec_bands_data(bitmap_stream.composite_payload.bands_data)?;
        let decoded = if bitmap_stream.composite_payload.residual_data.is_empty() {
            let mut decoded = bands
                .iter()
                .map(|band| self.decode_band(destination, band))
                .collect::<Result<Vec<_>>>()?;
            decoded.extend(subcodec_regions);
            decoded
        } else {
            let expected_pixels = destination_width
                .checked_mul(destination_height)
                .context("ClearCodec destination pixel count overflow")?;
            let (mut rgba_data, residual_pixels) = decode_clearcodec_residual_prefix_to_rgba(
                bitmap_stream.composite_payload.residual_data,
                destination_width,
                destination_height,
            )?;
            if residual_pixels < expected_pixels && bands.is_empty() && subcodec_regions.is_empty() {
                bail!("ClearCodec partial residual without later layers is not implemented");
            }

            let band_regions = bands
                .iter()
                .map(|band| self.decode_band(destination, band))
                .collect::<Result<Vec<_>>>()?;

            if residual_pixels < expected_pixels
                && !combined_clearcodec_coverage_is_exact(
                    destination,
                    residual_pixels,
                    band_regions.iter().chain(subcodec_regions.iter()),
                )?
            {
                bail!("ClearCodec partial residual with incomplete later-layer coverage is not implemented");
            }

            for region in &band_regions {
                blit_region_into_surface(
                    &mut rgba_data,
                    destination_width,
                    destination,
                    &region.rectangle,
                    &region.rgba_data,
                )?;
            }

            for region in &subcodec_regions {
                blit_region_into_surface(
                    &mut rgba_data,
                    destination_width,
                    destination,
                    &region.rectangle,
                    &region.rgba_data,
                )?;
            }

            vec![DecodedClearCodecRegion {
                rectangle: destination.clone(),
                rgba_data,
            }]
        };

        let decoded_area = decoded.iter().try_fold(0usize, |acc, region| {
            let width = usize::from(region.rectangle.right.saturating_sub(region.rectangle.left)) + 1;
            let height = usize::from(region.rectangle.bottom.saturating_sub(region.rectangle.top)) + 1;
            acc.checked_add(
                width
                    .checked_mul(height)
                    .context("ClearCodec decoded region area overflow")?,
            )
            .context("ClearCodec decoded area overflow")
        })?;
        let tiny_destination = destination_area <= 4096;

        if decoded_area < destination_area
            || !subcodec_ids.is_empty()
            || !bitmap_stream.composite_payload.residual_data.is_empty()
            || bands.len() > 1
            || glyph_hit
            || tiny_destination
        {
            debug!(
                flags = bitmap_stream.flags,
                sequence_number = bitmap_stream.sequence_number,
                glyph_index = ?glyph_index,
                glyph_hit,
                tiny_destination,
                destination_left = destination.left,
                destination_top = destination.top,
                destination_width,
                destination_height,
                destination_area,
                residual_bytes = bitmap_stream.composite_payload.residual_data.len(),
                bands_bytes = bitmap_stream.composite_payload.bands_data.len(),
                subcodec_bytes = bitmap_stream.composite_payload.subcodec_data.len(),
                band_count = bands.len(),
                subcodec_ids = ?subcodec_ids,
                decoded_region_count = decoded.len(),
                decoded_area,
                "Decoded ClearCodec bitmap stream",
            );
        }

        if let Some(glyph_index) = glyph_index {
            self.store_glyph(destination, glyph_index, &decoded)?;
        }

        Ok(decoded)
    }

    fn decode_band(
        &mut self,
        destination: &InclusiveRectangle,
        band: &ClearCodecBand<'_>,
    ) -> Result<DecodedClearCodecRegion> {
        let width = band.header.vbar_count();
        let height = band.header.pixel_height();
        let mut rgba_data = vec![0; width * height * 4];

        for pixel in rgba_data.chunks_exact_mut(4) {
            pixel[0] = band.header.red;
            pixel[1] = band.header.green;
            pixel[2] = band.header.blue;
            pixel[3] = 0xFF;
        }

        for (x, vbar) in band.vbars.iter().enumerate() {
            let full_vbar = self.resolve_vbar(&band.header, vbar)?;

            for row in 0..height {
                let src_offset = row * 3;
                let dst_offset = (row * width + x) * 4;
                rgba_data[dst_offset] = full_vbar[src_offset + 2];
                rgba_data[dst_offset + 1] = full_vbar[src_offset + 1];
                rgba_data[dst_offset + 2] = full_vbar[src_offset];
                rgba_data[dst_offset + 3] = 0xFF;
            }
        }

        Ok(DecodedClearCodecRegion {
            rectangle: InclusiveRectangle {
                left: destination.left.saturating_add(band.header.x_start),
                top: destination.top.saturating_add(band.header.y_start),
                right: destination.left.saturating_add(band.header.x_end),
                bottom: destination.top.saturating_add(band.header.y_end),
            },
            rgba_data,
        })
    }

    fn reset_cache_cursors(&mut self) {
        self.vbar_cursor = 0;
        self.short_vbar_cursor = 0;
    }

    fn decode_glyph_hit(
        &self,
        destination: &InclusiveRectangle,
        glyph_index: u16,
    ) -> Result<Vec<DecodedClearCodecRegion>> {
        let glyph = self
            .glyph_storage
            .get(&glyph_index)
            .context("ClearCodec glyph hit referenced missing glyph")?;

        glyph
            .iter()
            .map(|region| {
                let left = destination.left.saturating_add(region.rectangle.left);
                let top = destination.top.saturating_add(region.rectangle.top);
                let right = destination.left.saturating_add(region.rectangle.right);
                let bottom = destination.top.saturating_add(region.rectangle.bottom);
                Ok(DecodedClearCodecRegion {
                    rectangle: InclusiveRectangle {
                        left,
                        top,
                        right,
                        bottom,
                    },
                    rgba_data: region.rgba_data.clone(),
                })
            })
            .collect()
    }

    fn cache_vbar(&mut self, full_vbar: &[u8]) {
        self.vbar_storage.insert(self.vbar_cursor, full_vbar.to_vec());
        self.vbar_cursor = increment_wrapped_cursor(self.vbar_cursor, CLEARCODEC_VBAR_STORAGE_CAPACITY);
    }

    fn cache_short_vbar(&mut self, short_vbar_pixels: &[u8]) {
        self.short_vbar_storage
            .insert(self.short_vbar_cursor, short_vbar_pixels.to_vec());
        self.short_vbar_cursor =
            increment_wrapped_cursor(self.short_vbar_cursor, CLEARCODEC_SHORT_VBAR_STORAGE_CAPACITY);
    }

    fn store_glyph(
        &mut self,
        destination: &InclusiveRectangle,
        glyph_index: u16,
        decoded: &[DecodedClearCodecRegion],
    ) -> Result<()> {
        if glyph_index >= CLEARCODEC_GLYPH_STORAGE_CAPACITY {
            bail!("ClearCodec glyph index exceeds glyph storage capacity");
        }

        let stored = decoded
            .iter()
            .map(|region| {
                Ok(StoredGlyphRegion {
                    rectangle: InclusiveRectangle {
                        left: region.rectangle.left.saturating_sub(destination.left),
                        top: region.rectangle.top.saturating_sub(destination.top),
                        right: region.rectangle.right.saturating_sub(destination.left),
                        bottom: region.rectangle.bottom.saturating_sub(destination.top),
                    },
                    rgba_data: region.rgba_data.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.glyph_storage.insert(glyph_index, stored);
        Ok(())
    }

    fn resolve_vbar(&mut self, band: &ClearCodecBandHeader, vbar: &ClearCodecVBar<'_>) -> Result<Vec<u8>> {
        let height = band.pixel_height();
        let mut full_vbar = vec![0; height * 3];

        for row in 0..height {
            let offset = row * 3;
            full_vbar[offset] = band.blue;
            full_vbar[offset + 1] = band.green;
            full_vbar[offset + 2] = band.red;
        }

        match vbar {
            ClearCodecVBar::CacheHit { vbar_index } => {
                let cached = self
                    .vbar_storage
                    .get(vbar_index)
                    .context("ClearCodec V-Bar cache hit referenced missing V-Bar")?;
                if cached.len() != full_vbar.len() {
                    bail!(
                        "ClearCodec V-Bar cache hit size mismatch: got {} bytes, expected {}",
                        cached.len(),
                        full_vbar.len()
                    );
                }
                Ok(cached.clone())
            }
            ClearCodecVBar::ShortCacheHit {
                short_vbar_index,
                short_vbar_y_on,
            } => {
                let cached = self
                    .short_vbar_storage
                    .get(short_vbar_index)
                    .context("ClearCodec short V-Bar cache hit referenced missing short V-Bar")?;
                apply_short_vbar(&mut full_vbar, *short_vbar_y_on, cached)?;
                self.cache_vbar(&full_vbar);
                Ok(full_vbar)
            }
            ClearCodecVBar::ShortCacheMiss {
                short_vbar_y_on,
                short_vbar_pixels,
                ..
            } => {
                apply_short_vbar(&mut full_vbar, *short_vbar_y_on, short_vbar_pixels)?;
                self.cache_short_vbar(short_vbar_pixels);
                self.cache_vbar(&full_vbar);
                Ok(full_vbar)
            }
        }
    }
}

pub fn parse_clearcodec_bitmap_stream(input: &[u8]) -> Result<ClearCodecBitmapStream<'_>> {
    if input.len() < 14 {
        bail!("ClearCodec bitmap stream is too short");
    }

    let flags = input[0];
    let sequence_number = input[1];
    let mut offset = 2usize;
    let glyph_index = if flags & CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX != 0 {
        let glyph_index = read_u16_le(input, offset).context("read ClearCodec glyph index")?;
        offset += 2;
        Some(glyph_index)
    } else {
        None
    };

    let residual_byte_count =
        usize::try_from(read_u32_le(input, offset).context("read ClearCodec residual byte count")?)
            .context("ClearCodec residual byte count does not fit usize")?;
    offset += 4;
    let bands_byte_count = usize::try_from(read_u32_le(input, offset).context("read ClearCodec bands byte count")?)
        .context("ClearCodec bands byte count does not fit usize")?;
    offset += 4;
    let subcodec_byte_count =
        usize::try_from(read_u32_le(input, offset).context("read ClearCodec subcodec byte count")?)
            .context("ClearCodec subcodec byte count does not fit usize")?;
    offset += 4;

    let expected_len = offset
        .checked_add(residual_byte_count)
        .and_then(|value| value.checked_add(bands_byte_count))
        .and_then(|value| value.checked_add(subcodec_byte_count))
        .context("ClearCodec composite payload length overflow")?;

    if input.len() != expected_len {
        bail!(
            "ClearCodec bitmap stream size mismatch: got {} bytes, expected {}",
            input.len(),
            expected_len
        );
    }

    let residual_end = offset + residual_byte_count;
    let bands_end = residual_end + bands_byte_count;
    let residual_data = &input[offset..residual_end];
    let bands_data = &input[residual_end..bands_end];
    let subcodec_data = &input[bands_end..];

    Ok(ClearCodecBitmapStream {
        flags,
        sequence_number,
        glyph_index,
        composite_payload: ClearCodecCompositePayload {
            residual_data,
            bands_data,
            subcodec_data,
        },
    })
}

pub fn parse_clearcodec_bands_data(input: &[u8]) -> Result<Vec<ClearCodecBand<'_>>> {
    let mut bands = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let header = parse_clearcodec_band_header(&input[offset..]).context("parse ClearCodec band header")?;
        offset += CLEARCODEC_BAND_HEADER_LEN;

        let mut vbars = Vec::with_capacity(header.vbar_count());
        for _ in 0..header.vbar_count() {
            let header_word = read_u16_le(input, offset).context("read ClearCodec V-Bar header")?;
            if header_word & 0x8000 != 0 {
                vbars.push(ClearCodecVBar::CacheHit {
                    vbar_index: header_word & 0x7FFF,
                });
                offset += 2;
                continue;
            }

            let short_kind = header_word >> 14;
            match short_kind {
                0 => {
                    let short_vbar_y_on = input.get(offset).copied().context("read ClearCodec short V-Bar yOn")?;
                    let short_vbar_y_off = input
                        .get(offset + 1)
                        .copied()
                        .context("read ClearCodec short V-Bar yOff")?
                        & 0x3F;
                    if short_vbar_y_off < short_vbar_y_on {
                        bail!(
                            "ClearCodec short V-Bar y range is invalid: yOn={} yOff={}",
                            short_vbar_y_on,
                            short_vbar_y_off
                        );
                    }
                    let pixel_len = usize::from(short_vbar_y_off.saturating_sub(short_vbar_y_on))
                        .checked_mul(3)
                        .context("ClearCodec short V-Bar pixel length overflow")?;
                    let short_vbar_pixels = input
                        .get(offset + 2..offset + 2 + pixel_len)
                        .context("ClearCodec short V-Bar pixel data extends past end of bands payload")?;
                    vbars.push(ClearCodecVBar::ShortCacheMiss {
                        short_vbar_y_on,
                        short_vbar_y_off,
                        short_vbar_pixels,
                    });
                    offset += 2 + pixel_len;
                }
                1 => {
                    let short_vbar_y_on = input
                        .get(offset + 2)
                        .copied()
                        .context("read ClearCodec short V-Bar cache-hit yOn")?;
                    vbars.push(ClearCodecVBar::ShortCacheHit {
                        short_vbar_index: header_word & 0x3FFF,
                        short_vbar_y_on,
                    });
                    offset += 3;
                }
                unsupported => bail!("ClearCodec V-Bar kind {unsupported} is not implemented"),
            }
        }

        bands.push(ClearCodecBand { header, vbars });
    }

    Ok(bands)
}

pub fn parse_clearcodec_band_header(input: &[u8]) -> Result<ClearCodecBandHeader> {
    if input.len() < CLEARCODEC_BAND_HEADER_LEN {
        bail!("ClearCodec band header is too short");
    }

    Ok(ClearCodecBandHeader {
        x_start: read_u16_le(input, 0).context("read ClearCodec band xStart")?,
        x_end: read_u16_le(input, 2).context("read ClearCodec band xEnd")?,
        y_start: read_u16_le(input, 4).context("read ClearCodec band yStart")?,
        y_end: read_u16_le(input, 6).context("read ClearCodec band yEnd")?,
        blue: input[8],
        green: input[9],
        red: input[10],
    })
}

fn apply_short_vbar(full_vbar: &mut [u8], short_vbar_y_on: u8, short_vbar_pixels: &[u8]) -> Result<()> {
    if short_vbar_pixels.len() % 3 != 0 {
        bail!(
            "ClearCodec short V-Bar pixel data size must be a multiple of 3, got {}",
            short_vbar_pixels.len()
        );
    }

    let row_offset = usize::from(short_vbar_y_on)
        .checked_mul(3)
        .context("ClearCodec short V-Bar row offset overflow")?;
    let end = row_offset
        .checked_add(short_vbar_pixels.len())
        .context("ClearCodec short V-Bar write end overflow")?;
    if end > full_vbar.len() {
        bail!(
            "ClearCodec short V-Bar extends past band height: end={} band_bytes={}",
            end,
            full_vbar.len()
        );
    }

    full_vbar[row_offset..end].copy_from_slice(short_vbar_pixels);
    Ok(())
}

#[cfg(all(test, target_os = "none"))]
fn decode_clearcodec_residual_to_rgba(residual_data: &[u8], width: usize, height: usize) -> Result<Vec<u8>> {
    let expected_pixels = width
        .checked_mul(height)
        .context("ClearCodec residual pixel count overflow")?;
    let decoded = parse_clearcodec_residual_data(residual_data, expected_pixels)?;
    if decoded.decoded_pixels != expected_pixels {
        bail!(
            "ClearCodec residual decoded {} pixels, expected {}",
            decoded.decoded_pixels,
            expected_pixels
        );
    }

    let (rgba_data, _) = decode_clearcodec_residual_prefix_to_rgba(residual_data, width, height)?;
    Ok(rgba_data)
}

fn decode_clearcodec_residual_prefix_to_rgba(
    residual_data: &[u8],
    width: usize,
    height: usize,
) -> Result<(Vec<u8>, usize)> {
    let expected_pixels = width
        .checked_mul(height)
        .context("ClearCodec residual pixel count overflow")?;
    let decoded = parse_clearcodec_residual_data(residual_data, expected_pixels)?;

    let mut rgba_data = vec![
        0;
        expected_pixels
            .checked_mul(4)
            .context("ClearCodec residual RGBA byte count overflow")?
    ];

    let mut pixel_index = 0usize;
    for segment in decoded.segments {
        for _ in 0..segment.run_length {
            let offset = pixel_index
                .checked_mul(4)
                .context("ClearCodec residual RGBA offset overflow")?;
            rgba_data[offset] = segment.red;
            rgba_data[offset + 1] = segment.green;
            rgba_data[offset + 2] = segment.blue;
            rgba_data[offset + 3] = 0xFF;
            pixel_index += 1;
        }
    }

    Ok((rgba_data, decoded.decoded_pixels))
}

fn combined_clearcodec_coverage_is_exact<I>(
    destination: &InclusiveRectangle,
    residual_pixels: usize,
    regions: I,
) -> Result<bool>
where
    I: IntoIterator,
    I::Item: Borrow<DecodedClearCodecRegion>,
{
    let width = usize::from(destination.right.saturating_sub(destination.left)) + 1;
    let height = usize::from(destination.bottom.saturating_sub(destination.top)) + 1;
    let expected_pixels = width
        .checked_mul(height)
        .context("ClearCodec coverage pixel count overflow")?;
    if residual_pixels > expected_pixels {
        bail!(
            "ClearCodec residual coverage exceeds destination size: residual_pixels={} expected_pixels={}",
            residual_pixels,
            expected_pixels
        );
    }

    let mut covered = vec![false; expected_pixels];
    for slot in covered.iter_mut().take(residual_pixels) {
        *slot = true;
    }

    for region in regions {
        let region = region.borrow();
        let region_left = usize::from(region.rectangle.left.saturating_sub(destination.left));
        let region_top = usize::from(region.rectangle.top.saturating_sub(destination.top));
        let region_width = usize::from(region.rectangle.right.saturating_sub(region.rectangle.left)) + 1;
        let region_height = usize::from(region.rectangle.bottom.saturating_sub(region.rectangle.top)) + 1;

        for row in 0..region_height {
            let dest_row = region_top
                .checked_add(row)
                .context("ClearCodec coverage row overflow")?;
            let row_start = dest_row
                .checked_mul(width)
                .and_then(|base| base.checked_add(region_left))
                .context("ClearCodec coverage row start overflow")?;
            let row_end = row_start
                .checked_add(region_width)
                .context("ClearCodec coverage row end overflow")?;
            if row_end > covered.len() {
                bail!(
                    "ClearCodec region coverage exceeds destination bounds: row_end={} destination_pixels={}",
                    row_end,
                    covered.len()
                );
            }

            for slot in &mut covered[row_start..row_end] {
                *slot = true;
            }
        }
    }

    Ok(covered.into_iter().all(|pixel| pixel))
}

pub fn parse_clearcodec_subcodecs_data(input: &[u8]) -> Result<Vec<ClearCodecSubcodec<'_>>> {
    let mut subcodecs = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let x_start = read_u16_le(input, offset).context("read ClearCodec subcodec xStart")?;
        let y_start = read_u16_le(input, offset + 2).context("read ClearCodec subcodec yStart")?;
        let width = read_u16_le(input, offset + 4).context("read ClearCodec subcodec width")?;
        let height = read_u16_le(input, offset + 6).context("read ClearCodec subcodec height")?;
        let bitmap_data_byte_count =
            usize::try_from(read_u32_le(input, offset + 8).context("read ClearCodec subcodec bitmapDataByteCount")?)
                .context("ClearCodec subcodec bitmapDataByteCount does not fit usize")?;
        let subcodec_id = *input.get(offset + 12).context("read ClearCodec subcodec subCodecId")?;
        offset += 13;

        let bitmap_data = input
            .get(offset..offset + bitmap_data_byte_count)
            .context("ClearCodec subcodec bitmap data extends past end of payload")?;
        offset += bitmap_data_byte_count;

        if subcodec_id == 0x00 {
            let max_bitmap_data_len = usize::from(width)
                .checked_mul(usize::from(height))
                .and_then(|pixels| pixels.checked_mul(3))
                .context("ClearCodec subcodec bitmap capacity overflow")?;
            if bitmap_data.len() > max_bitmap_data_len {
                bail!(
                    "ClearCodec subcodec bitmapDataByteCount exceeds raw capacity: got {} bytes, max {}",
                    bitmap_data.len(),
                    max_bitmap_data_len
                );
            }
        }

        subcodecs.push(ClearCodecSubcodec {
            x_start,
            y_start,
            width,
            height,
            subcodec_id,
            bitmap_data,
        });
    }

    Ok(subcodecs)
}

fn decode_clearcodec_subcodec_to_region(
    destination: &InclusiveRectangle,
    subcodec: &ClearCodecSubcodec<'_>,
) -> Result<DecodedClearCodecRegion> {
    match subcodec.subcodec_id {
        0x00 => decode_clearcodec_raw_subcodec_to_region(destination, subcodec),
        0x01 => decode_clearcodec_nsc_subcodec_to_region(destination, subcodec),
        0x02 => decode_clearcodec_rlex_subcodec_to_region(destination, subcodec),
        unsupported => bail!("ClearCodec subcodec id {unsupported} is not implemented"),
    }
}

fn decode_clearcodec_raw_subcodec_to_region(
    destination: &InclusiveRectangle,
    subcodec: &ClearCodecSubcodec<'_>,
) -> Result<DecodedClearCodecRegion> {
    let width = usize::from(subcodec.width);
    let height = usize::from(subcodec.height);
    let expected_bitmap_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(3))
        .context("ClearCodec raw subcodec bitmap size overflow")?;
    if subcodec.bitmap_data.len() != expected_bitmap_len {
        bail!(
            "ClearCodec raw subcodec bitmap size mismatch: got {} bytes, expected {}",
            subcodec.bitmap_data.len(),
            expected_bitmap_len
        );
    }

    let mut rgba_data = Vec::with_capacity(
        width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .context("ClearCodec raw subcodec RGBA size overflow")?,
    );
    for pixel in subcodec.bitmap_data.chunks_exact(3) {
        rgba_data.extend_from_slice(&[pixel[2], pixel[1], pixel[0], 0xFF]);
    }

    Ok(DecodedClearCodecRegion {
        rectangle: clearcodec_subcodec_rectangle(destination, subcodec),
        rgba_data,
    })
}

fn decode_clearcodec_rlex_subcodec_to_region(
    destination: &InclusiveRectangle,
    subcodec: &ClearCodecSubcodec<'_>,
) -> Result<DecodedClearCodecRegion> {
    if subcodec.bitmap_data.is_empty() {
        bail!("ClearCodec RLEX subcodec payload is too short");
    }

    let palette_count = subcodec.bitmap_data[0];
    if palette_count > 0x7F {
        bail!("ClearCodec RLEX paletteCount exceeds 0x7F");
    }
    if palette_count < 2 {
        bail!("ClearCodec RLEX paletteCount must be at least 2");
    }

    let palette_len = usize::from(palette_count)
        .checked_mul(3)
        .context("ClearCodec RLEX palette byte count overflow")?;
    let palette_end = 1usize
        .checked_add(palette_len)
        .context("ClearCodec RLEX palette end overflow")?;
    let palette_data = subcodec
        .bitmap_data
        .get(1..palette_end)
        .context("ClearCodec RLEX palette extends past end of payload")?;

    let mut palette = Vec::with_capacity(usize::from(palette_count));
    for entry in palette_data.chunks_exact(3) {
        palette.push([entry[0], entry[1], entry[2]]);
    }

    let width = usize::from(subcodec.width);
    let height = usize::from(subcodec.height);
    let expected_pixels = width
        .checked_mul(height)
        .context("ClearCodec RLEX pixel count overflow")?;
    let mut rgba_data = Vec::with_capacity(
        expected_pixels
            .checked_mul(4)
            .context("ClearCodec RLEX RGBA size overflow")?,
    );

    let stop_index_bits = clearcodec_rlex_stop_index_bit_count(palette_count);
    let stop_index_mask = (1u8 << stop_index_bits) - 1;
    let mut offset = palette_end;
    let mut decoded_pixels = 0usize;

    while offset < subcodec.bitmap_data.len() && decoded_pixels < expected_pixels {
        let encoded_segment = *subcodec
            .bitmap_data
            .get(offset)
            .context("read ClearCodec RLEX segment header")?;
        offset += 1;

        let stop_index = encoded_segment & stop_index_mask;
        let suite_depth = encoded_segment >> stop_index_bits;
        if stop_index >= palette_count {
            bail!(
                "ClearCodec RLEX stopIndex {} exceeds palette size {}",
                stop_index,
                palette_count
            );
        }
        if suite_depth > stop_index {
            bail!(
                "ClearCodec RLEX suiteDepth {} exceeds stopIndex {}",
                suite_depth,
                stop_index
            );
        }

        let run_length = parse_clearcodec_variable_run_length(subcodec.bitmap_data, &mut offset, "ClearCodec RLEX")?;
        let start_index = stop_index - suite_depth;
        let segment_pixels = run_length
            .checked_add(usize::from(suite_depth))
            .and_then(|value| value.checked_add(1))
            .context("ClearCodec RLEX segment pixel count overflow")?;
        decoded_pixels = decoded_pixels
            .checked_add(segment_pixels)
            .context("ClearCodec RLEX decoded pixel count overflow")?;
        if decoded_pixels > expected_pixels {
            bail!(
                "ClearCodec RLEX decoded {} pixels, expected {}",
                decoded_pixels,
                expected_pixels
            );
        }

        let start_color = palette[usize::from(start_index)];
        for _ in 0..run_length {
            rgba_data.extend_from_slice(&[start_color[2], start_color[1], start_color[0], 0xFF]);
        }

        for palette_index in start_index..=stop_index {
            let color = palette[usize::from(palette_index)];
            rgba_data.extend_from_slice(&[color[2], color[1], color[0], 0xFF]);
        }
    }

    if decoded_pixels != expected_pixels {
        bail!(
            "ClearCodec RLEX decoded {} pixels, expected {}",
            decoded_pixels,
            expected_pixels
        );
    }
    if offset != subcodec.bitmap_data.len() {
        bail!(
            "ClearCodec RLEX data has {} trailing bytes after decoding {} pixels",
            subcodec.bitmap_data.len().saturating_sub(offset),
            expected_pixels
        );
    }

    Ok(DecodedClearCodecRegion {
        rectangle: clearcodec_subcodec_rectangle(destination, subcodec),
        rgba_data,
    })
}

fn decode_clearcodec_nsc_subcodec_to_region(
    destination: &InclusiveRectangle,
    subcodec: &ClearCodecSubcodec<'_>,
) -> Result<DecodedClearCodecRegion> {
    Ok(DecodedClearCodecRegion {
        rectangle: clearcodec_subcodec_rectangle(destination, subcodec),
        rgba_data: decode_nsc_bitmap_to_rgba(subcodec.width, subcodec.height, subcodec.bitmap_data)?,
    })
}

fn clearcodec_subcodec_rectangle(
    destination: &InclusiveRectangle,
    subcodec: &ClearCodecSubcodec<'_>,
) -> InclusiveRectangle {
    InclusiveRectangle {
        left: destination.left.saturating_add(subcodec.x_start),
        top: destination.top.saturating_add(subcodec.y_start),
        right: destination
            .left
            .saturating_add(subcodec.x_start)
            .saturating_add(subcodec.width.saturating_sub(1)),
        bottom: destination
            .top
            .saturating_add(subcodec.y_start)
            .saturating_add(subcodec.height.saturating_sub(1)),
    }
}

fn blit_region_into_surface(
    surface_rgba: &mut [u8],
    surface_width: usize,
    surface_rectangle: &InclusiveRectangle,
    region_rectangle: &InclusiveRectangle,
    region_rgba: &[u8],
) -> Result<()> {
    let region_width = usize::from(region_rectangle.right.saturating_sub(region_rectangle.left)) + 1;
    let region_height = usize::from(region_rectangle.bottom.saturating_sub(region_rectangle.top)) + 1;
    let expected_region_len = region_width
        .checked_mul(region_height)
        .and_then(|pixels| pixels.checked_mul(4))
        .context("ClearCodec blit region byte count overflow")?;
    if region_rgba.len() != expected_region_len {
        bail!(
            "ClearCodec blit region size mismatch: got {} bytes, expected {}",
            region_rgba.len(),
            expected_region_len
        );
    }

    let offset_x = usize::from(region_rectangle.left.saturating_sub(surface_rectangle.left));
    let offset_y = usize::from(region_rectangle.top.saturating_sub(surface_rectangle.top));
    for row in 0..region_height {
        let src_offset = row
            .checked_mul(region_width)
            .and_then(|pixels| pixels.checked_mul(4))
            .context("ClearCodec blit source offset overflow")?;
        let dst_offset = offset_y
            .checked_add(row)
            .and_then(|surface_row| surface_row.checked_mul(surface_width))
            .and_then(|pixels| pixels.checked_add(offset_x))
            .and_then(|pixels| pixels.checked_mul(4))
            .context("ClearCodec blit destination offset overflow")?;
        let len = region_width
            .checked_mul(4)
            .context("ClearCodec blit row length overflow")?;
        let dst_end = dst_offset
            .checked_add(len)
            .context("ClearCodec blit destination end overflow")?;
        if dst_end > surface_rgba.len() {
            bail!(
                "ClearCodec blit region exceeds destination surface: end={} surface_bytes={}",
                dst_end,
                surface_rgba.len()
            );
        }
        surface_rgba[dst_offset..dst_end].copy_from_slice(&region_rgba[src_offset..src_offset + len]);
    }

    Ok(())
}

pub fn parse_clearcodec_residual_data(input: &[u8], expected_pixels: usize) -> Result<DecodedClearCodecResidual> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    let mut decoded_pixels = 0usize;

    while offset < input.len() && decoded_pixels < expected_pixels {
        let blue = *input.get(offset).context("read ClearCodec residual blueValue")?;
        let green = *input.get(offset + 1).context("read ClearCodec residual greenValue")?;
        let red = *input.get(offset + 2).context("read ClearCodec residual redValue")?;
        offset += 3;
        let run_length = parse_clearcodec_variable_run_length(input, &mut offset, "ClearCodec residual")?;

        if run_length == 0 {
            bail!("ClearCodec residual run length must be non-zero");
        }

        decoded_pixels = decoded_pixels
            .checked_add(run_length)
            .context("ClearCodec residual decoded pixel count overflow")?;
        if decoded_pixels > expected_pixels {
            bail!(
                "ClearCodec residual decoded {} pixels, expected {}",
                decoded_pixels,
                expected_pixels
            );
        }

        segments.push(ClearCodecRgbRunSegment {
            blue,
            green,
            red,
            run_length,
        });
    }

    if offset != input.len() {
        bail!(
            "ClearCodec residual data has {} trailing bytes after decoding {} pixels",
            input.len().saturating_sub(offset),
            expected_pixels
        );
    }

    Ok(DecodedClearCodecResidual {
        segments,
        decoded_pixels,
    })
}

fn parse_clearcodec_variable_run_length(input: &[u8], offset: &mut usize, label: &str) -> Result<usize> {
    let run_length_factor_1 = *input
        .get(*offset)
        .with_context(|| format!("read {label} runLengthFactor1"))?;
    *offset += 1;

    if run_length_factor_1 < 0xFF {
        return Ok(usize::from(run_length_factor_1));
    }

    let run_length_factor_2 = read_u16_le(input, *offset).with_context(|| format!("read {label} runLengthFactor2"))?;
    *offset += 2;
    if run_length_factor_2 < 0xFFFF {
        return Ok(usize::from(run_length_factor_2));
    }

    let run_length_factor_3 = read_u32_le(input, *offset).with_context(|| format!("read {label} runLengthFactor3"))?;
    *offset += 4;
    usize::try_from(run_length_factor_3).with_context(|| format!("{label} runLengthFactor3 does not fit usize"))
}

fn clearcodec_rlex_stop_index_bit_count(palette_count: u8) -> u8 {
    debug_assert!(palette_count >= 2);
    let max_palette_index = palette_count - 1;
    (u8::BITS - max_palette_index.leading_zeros()) as u8
}

fn read_u16_le(input: &[u8], offset: usize) -> Result<u16> {
    let bytes = input
        .get(offset..offset + 2)
        .context("u16 field extends past end of ClearCodec buffer")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input
        .get(offset..offset + 4)
        .context("u32 field extends past end of ClearCodec buffer")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn increment_wrapped_cursor(cursor: u16, capacity: u16) -> u16 {
    let next = u32::from(cursor) + 1;
    if next >= u32::from(capacity) { 0 } else { next as u16 }
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use super::*;

    const LOCAL_IRONRDP_CLEARCODEC_BITMAP_DATA: &[u8] = &[
        0x01, 0x0E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x3F, 0x27, 0x19, 0x82, 0x72, 0x69, 0x40,
        0x28, 0x1A, 0x3F, 0x27, 0x19, 0x40, 0x28, 0x1A, 0x41, 0x29, 0x1B, 0x4F, 0x39, 0x2C, 0xA0, 0x94, 0x8D, 0xC0,
        0xB8, 0xB3, 0x00, 0x09, 0xD8, 0xD3, 0xD0, 0x97, 0x8A, 0x82, 0x40, 0x28, 0x1A, 0x41, 0x29, 0x1B, 0x3F, 0x27,
        0x19, 0x4F, 0x39, 0x2C, 0xDF, 0xDB, 0xD9, 0xD8, 0xD3, 0xD0, 0xFF, 0xFF, 0xFF, 0x00, 0x09, 0xFF, 0xFF, 0xFF,
        0x3F, 0x27, 0x19, 0x41, 0x29, 0x1B, 0x40, 0x28, 0x1A, 0x40, 0x28, 0x1A, 0xE5, 0xE1, 0xE0, 0x81, 0x71, 0x68,
        0x40, 0x28, 0x1A, 0xFF, 0xFF, 0xFF, 0x00, 0x09, 0xFF, 0xFF, 0xFF, 0x60, 0x4B, 0x40, 0x4F, 0x39, 0x2C, 0x60,
        0x4B, 0x40, 0xD8, 0xD3, 0xD0, 0xC0, 0xB8, 0xB3, 0x43, 0x2B, 0x1D, 0x3F, 0x27, 0x19, 0xFF, 0xFF, 0xFF, 0x00,
        0x09, 0xC0, 0xB8, 0xB3, 0xEF, 0xED, 0xEB, 0xDF, 0xDB, 0xD9, 0xEA, 0xE7, 0xE6, 0xC0, 0xB8, 0xB3, 0x41, 0x29,
        0x1B, 0x41, 0x29, 0x1B, 0x42, 0x2A, 0x1C, 0xFF, 0xFF, 0xFF, 0x00, 0x09, 0x41, 0x29, 0x1B, 0x81, 0x71, 0x68,
        0x80, 0x71, 0x67, 0x5F, 0x4B, 0x3F, 0x40, 0x28, 0x1A, 0x42, 0x2A, 0x1C, 0x40, 0x28, 0x1A, 0x3F, 0x27, 0x19,
        0xC0, 0xB8, 0xB3,
    ];

    const LOCAL_IRONRDP_CLEARCODEC_DESTINATION: InclusiveRectangle = InclusiveRectangle {
        left: 933,
        top: 734,
        right: 939,
        bottom: 743,
    };

    const OFFICIAL_RLEX_EXAMPLE_2_BITMAP_DATA: &[u8] = &[
        0x0E, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xDB, 0xFF, 0xFF, 0x00, 0x3A, 0x90, 0xFF, 0xB6, 0x66, 0x66, 0xB6,
        0xFF, 0xB6, 0x66, 0x00, 0x90, 0xDB, 0xFF, 0x00, 0x00, 0x3A, 0xDB, 0x90, 0x3A, 0x3A, 0x90, 0xDB, 0x66, 0x00,
        0x00, 0xFF, 0xFF, 0xB6, 0x64, 0x64, 0x64, 0x11, 0x04, 0x11, 0x4C, 0x11, 0x4C, 0x11, 0x4C, 0x11, 0x4C, 0x11,
        0x4C, 0x00, 0x47, 0x13, 0x00, 0x01, 0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x47, 0x16, 0x00, 0x11, 0x02, 0x00,
        0x47, 0x29, 0x00, 0x11, 0x01, 0x00, 0x49, 0x0A, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x4A, 0x0A,
        0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x47, 0x05, 0x00, 0x01, 0x01, 0x1C, 0x00, 0x01, 0x00, 0x11, 0x4C, 0x11,
        0x4C, 0x11, 0x4C, 0x00, 0x47, 0x0D, 0x4D, 0x00, 0x4D,
    ];

    fn encode_bitmap_stream(
        flags: u8,
        glyph_index: Option<u16>,
        bands_data: &[u8],
        residual_data: &[u8],
        subcodec_data: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![flags, 0x0E];
        if let Some(glyph_index) = glyph_index {
            out.extend_from_slice(&glyph_index.to_le_bytes());
        }
        out.extend_from_slice(&(residual_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(bands_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(subcodec_data.len() as u32).to_le_bytes());
        out.extend_from_slice(residual_data);
        out.extend_from_slice(bands_data);
        out.extend_from_slice(subcodec_data);
        out
    }

    fn encode_subcodec_payload(
        x_start: u16,
        y_start: u16,
        width: u16,
        height: u16,
        subcodec_id: u8,
        bitmap_data: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&x_start.to_le_bytes());
        out.extend_from_slice(&y_start.to_le_bytes());
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&(bitmap_data.len() as u32).to_le_bytes());
        out.push(subcodec_id);
        out.extend_from_slice(bitmap_data);
        out
    }

    fn encode_nsc_bitmap(plane_payloads: [&[u8]; 4], color_loss_level: u8, chroma_subsampling: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for plane_payload in plane_payloads {
            out.extend_from_slice(&(plane_payload.len() as u32).to_le_bytes());
        }
        out.push(color_loss_level);
        out.push(u8::from(chroma_subsampling));
        out.extend_from_slice(&[0, 0]);
        for plane_payload in plane_payloads {
            out.extend_from_slice(plane_payload);
        }
        out
    }

    fn rgba_pixel(region: &DecodedClearCodecRegion, width: usize, x: usize, y: usize) -> [u8; 4] {
        let offset = ((y * width) + x) * 4;
        [
            region.rgba_data[offset],
            region.rgba_data[offset + 1],
            region.rgba_data[offset + 2],
            region.rgba_data[offset + 3],
        ]
    }

    fn encode_band_short_cache_hit(
        x_start: u16,
        y_start: u16,
        width: u16,
        height: u16,
        background_bgr: [u8; 3],
        short_vbar_index: u16,
        short_vbar_y_on: u8,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&x_start.to_le_bytes());
        out.extend_from_slice(&(x_start + width - 1).to_le_bytes());
        out.extend_from_slice(&y_start.to_le_bytes());
        out.extend_from_slice(&(y_start + height - 1).to_le_bytes());
        out.push(background_bgr[0]);
        out.push(background_bgr[1]);
        out.push(background_bgr[2]);
        out.extend_from_slice(&(0x4000u16 | short_vbar_index).to_le_bytes());
        out.push(short_vbar_y_on);
        out
    }

    fn encode_band_short_misses(
        x_start: u16,
        y_start: u16,
        width: u16,
        height: u16,
        background_bgr: [u8; 3],
        short_vbars: &[&[u8]],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&x_start.to_le_bytes());
        out.extend_from_slice(&(x_start + width - 1).to_le_bytes());
        out.extend_from_slice(&y_start.to_le_bytes());
        out.extend_from_slice(&(y_start + height - 1).to_le_bytes());
        out.push(background_bgr[0]);
        out.push(background_bgr[1]);
        out.push(background_bgr[2]);

        for short_vbar in short_vbars {
            let pixel_rows = short_vbar.len() / 3;
            assert_eq!(short_vbar.len() % 3, 0);
            out.push(0);
            out.push(u8::try_from(pixel_rows).expect("pixel rows fit u8"));
            out.extend_from_slice(short_vbar);
        }

        out
    }

    #[test]
    fn parse_clearcodec_bitmap_stream_handles_glyph_index_and_bands_only_shape() {
        let bands_data = vec![0; 0xB9];
        let bitmap_data = encode_bitmap_stream(
            CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX,
            Some(3),
            &bands_data,
            &[],
            &[],
        );

        let parsed = parse_clearcodec_bitmap_stream(&bitmap_data).expect("parse ClearCodec bitmap stream");

        assert_eq!(parsed.flags, CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX);
        assert_eq!(parsed.sequence_number, 0x0E);
        assert_eq!(parsed.glyph_index, Some(3));
        assert!(parsed.composite_payload.residual_data.is_empty());
        assert_eq!(parsed.composite_payload.bands_data.len(), 0xB9);
        assert!(parsed.composite_payload.subcodec_data.is_empty());
    }

    #[test]
    fn parse_clearcodec_band_header_matches_local_fixture_prefix() {
        let header = parse_clearcodec_band_header(&[0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
            .expect("parse band header");

        assert_eq!(
            header,
            ClearCodecBandHeader {
                x_start: 0,
                x_end: 5,
                y_start: 0,
                y_end: 8,
                blue: 0,
                green: 0,
                red: 0,
            }
        );
        assert_eq!(header.vbar_count(), 6);
        assert_eq!(header.pixel_height(), 9);
    }

    #[test]
    fn parse_clearcodec_bands_data_reads_short_vbar_misses() {
        let bands_data =
            encode_band_short_misses(0, 0, 2, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6], &[7, 8, 9, 10, 11, 12]]);

        let bands = parse_clearcodec_bands_data(&bands_data).expect("parse bands data");

        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].vbars.len(), 2);
        assert!(matches!(
            &bands[0].vbars[0],
            ClearCodecVBar::ShortCacheMiss {
                short_vbar_y_on: 0,
                short_vbar_y_off: 2,
                short_vbar_pixels,
            } if *short_vbar_pixels == [1, 2, 3, 4, 5, 6]
        ));
    }

    #[test]
    fn decode_clearcodec_short_miss_band_yields_rgba_region() {
        let bands_data =
            encode_band_short_misses(0, 0, 2, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6], &[7, 8, 9, 10, 11, 12]]);
        let bitmap_data = encode_bitmap_stream(0, None, &bands_data, &[], &[]);
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 11,
            bottom: 21,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let decoded = decoders
            .decode_wire_to_surface_1(1, &destination, &bitmap_data)
            .expect("decode ClearCodec short misses");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(
            decoded[0].rgba_data,
            vec![3, 2, 1, 255, 9, 8, 7, 255, 6, 5, 4, 255, 12, 11, 10, 255,]
        );
    }

    #[test]
    fn decode_clearcodec_cache_hit_reuses_stored_vbar() {
        let first_band = encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6]]);
        let first_bitmap = encode_bitmap_stream(0, None, &first_band, &[], &[]);
        let mut decoders = SurfaceClearCodecDecoders::default();
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 1,
        };
        decoders
            .decode_wire_to_surface_1(7, &destination, &first_bitmap)
            .expect("prime ClearCodec V-Bar cache");

        let mut cache_hit_band = Vec::new();
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&1u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&[0, 0, 0]);
        cache_hit_band.extend_from_slice(&(0x8000u16).to_le_bytes());
        let cache_hit_bitmap = encode_bitmap_stream(0, None, &cache_hit_band, &[], &[]);

        let decoded = decoders
            .decode_wire_to_surface_1(7, &destination, &cache_hit_bitmap)
            .expect("decode ClearCodec cache hit");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rgba_data, vec![3, 2, 1, 255, 6, 5, 4, 255]);
    }

    #[test]
    fn decode_clearcodec_short_cache_hit_reuses_stored_short_vbar() {
        let first_band = encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6]]);
        let first_bitmap = encode_bitmap_stream(0, None, &first_band, &[], &[]);
        let mut decoders = SurfaceClearCodecDecoders::default();
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 1,
        };
        decoders
            .decode_wire_to_surface_1(9, &destination, &first_bitmap)
            .expect("prime ClearCodec short V-Bar cache");

        let short_hit_band = encode_band_short_cache_hit(0, 0, 1, 2, [0, 0, 0], 0, 0);
        let short_hit_bitmap = encode_bitmap_stream(0, None, &short_hit_band, &[], &[]);

        let decoded = decoders
            .decode_wire_to_surface_1(9, &destination, &short_hit_bitmap)
            .expect("decode ClearCodec short cache hit");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rgba_data, vec![3, 2, 1, 255, 6, 5, 4, 255]);

        let decoder = decoders.contexts.get(&9).expect("surface decoder exists");
        assert_eq!(decoder.vbar_cursor, 2);
        assert_eq!(decoder.short_vbar_cursor, 1);
        assert_eq!(decoder.vbar_storage.len(), 2);
        assert_eq!(decoder.short_vbar_storage.len(), 1);
    }

    #[test]
    fn decode_clearcodec_local_ironrdp_fixture_yields_expected_band_region() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let bitmap_stream = parse_clearcodec_bitmap_stream(LOCAL_IRONRDP_CLEARCODEC_BITMAP_DATA)
            .expect("parse local IronRDP ClearCodec fixture");
        let bands = parse_clearcodec_bands_data(bitmap_stream.composite_payload.bands_data)
            .expect("parse local IronRDP ClearCodec bands");

        assert_eq!(bitmap_stream.flags, CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX);
        assert_eq!(bitmap_stream.sequence_number, 0x0E);
        assert_eq!(bitmap_stream.glyph_index, Some(3));
        assert!(bitmap_stream.composite_payload.residual_data.is_empty());
        assert!(bitmap_stream.composite_payload.subcodec_data.is_empty());
        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].vbars.len(), 6);
        assert!(bands[0].vbars.iter().all(|vbar| matches!(
            vbar,
            ClearCodecVBar::ShortCacheMiss {
                short_vbar_y_on: 0,
                short_vbar_y_off: 9,
                ..
            }
        )));

        let decoded = decoders
            .decode_wire_to_surface_1(
                0,
                &LOCAL_IRONRDP_CLEARCODEC_DESTINATION,
                LOCAL_IRONRDP_CLEARCODEC_BITMAP_DATA,
            )
            .expect("decode local IronRDP ClearCodec fixture");

        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].rectangle,
            InclusiveRectangle {
                left: 933,
                top: 734,
                right: 938,
                bottom: 742,
            }
        );
        assert_eq!(decoded[0].rgba_data.len(), 6 * 9 * 4);

        let decoder = decoders.contexts.get(&0).expect("surface decoder exists");
        let glyph = decoder.glyph_storage.get(&3).expect("glyph stored");
        assert_eq!(glyph.len(), 1);
        assert_eq!(
            glyph[0].rectangle,
            InclusiveRectangle {
                left: 0,
                top: 0,
                right: 5,
                bottom: 8,
            }
        );
        assert_eq!(glyph[0].rgba_data.len(), 6 * 9 * 4);
    }

    #[test]
    fn decode_clearcodec_glyph_hit_reuses_stored_glyph_at_new_destination() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        decoders
            .decode_wire_to_surface_1(
                0,
                &LOCAL_IRONRDP_CLEARCODEC_DESTINATION,
                LOCAL_IRONRDP_CLEARCODEC_BITMAP_DATA,
            )
            .expect("prime glyph storage from local fixture");

        let glyph_hit_bitmap = encode_bitmap_stream(
            CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX | CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_HIT,
            Some(3),
            &[],
            &[],
            &[],
        );
        let replay_destination = InclusiveRectangle {
            left: 100,
            top: 200,
            right: 106,
            bottom: 209,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &replay_destination, &glyph_hit_bitmap)
            .expect("decode glyph-hit stream");

        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].rectangle,
            InclusiveRectangle {
                left: 100,
                top: 200,
                right: 105,
                bottom: 208,
            }
        );
        assert_eq!(decoded[0].rgba_data.len(), 6 * 9 * 4);
    }

    #[test]
    fn decode_clearcodec_glyph_hit_requires_stored_glyph() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let glyph_hit_bitmap = encode_bitmap_stream(
            CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX | CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_HIT,
            Some(3),
            &[],
            &[],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 6,
            bottom: 9,
        };

        let error = decoders
            .decode_wire_to_surface_1(0, &destination, &glyph_hit_bitmap)
            .unwrap_err();

        assert!(error.to_string().contains("missing glyph"));
    }

    #[test]
    fn decode_clearcodec_rejects_glyph_hit_without_glyph_index() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let glyph_hit_bitmap = encode_bitmap_stream(CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_HIT, None, &[], &[], &[]);
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 6,
            bottom: 9,
        };

        let error = decoders
            .decode_wire_to_surface_1(0, &destination, &glyph_hit_bitmap)
            .unwrap_err();

        assert!(error.to_string().contains("glyph hit requires glyph index"));
    }

    #[test]
    fn decode_clearcodec_rejects_oversized_glyph_bitmap() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let bands_data = encode_band_short_misses(0, 0, 33, 32, [0, 0, 0], &[&[1, 2, 3][..]]);
        let glyph_bitmap = encode_bitmap_stream(
            CLEARCODEC_BITMAP_STREAM_FLAG_GLYPH_INDEX,
            Some(1),
            &bands_data,
            &[],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 32,
            bottom: 31,
        };

        let error = decoders
            .decode_wire_to_surface_1(0, &destination, &glyph_bitmap)
            .unwrap_err();

        assert!(error.to_string().contains("area exceeds 1024"));
    }

    #[test]
    fn parse_clearcodec_subcodecs_data_reads_raw_subcodec_shape() {
        let payload = [
            0x02, 0x00, 0x03, 0x00, // xStart, yStart
            0x02, 0x00, 0x01, 0x00, // width, height
            0x06, 0x00, 0x00, 0x00, // bitmapDataByteCount
            0x00, // subCodecId
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];

        let subcodecs = parse_clearcodec_subcodecs_data(&payload).expect("parse raw subcodec payload");

        assert_eq!(subcodecs.len(), 1);
        assert_eq!(
            subcodecs[0],
            ClearCodecSubcodec {
                x_start: 2,
                y_start: 3,
                width: 2,
                height: 1,
                subcodec_id: 0x00,
                bitmap_data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            }
        );
    }

    #[test]
    fn decode_clearcodec_raw_subcodec_yields_region() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let subcodec_payload = [
            0x01, 0x00, 0x02, 0x00, // xStart, yStart
            0x02, 0x00, 0x01, 0x00, // width, height
            0x06, 0x00, 0x00, 0x00, // bitmapDataByteCount
            0x00, // subCodecId
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];
        let bitmap = encode_bitmap_stream(0, None, &[], &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 13,
            bottom: 23,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &destination, &bitmap)
            .expect("decode raw subcodec payload");

        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].rectangle,
            InclusiveRectangle {
                left: 11,
                top: 22,
                right: 12,
                bottom: 22,
            }
        );
        assert_eq!(
            decoded[0].rgba_data,
            vec![0x03, 0x02, 0x01, 0xFF, 0x06, 0x05, 0x04, 0xFF]
        );
    }

    #[test]
    fn decode_clearcodec_nsc_subcodec_yields_region() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let nsc_bitmap = encode_nsc_bitmap([&[0x10, 0x20], &[0x00, 0x00], &[0x00, 0x00], &[0x30, 0x40]], 1, false);
        let subcodec_payload = encode_subcodec_payload(1, 2, 2, 1, 0x01, &nsc_bitmap);
        let bitmap = encode_bitmap_stream(0, None, &[], &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 13,
            bottom: 23,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &destination, &bitmap)
            .expect("decode NSCodec subcodec payload");

        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].rectangle,
            InclusiveRectangle {
                left: 11,
                top: 22,
                right: 12,
                bottom: 22,
            }
        );
        assert_eq!(
            decoded[0].rgba_data,
            vec![0x10, 0x10, 0x10, 0x30, 0x20, 0x20, 0x20, 0x40]
        );
    }

    #[test]
    fn decode_clearcodec_bands_and_raw_subcodec_yields_ordered_regions() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let bands_data = encode_band_short_misses(0, 0, 1, 1, [0, 0, 0], &[&[1, 2, 3][..]]);
        let subcodec_payload = [
            0x00, 0x00, 0x00, 0x00, // xStart, yStart
            0x01, 0x00, 0x01, 0x00, // width, height
            0x03, 0x00, 0x00, 0x00, // bitmapDataByteCount
            0x00, // subCodecId
            0x01, 0x02, 0x03,
        ];
        let bitmap = encode_bitmap_stream(0, None, &bands_data, &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &destination, &bitmap)
            .expect("decode bands + raw subcodec");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(decoded[0].rgba_data, vec![3, 2, 1, 0xFF]);
        assert_eq!(decoded[1].rectangle, destination);
        assert_eq!(decoded[1].rgba_data, vec![3, 2, 1, 0xFF]);
    }

    #[test]
    fn decode_clearcodec_rejects_raw_subcodec_size_mismatch() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let subcodec_payload = [
            0x00, 0x00, 0x00, 0x00, // xStart, yStart
            0x01, 0x00, 0x01, 0x00, // width, height
            0x02, 0x00, 0x00, 0x00, // bitmapDataByteCount
            0x00, // subCodecId
            0x01, 0x02,
        ];
        let bitmap = encode_bitmap_stream(0, None, &[], &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };

        let error = decoders.decode_wire_to_surface_1(0, &destination, &bitmap).unwrap_err();

        assert!(error.to_string().contains("raw subcodec bitmap size mismatch"));
    }

    #[test]
    fn decode_clearcodec_residual_bands_and_raw_subcodec_yields_full_region() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let residual_data = [0x10, 0x20, 0x30, 0x04];
        let bands_data = encode_band_short_misses(0, 0, 1, 1, [0, 0, 0], &[&[1, 2, 3][..]]);
        let subcodec_payload = [
            0x01, 0x00, 0x01, 0x00, // xStart, yStart
            0x01, 0x00, 0x01, 0x00, // width, height
            0x03, 0x00, 0x00, 0x00, // bitmapDataByteCount
            0x00, // subCodecId
            0x04, 0x05, 0x06,
        ];
        let bitmap = encode_bitmap_stream(0, None, &bands_data, &residual_data, &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 11,
            bottom: 21,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &destination, &bitmap)
            .expect("decode residual + bands + raw subcodec");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(
            decoded[0].rgba_data,
            vec![
                0x03, 0x02, 0x01, 0xFF, 0x30, 0x20, 0x10, 0xFF, 0x30, 0x20, 0x10, 0xFF, 0x06, 0x05, 0x04, 0xFF,
            ]
        );
    }

    #[test]
    fn decode_clearcodec_official_rlex_example_2_yields_expected_pixels() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let subcodec_payload = encode_subcodec_payload(0, 0, 78, 17, 0x02, OFFICIAL_RLEX_EXAMPLE_2_BITMAP_DATA);
        let bitmap = encode_bitmap_stream(0, None, &[], &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 77,
            bottom: 16,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(0, &destination, &bitmap)
            .expect("decode official ClearCodec Example 2 RLEX payload");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(decoded[0].rgba_data.len(), 78 * 17 * 4);

        assert_eq!(rgba_pixel(&decoded[0], 78, 0, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(rgba_pixel(&decoded[0], 78, 4, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(rgba_pixel(&decoded[0], 78, 5, 0), [0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(rgba_pixel(&decoded[0], 78, 0, 8), [0xFF, 0xDB, 0x90, 0xFF]);
        assert_eq!(rgba_pixel(&decoded[0], 78, 1, 8), [0x3A, 0x00, 0x00, 0xFF]);
        assert_eq!(rgba_pixel(&decoded[0], 78, 2, 8), [0x3A, 0x90, 0xDB, 0xFF]);
    }

    #[test]
    fn decode_clearcodec_rejects_rlex_stop_index_past_palette() {
        let mut decoders = SurfaceClearCodecDecoders::default();
        let rlex_bitmap = [
            0x03, // paletteCount
            0x00, 0x00, 0x00, // palette[0]
            0x01, 0x01, 0x01, // palette[1]
            0x02, 0x02, 0x02, // palette[2]
            0x03, // stopIndex=3 (out of range for paletteCount=3), suiteDepth=0
            0x00, // runLengthFactor1
        ];
        let subcodec_payload = encode_subcodec_payload(0, 0, 1, 1, 0x02, &rlex_bitmap);
        let bitmap = encode_bitmap_stream(0, None, &[], &[], &subcodec_payload);
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };

        let error = decoders.decode_wire_to_surface_1(0, &destination, &bitmap).unwrap_err();

        assert!(error.to_string().contains("stopIndex 3 exceeds palette size 3"));
    }

    #[test]
    fn decode_clearcodec_cache_hit_does_not_advance_storage_cursors() {
        let first_band = encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6]]);
        let first_bitmap = encode_bitmap_stream(0, None, &first_band, &[], &[]);
        let mut decoders = SurfaceClearCodecDecoders::default();
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 1,
        };
        decoders
            .decode_wire_to_surface_1(11, &destination, &first_bitmap)
            .expect("prime ClearCodec cache state");

        let mut cache_hit_band = Vec::new();
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&1u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&[0, 0, 0]);
        cache_hit_band.extend_from_slice(&(0x8000u16).to_le_bytes());
        let cache_hit_bitmap = encode_bitmap_stream(0, None, &cache_hit_band, &[], &[]);

        decoders
            .decode_wire_to_surface_1(11, &destination, &cache_hit_bitmap)
            .expect("decode ClearCodec cache hit");

        let decoder = decoders.contexts.get(&11).expect("surface decoder exists");
        assert_eq!(decoder.vbar_cursor, 1);
        assert_eq!(decoder.short_vbar_cursor, 1);
        assert_eq!(decoder.vbar_storage.len(), 1);
        assert_eq!(decoder.short_vbar_storage.len(), 1);
    }

    #[test]
    fn decode_clearcodec_cache_reset_rewinds_write_cursors() {
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 1,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let first_bitmap = encode_bitmap_stream(
            0,
            None,
            &encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6]]),
            &[],
            &[],
        );
        let second_bitmap = encode_bitmap_stream(
            0,
            None,
            &encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[11, 12, 13, 14, 15, 16]]),
            &[],
            &[],
        );
        let reset_bitmap = encode_bitmap_stream(
            CLEARCODEC_BITMAP_STREAM_FLAG_CACHE_RESET,
            None,
            &encode_band_short_misses(0, 0, 1, 2, [0, 0, 0], &[&[21, 22, 23, 24, 25, 26]]),
            &[],
            &[],
        );

        decoders
            .decode_wire_to_surface_1(13, &destination, &first_bitmap)
            .expect("decode first short miss");
        decoders
            .decode_wire_to_surface_1(13, &destination, &second_bitmap)
            .expect("decode second short miss");
        decoders
            .decode_wire_to_surface_1(13, &destination, &reset_bitmap)
            .expect("decode cache-reset short miss");

        let decoder = decoders.contexts.get(&13).expect("surface decoder exists");
        assert_eq!(decoder.vbar_cursor, 1);
        assert_eq!(decoder.short_vbar_cursor, 1);

        let mut cache_hit_band = Vec::new();
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&0u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&1u16.to_le_bytes());
        cache_hit_band.extend_from_slice(&[0, 0, 0]);
        cache_hit_band.extend_from_slice(&(0x8000u16).to_le_bytes());
        let cache_hit_bitmap = encode_bitmap_stream(0, None, &cache_hit_band, &[], &[]);

        let decoded = decoders
            .decode_wire_to_surface_1(13, &destination, &cache_hit_bitmap)
            .expect("decode cache hit after cursor reset");

        assert_eq!(decoded[0].rgba_data, vec![23, 22, 21, 255, 26, 25, 24, 255]);
    }

    #[test]
    fn parse_clearcodec_bitmap_stream_rejects_truncated_payload() {
        let error = parse_clearcodec_bitmap_stream(&[
            0x00, 0x01, // flags, sequence number
            0x01, 0x00, 0x00, 0x00, // residual bytes
            0x00, 0x00, 0x00, 0x00, // bands bytes
            0x00, 0x00, 0x00, 0x00, // subcodec bytes
        ])
        .unwrap_err();

        assert!(error.to_string().contains("size mismatch"));
    }

    #[test]
    fn parse_clearcodec_residual_data_reads_run_segments() {
        let residual =
            parse_clearcodec_residual_data(&[0xFE, 0xFE, 0xFE, 0xFF, 0x80, 0x05], 1408).expect("parse residual");

        assert_eq!(
            residual,
            DecodedClearCodecResidual {
                segments: vec![ClearCodecRgbRunSegment {
                    blue: 0xFE,
                    green: 0xFE,
                    red: 0xFE,
                    run_length: 1408,
                }],
                decoded_pixels: 1408,
            }
        );
    }

    #[test]
    fn decode_clearcodec_residual_to_rgba_yields_full_canvas() {
        let rgba = decode_clearcodec_residual_to_rgba(
            &[
                0x00, 0x00, 0xFF, 0x02, // 2 red pixels
                0x00, 0xFF, 0x00, 0x02, // 2 green pixels
            ],
            2,
            2,
        )
        .expect("decode residual");

        assert_eq!(
            rgba,
            vec![
                0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
            ]
        );
    }

    #[test]
    fn decode_clearcodec_residual_and_bands_yields_full_region() {
        let bands_data = encode_band_short_misses(1, 0, 1, 2, [0, 0, 0], &[&[1, 2, 3, 4, 5, 6]]);
        let bitmap_data = encode_bitmap_stream(
            0,
            None,
            &bands_data,
            &[
                0x00, 0x00, 0x00, 0x04, // 4 black pixels
            ],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 11,
            bottom: 21,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let decoded = decoders
            .decode_wire_to_surface_1(2, &destination, &bitmap_data)
            .expect("decode residual+bands");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(
            decoded[0].rgba_data,
            vec![0, 0, 0, 255, 3, 2, 1, 255, 0, 0, 0, 255, 6, 5, 4, 255,]
        );
    }

    #[test]
    fn parse_clearcodec_residual_data_rejects_partial_coverage() {
        let residual = parse_clearcodec_residual_data(&[0x00, 0x00, 0x00, 0x03], 4).expect("parse partial residual");
        assert_eq!(
            residual,
            DecodedClearCodecResidual {
                segments: vec![ClearCodecRgbRunSegment {
                    blue: 0x00,
                    green: 0x00,
                    red: 0x00,
                    run_length: 3,
                }],
                decoded_pixels: 3,
            }
        );
    }

    #[test]
    fn decode_clearcodec_residual_to_rgba_rejects_partial_coverage() {
        let error = decode_clearcodec_residual_to_rgba(&[0x00, 0x00, 0x00, 0x03], 2, 2).unwrap_err();
        assert!(error.to_string().contains("decoded 3 pixels, expected 4"));
    }

    #[test]
    fn decode_clearcodec_partial_residual_and_bands_yields_full_region() {
        let bands_data = encode_band_short_misses(0, 1, 2, 1, [0, 0, 0], &[&[1, 2, 3], &[4, 5, 6]]);
        let bitmap_data = encode_bitmap_stream(
            0,
            None,
            &bands_data,
            &[
                0x00, 0x00, 0x00, 0x02, // 2 black pixels for the top row only
            ],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 11,
            bottom: 21,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let decoded = decoders
            .decode_wire_to_surface_1(3, &destination, &bitmap_data)
            .expect("decode partial residual + bands");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        assert_eq!(
            decoded[0].rgba_data,
            vec![0, 0, 0, 255, 0, 0, 0, 255, 3, 2, 1, 255, 6, 5, 4, 255,]
        );
    }

    #[test]
    fn decode_clearcodec_rejects_partial_residual_without_later_layers() {
        let bitmap_data = encode_bitmap_stream(
            0,
            None,
            &[],
            &[
                0x00, 0x00, 0x00, 0x03, // only 3 of 4 pixels
            ],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 1,
            bottom: 1,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let error = decoders
            .decode_wire_to_surface_1(4, &destination, &bitmap_data)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("partial residual without later layers is not implemented")
        );
    }

    #[test]
    fn decode_clearcodec_rejects_partial_residual_with_incomplete_later_coverage() {
        let bands_data = encode_band_short_misses(0, 1, 1, 1, [0, 0, 0], &[&[1, 2, 3]]);
        let bitmap_data = encode_bitmap_stream(
            0,
            None,
            &bands_data,
            &[
                0x00, 0x00, 0x00, 0x01, // only 1 of 4 pixels
            ],
            &[],
        );
        let destination = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 1,
            bottom: 1,
        };
        let mut decoders = SurfaceClearCodecDecoders::default();

        let error = decoders
            .decode_wire_to_surface_1(5, &destination, &bitmap_data)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("partial residual with incomplete later-layer coverage is not implemented")
        );
    }
}
