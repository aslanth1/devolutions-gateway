#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::manual_is_multiple_of,
    clippy::needless_borrow,
    clippy::similar_names,
    reason = "imported RDPEGFX AVC decoder keeps upstream structure while playback is being proven"
)]

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use anyhow::{Context, Result, bail};
use ironrdp_core::decode;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::vc::dvc::gfx::{Avc420BitmapStream, Avc444BitmapStream, Codec1Type, Encoding};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAvcRegion {
    pub rectangle: InclusiveRectangle,
    pub rgba_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedYuvFrame {
    union_rectangle: InclusiveRectangle,
    width: usize,
    height: usize,
    strides: (usize, usize, usize),
    y_plane: Vec<u8>,
    u_plane: Vec<u8>,
    v_plane: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedMainAvcFrame {
    codec_id: Codec1Type,
    frame: DecodedYuvFrame,
}

#[derive(Default)]
pub struct SurfaceAvcDecoders {
    decoders: HashMap<u16, Decoder>,
    cached_main_frames: HashMap<u16, CachedMainAvcFrame>,
}

impl SurfaceAvcDecoders {
    pub fn remove_surface(&mut self, surface_id: u16) {
        self.decoders.remove(&surface_id);
        self.cached_main_frames.remove(&surface_id);
    }

    pub fn decode_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        codec_id: Codec1Type,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedAvcRegion>> {
        match codec_id {
            Codec1Type::Avc420 => self.decode_avc420_wire_to_surface_1(surface_id, bitmap_data),
            Codec1Type::Avc444 | Codec1Type::Avc444v2 => {
                self.decode_avc444_wire_to_surface_1(surface_id, codec_id, bitmap_data)
            }
            unsupported => bail!("unsupported WireToSurface1 AVC codec: {unsupported:?}"),
        }
    }

    fn decode_avc420_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedAvcRegion>> {
        let packet = decode::<Avc420BitmapStream<'_>>(bitmap_data).context("decode AVC420 bitmap stream")?;
        self.decode_avc420_bitmap_stream(surface_id, &packet)
    }

    fn decode_avc444_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        codec_id: Codec1Type,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedAvcRegion>> {
        let packet = decode::<Avc444BitmapStream<'_>>(bitmap_data).context("decode AVC444 bitmap stream")?;

        match packet.encoding {
            Encoding::LUMA => {
                let main_frame = self.decode_avc420_bitmap_stream_to_yuv(surface_id, &packet.stream1)?;
                self.cached_main_frames.insert(
                    surface_id,
                    CachedMainAvcFrame {
                        codec_id,
                        frame: main_frame.clone(),
                    },
                );
                main_frame.rgba_regions(&packet.stream1.rectangles)
            }
            Encoding::LUMA_AND_CHROMA => self.decode_avc444_dual_stream(surface_id, codec_id, &packet),
            Encoding::CHROMA => self.decode_avc444_chroma_only(surface_id, codec_id, &packet.stream1),
            unsupported => bail!("unsupported {codec_id:?} encoding flags: {unsupported:?}"),
        }
    }

    fn decode_avc420_bitmap_stream(
        &mut self,
        surface_id: u16,
        packet: &Avc420BitmapStream<'_>,
    ) -> Result<Vec<DecodedAvcRegion>> {
        let frame = self.decode_avc420_bitmap_stream_to_yuv(surface_id, packet)?;
        frame.rgba_regions(&packet.rectangles)
    }

    fn decode_avc420_bitmap_stream_to_yuv(
        &mut self,
        surface_id: u16,
        packet: &Avc420BitmapStream<'_>,
    ) -> Result<DecodedYuvFrame> {
        if packet.rectangles.is_empty() {
            bail!("AVC420 WireToSurface1 requires at least one rectangle");
        }

        let union_rectangle = union_rectangles(&packet.rectangles).context("AVC420 bitmap stream has no rectangles")?;
        let expected_width = inclusive_rect_width(&union_rectangle);
        let expected_height = inclusive_rect_height(&union_rectangle);

        let decoder = match self.decoders.entry(surface_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Decoder::new().context("create OpenH264 decoder")?),
        };
        let decoded = decoder
            .decode(packet.data)
            .context("decode AVC420 H264 payload")?
            .context("AVC420 decoder did not yield a frame")?;

        let (actual_width, actual_height) = decoded.dimensions();
        if actual_width != expected_width || actual_height != expected_height {
            bail!(
                "decoded AVC420 frame dimensions {}x{} do not match update rectangle {}x{}",
                actual_width,
                actual_height,
                expected_width,
                expected_height
            );
        }

        Ok(DecodedYuvFrame::from_decoded(decoded, union_rectangle))
    }

    fn decode_avc444_dual_stream(
        &mut self,
        surface_id: u16,
        codec_id: Codec1Type,
        packet: &Avc444BitmapStream<'_>,
    ) -> Result<Vec<DecodedAvcRegion>> {
        let main_frame = self.decode_avc420_bitmap_stream_to_yuv(surface_id, &packet.stream1)?;
        self.cached_main_frames.insert(
            surface_id,
            CachedMainAvcFrame {
                codec_id,
                frame: main_frame.clone(),
            },
        );

        let aux_stream = packet
            .stream2
            .as_ref()
            .context("AVC444 dual-stream update is missing stream2")?;
        let aux_frame = self.decode_avc420_bitmap_stream_to_yuv(surface_id, aux_stream)?;
        ensure_matching_merge_geometry(codec_id, &main_frame, &aux_frame)?;

        let merged_rgba = merge_avc444_rgba(codec_id, &main_frame, &aux_frame)?;
        crop_rgba_regions(
            &merged_rgba,
            aux_frame.width,
            aux_frame.height,
            &aux_frame.union_rectangle,
            &aux_stream.rectangles,
        )
    }

    fn decode_avc444_chroma_only(
        &mut self,
        surface_id: u16,
        codec_id: Codec1Type,
        aux_stream: &Avc420BitmapStream<'_>,
    ) -> Result<Vec<DecodedAvcRegion>> {
        let cached_main = self
            .cached_main_frames
            .get(&surface_id)
            .cloned()
            .context("AVC444 chroma-only update requires a cached main luma frame")?;
        if cached_main.codec_id != codec_id {
            bail!(
                "AVC444 chroma-only update codec mismatch: cached {:?}, current {:?}",
                cached_main.codec_id,
                codec_id
            );
        }

        let aux_frame = self.decode_avc420_bitmap_stream_to_yuv(surface_id, aux_stream)?;
        ensure_matching_merge_geometry(codec_id, &cached_main.frame, &aux_frame)?;

        let merged_rgba = merge_avc444_rgba(codec_id, &cached_main.frame, &aux_frame)?;
        crop_rgba_regions(
            &merged_rgba,
            aux_frame.width,
            aux_frame.height,
            &aux_frame.union_rectangle,
            &aux_stream.rectangles,
        )
    }
}

impl DecodedYuvFrame {
    fn from_decoded(decoded: impl YUVSource, union_rectangle: InclusiveRectangle) -> Self {
        Self {
            union_rectangle,
            width: decoded.dimensions().0,
            height: decoded.dimensions().1,
            strides: decoded.strides(),
            y_plane: decoded.y().to_vec(),
            u_plane: decoded.u().to_vec(),
            v_plane: decoded.v().to_vec(),
        }
    }

    fn rgba_regions(&self, rectangles: &[InclusiveRectangle]) -> Result<Vec<DecodedAvcRegion>> {
        let rgba = rgba_from_yuv420_frame(self);
        crop_rgba_regions(&rgba, self.width, self.height, &self.union_rectangle, rectangles)
    }
}

fn ensure_matching_merge_geometry(codec_id: Codec1Type, main: &DecodedYuvFrame, aux: &DecodedYuvFrame) -> Result<()> {
    if main.union_rectangle != aux.union_rectangle || main.width != aux.width || main.height != aux.height {
        bail!(
            "unsupported {codec_id:?} merge geometry mismatch: main {:?} {}x{}, aux {:?} {}x{}",
            main.union_rectangle,
            main.width,
            main.height,
            aux.union_rectangle,
            aux.width,
            aux.height
        );
    }

    Ok(())
}

fn rgba_from_yuv420_frame(frame: &DecodedYuvFrame) -> Vec<u8> {
    let mut rgba = vec![0; frame.width * frame.height * 4];
    for y in 0..frame.height {
        for x in 0..frame.width {
            let luma = sample_luma(frame, x, y);
            let chroma_u = sample_chroma(&frame.u_plane, frame.width, frame.height, frame.strides.1, x, y);
            let chroma_v = sample_chroma(&frame.v_plane, frame.width, frame.height, frame.strides.2, x, y);
            write_rgba_pixel(yuv_to_rgba(luma, chroma_u, chroma_v), &mut rgba, x, y, frame.width);
        }
    }
    rgba
}

fn merge_avc444_rgba(codec_id: Codec1Type, main: &DecodedYuvFrame, aux: &DecodedYuvFrame) -> Result<Vec<u8>> {
    let mut rgba = vec![0; main.width * main.height * 4];
    for y in 0..main.height {
        for x in 0..main.width {
            let main_luma = sample_luma(main, x, y);
            let (merged_u, merged_v) = avc444_uv(codec_id, main, aux, x, y)?;
            write_rgba_pixel(yuv_to_rgba(main_luma, merged_u, merged_v), &mut rgba, x, y, main.width);
        }
    }
    Ok(rgba)
}

fn avc444_uv(
    codec_id: Codec1Type,
    main: &DecodedYuvFrame,
    aux: &DecodedYuvFrame,
    x: usize,
    y: usize,
) -> Result<(u8, u8)> {
    match codec_id {
        Codec1Type::Avc444 => avc444_uv_v1(main, aux, x, y),
        Codec1Type::Avc444v2 => avc444_uv_v2(main, aux, x, y),
        unsupported => bail!("unsupported AVC444 merge codec: {unsupported:?}"),
    }
}

fn avc444_uv_v1(main: &DecodedYuvFrame, aux: &DecodedYuvFrame, x: usize, y: usize) -> Result<(u8, u8)> {
    let main_u = sample_chroma(&main.u_plane, main.width, main.height, main.strides.1, x, y);
    let main_v = sample_chroma(&main.v_plane, main.width, main.height, main.strides.2, x, y);

    let start_y = (y / 16) * 16 + ((y % 16) / 2);
    let aux_u_main = sample_luma(aux, x, start_y);
    let aux_v_main = sample_luma(aux, x, start_y + 8);
    let aux_u_additional = sample_luma(aux, x + 1, start_y);
    let aux_v_additional = sample_luma(aux, x + 1, start_y + 8);
    let aux_u_secondary = sample_chroma(&aux.u_plane, aux.width, aux.height, aux.strides.1, x, y);
    let aux_v_secondary = sample_chroma(&aux.v_plane, aux.width, aux.height, aux.strides.2, x, y);

    let x_is_odd = x % 2 == 1;
    let y_is_odd = y % 2 == 1;
    if !x_is_odd && !y_is_odd {
        let augmented_u = augment_uv(main_u, aux_u_main, aux_u_secondary, aux_u_additional);
        let augmented_v = augment_uv(main_v, aux_v_main, aux_v_secondary, aux_v_additional);
        let final_u = if main_u.abs_diff(augmented_u) > 30 {
            augmented_u
        } else {
            main_u
        };
        let final_v = if main_v.abs_diff(augmented_v) > 30 {
            augmented_v
        } else {
            main_v
        };
        Ok((final_u, final_v))
    } else if y_is_odd {
        Ok((aux_u_main, aux_v_main))
    } else if x_is_odd {
        Ok((aux_u_secondary, aux_v_secondary))
    } else {
        bail!("unexpected AVC444 coordinate branch")
    }
}

fn avc444_uv_v2(main: &DecodedYuvFrame, aux: &DecodedYuvFrame, x: usize, y: usize) -> Result<(u8, u8)> {
    let main_u = sample_chroma(&main.u_plane, main.width, main.height, main.strides.1, x, y);
    let main_v = sample_chroma(&main.v_plane, main.width, main.height, main.strides.2, x, y);

    let left_x = x / 2;
    let right_x = aux.width / 2 + x / 2;
    let aux_u_main = sample_luma(aux, left_x, y);
    let aux_v_main = sample_luma(aux, right_x, y);
    let aux_uv_left = (
        sample_chroma(&aux.u_plane, aux.width, aux.height, aux.strides.1, x / 2, y),
        sample_chroma(
            &aux.u_plane,
            aux.width,
            aux.height,
            aux.strides.1,
            aux.width / 2 + x / 2,
            y,
        ),
    );
    let aux_uv_right = (
        sample_chroma(&aux.v_plane, aux.width, aux.height, aux.strides.2, x / 2, y),
        sample_chroma(
            &aux.v_plane,
            aux.width,
            aux.height,
            aux.strides.2,
            aux.width / 2 + x / 2,
            y,
        ),
    );

    let x_is_odd = x % 2 == 1;
    let y_is_odd = y % 2 == 1;
    let x_mod_4_zero = x % 4 == 0;

    if !x_is_odd && !y_is_odd {
        let augmented_u = augment_uv(main_u, aux_u_main, aux_uv_left.0, aux_uv_right.0);
        let augmented_v = augment_uv(main_v, aux_v_main, aux_uv_left.1, aux_uv_right.1);
        let final_u = if main_u.abs_diff(augmented_u) > 30 {
            augmented_u
        } else {
            main_u
        };
        let final_v = if main_v.abs_diff(augmented_v) > 30 {
            augmented_v
        } else {
            main_v
        };
        Ok((final_u, final_v))
    } else if x_is_odd {
        Ok((aux_u_main, aux_v_main))
    } else if y_is_odd {
        if x_mod_4_zero {
            Ok(aux_uv_left)
        } else {
            Ok(aux_uv_right)
        }
    } else {
        bail!("unexpected AVC444v2 coordinate branch")
    }
}

fn augment_uv(main: u8, aux_primary: u8, aux_secondary: u8, aux_additional: u8) -> u8 {
    let augmented = i32::from(main) * 4 - i32::from(aux_primary) - i32::from(aux_secondary) - i32::from(aux_additional);
    augmented.clamp(0, 255) as u8
}

fn sample_luma(frame: &DecodedYuvFrame, x: usize, y: usize) -> u8 {
    let clamped_x = x.min(frame.width.saturating_sub(1));
    let clamped_y = y.min(frame.height.saturating_sub(1));
    frame.y_plane[clamped_y * frame.strides.0 + clamped_x]
}

fn sample_chroma(plane: &[u8], width: usize, height: usize, stride: usize, x: usize, y: usize) -> u8 {
    let chroma_width = (width / 2).max(1);
    let chroma_height = (height / 2).max(1);
    let chroma_x = (x / 2).min(chroma_width.saturating_sub(1));
    let chroma_y = (y / 2).min(chroma_height.saturating_sub(1));
    plane[chroma_y * stride + chroma_x]
}

fn yuv_to_rgba(y: u8, u: u8, v: u8) -> [u8; 4] {
    let c = i32::from(y).saturating_sub(16);
    let d = i32::from(u) - 128;
    let e = i32::from(v) - 128;

    let red = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8;
    let green = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8;
    let blue = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8;

    [red, green, blue, 255]
}

fn write_rgba_pixel(rgba: [u8; 4], target: &mut [u8], x: usize, y: usize, width: usize) {
    let offset = (y * width + x) * 4;
    target[offset..offset + 4].copy_from_slice(&rgba);
}

fn union_rectangles(rectangles: &[InclusiveRectangle]) -> Option<InclusiveRectangle> {
    let mut rectangles = rectangles.iter();
    let first = rectangles.next()?.clone();

    Some(rectangles.fold(first, |union, rectangle| InclusiveRectangle {
        left: union.left.min(rectangle.left),
        top: union.top.min(rectangle.top),
        right: union.right.max(rectangle.right),
        bottom: union.bottom.max(rectangle.bottom),
    }))
}

fn inclusive_rect_width(rectangle: &InclusiveRectangle) -> usize {
    usize::from(rectangle.right.saturating_sub(rectangle.left)) + 1
}

fn inclusive_rect_height(rectangle: &InclusiveRectangle) -> usize {
    usize::from(rectangle.bottom.saturating_sub(rectangle.top)) + 1
}

fn crop_rgba_region(
    source_rgba: &[u8],
    source_width: usize,
    source_height: usize,
    source_rectangle: &InclusiveRectangle,
    target_rectangle: &InclusiveRectangle,
) -> Result<Vec<u8>> {
    let target_width = inclusive_rect_width(&target_rectangle);
    let target_height = inclusive_rect_height(&target_rectangle);
    let source_stride = source_width * 4;

    if source_rgba.len() != source_width * source_height * 4 {
        bail!("decoded AVC420 RGBA buffer size does not match source dimensions");
    }

    if target_rectangle.left < source_rectangle.left
        || target_rectangle.top < source_rectangle.top
        || target_rectangle.right > source_rectangle.right
        || target_rectangle.bottom > source_rectangle.bottom
    {
        bail!("target rectangle is outside decoded AVC420 frame bounds");
    }

    let offset_x = usize::from(target_rectangle.left - source_rectangle.left);
    let offset_y = usize::from(target_rectangle.top - source_rectangle.top);
    let row_bytes = target_width * 4;
    let mut cropped = vec![0; target_width * target_height * 4];

    for row in 0..target_height {
        let source_row_offset = (offset_y + row) * source_stride + offset_x * 4;
        let target_row_offset = row * row_bytes;
        cropped[target_row_offset..target_row_offset + row_bytes]
            .copy_from_slice(&source_rgba[source_row_offset..source_row_offset + row_bytes]);
    }

    Ok(cropped)
}

fn crop_rgba_regions(
    source_rgba: &[u8],
    source_width: usize,
    source_height: usize,
    source_rectangle: &InclusiveRectangle,
    target_rectangles: &[InclusiveRectangle],
) -> Result<Vec<DecodedAvcRegion>> {
    target_rectangles
        .iter()
        .map(|rectangle| {
            let region_rgba = crop_rgba_region(source_rgba, source_width, source_height, source_rectangle, rectangle)?;

            Ok(DecodedAvcRegion {
                rectangle: rectangle.clone(),
                rgba_data: region_rgba,
            })
        })
        .collect()
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::rdp::vc::dvc::gfx::QuantQuality;
    use openh264::encoder::Encoder;
    use openh264::formats::{RgbSliceU8, YUVBuffer};

    use super::*;

    fn solid_rgb(width: usize, height: usize, rgb: [u8; 3]) -> Vec<u8> {
        let mut data = Vec::with_capacity(width * height * 3);
        for _ in 0..(width * height) {
            data.extend_from_slice(&rgb);
        }
        data
    }

    #[test]
    fn decode_avc420_wire_to_surface_1_yields_rgba_region() {
        let width = 16usize;
        let height = 16usize;
        let source_rgb = solid_rgb(width, height, [220, 10, 10]);
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&source_rgb, (width, height)));

        let mut encoder = Encoder::new().expect("OpenH264 encoder");
        let encoded = encoder.encode(&yuv).expect("encode h264").to_vec();

        let rectangle = InclusiveRectangle {
            left: 10,
            top: 20,
            right: 25,
            bottom: 35,
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

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(7, Codec1Type::Avc420, &bitmap_data)
            .expect("decode avc420 wire to surface");

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].rectangle, rectangle);
        assert_eq!(regions[0].rgba_data.len(), width * height * 4);
        assert!(regions[0].rgba_data.chunks_exact(4).any(|pixel| pixel[0] > pixel[1]));
        assert!(regions[0].rgba_data.chunks_exact(4).all(|pixel| pixel[3] == 255));
    }

    #[test]
    fn decode_avc420_wire_to_surface_1_yields_multiple_regions() {
        let width = 32usize;
        let height = 16usize;
        let mut source_rgb = Vec::with_capacity(width * height * 3);
        for _ in 0..height {
            for x in 0..width {
                if x < 16 {
                    source_rgb.extend_from_slice(&[220, 30, 30]);
                } else {
                    source_rgb.extend_from_slice(&[30, 220, 30]);
                }
            }
        }
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&source_rgb, (width, height)));

        let mut encoder = Encoder::new().expect("OpenH264 encoder");
        let encoded = encoder.encode(&yuv).expect("encode h264").to_vec();

        let bitmap_stream = Avc420BitmapStream {
            rectangles: vec![
                InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right: 15,
                    bottom: 15,
                },
                InclusiveRectangle {
                    left: 16,
                    top: 0,
                    right: 31,
                    bottom: 15,
                },
            ],
            quant_qual_vals: vec![
                QuantQuality {
                    quantization_parameter: 0,
                    progressive: false,
                    quality: 100,
                },
                QuantQuality {
                    quantization_parameter: 0,
                    progressive: false,
                    quality: 100,
                },
            ],
            data: &encoded,
        };
        let bitmap_data = encode_vec(&bitmap_stream).expect("encode avc420 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(9, Codec1Type::Avc420, &bitmap_data)
            .expect("multiple rectangles should decode");

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].rectangle.left, 0);
        assert_eq!(regions[0].rectangle.right, 15);
        assert_eq!(regions[0].rgba_data.len(), 16 * 16 * 4);
        assert!(regions[0].rgba_data.chunks_exact(4).any(|pixel| pixel[0] > pixel[1]));

        assert_eq!(regions[1].rectangle.left, 16);
        assert_eq!(regions[1].rectangle.right, 31);
        assert_eq!(regions[1].rgba_data.len(), 16 * 16 * 4);
        assert!(regions[1].rgba_data.chunks_exact(4).any(|pixel| pixel[1] > pixel[0]));
    }

    #[test]
    fn decode_avc420_wire_to_surface_1_rejects_empty_rectangle_list() {
        let bitmap_stream = Avc420BitmapStream {
            rectangles: vec![],
            quant_qual_vals: vec![],
            data: &[],
        };
        let bitmap_data = encode_vec(&bitmap_stream).expect("encode avc420 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let error = decoders
            .decode_wire_to_surface_1(11, Codec1Type::Avc420, &bitmap_data)
            .expect_err("empty rectangles should be rejected");

        assert!(error.to_string().contains("requires at least one rectangle"));
    }

    fn encode_avc420_bitmap_stream(
        width: usize,
        height: usize,
        source_rgb: &[u8],
        rectangles: Vec<InclusiveRectangle>,
    ) -> Vec<u8> {
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(source_rgb, (width, height)));
        let mut encoder = Encoder::new().expect("OpenH264 encoder");
        let encoded = encoder.encode(&yuv).expect("encode h264").to_vec();

        let quant_qual_vals = rectangles
            .iter()
            .map(|_| QuantQuality {
                quantization_parameter: 0,
                progressive: false,
                quality: 100,
            })
            .collect::<Vec<_>>();

        encode_vec(&Avc420BitmapStream {
            rectangles,
            quant_qual_vals,
            data: &encoded,
        })
        .expect("encode avc420 bitmap stream")
    }

    #[test]
    fn decode_avc444_wire_to_surface_1_luma_only_yields_rgba_region() {
        let width = 16usize;
        let height = 16usize;
        let source_rgb = solid_rgb(width, height, [30, 30, 220]);
        let rectangle = InclusiveRectangle {
            left: 40,
            top: 50,
            right: 55,
            bottom: 65,
        };
        let avc420_payload = encode_avc420_bitmap_stream(width, height, &source_rgb, vec![rectangle.clone()]);
        let avc420_stream = decode::<Avc420BitmapStream<'_>>(&avc420_payload).expect("decode avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::LUMA,
            stream1: avc420_stream,
            stream2: None,
        })
        .expect("encode avc444 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(13, Codec1Type::Avc444, &avc444_payload)
            .expect("decode avc444 luma-only stream");

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].rectangle, rectangle);
        assert_eq!(regions[0].rgba_data.len(), width * height * 4);
        assert!(regions[0].rgba_data.chunks_exact(4).any(|pixel| pixel[2] > pixel[0]));
    }

    #[test]
    fn decode_avc444v2_wire_to_surface_1_luma_only_yields_rgba_region() {
        let width = 16usize;
        let height = 16usize;
        let source_rgb = solid_rgb(width, height, [220, 220, 40]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };
        let avc420_payload = encode_avc420_bitmap_stream(width, height, &source_rgb, vec![rectangle.clone()]);
        let avc420_stream = decode::<Avc420BitmapStream<'_>>(&avc420_payload).expect("decode avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::LUMA,
            stream1: avc420_stream,
            stream2: None,
        })
        .expect("encode avc444v2 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(14, Codec1Type::Avc444v2, &avc444_payload)
            .expect("decode avc444v2 luma-only stream");

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].rectangle, rectangle);
        assert_eq!(regions[0].rgba_data.len(), width * height * 4);
        assert!(
            regions[0]
                .rgba_data
                .chunks_exact(4)
                .any(|pixel| pixel[0] > 100 && pixel[1] > 100)
        );
    }

    #[test]
    fn decode_avc444_wire_to_surface_1_dual_stream_yields_rgba_region() {
        let width = 16usize;
        let height = 16usize;
        let luma_rgb = solid_rgb(width, height, [200, 40, 40]);
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };
        let stream1_payload = encode_avc420_bitmap_stream(width, height, &luma_rgb, vec![rectangle.clone()]);
        let stream2_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle.clone()]);
        let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
        let stream2 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::LUMA_AND_CHROMA,
            stream1,
            stream2: Some(stream2),
        })
        .expect("encode dual-stream avc444 bitmap stream");

        let luma_only_payload = {
            let avc420_stream = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA,
                stream1: avc420_stream,
                stream2: None,
            })
            .expect("encode luma-only avc444 bitmap stream")
        };

        let mut luma_decoders = SurfaceAvcDecoders::default();
        let luma_regions = luma_decoders
            .decode_wire_to_surface_1(15, Codec1Type::Avc444, &luma_only_payload)
            .expect("decode luma-only avc444 stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(15, Codec1Type::Avc444, &avc444_payload)
            .expect("dual-stream avc444 should decode");

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].rectangle, rectangle);
        assert_eq!(regions[0].rgba_data.len(), width * height * 4);
        assert_ne!(regions[0].rgba_data, luma_regions[0].rgba_data);
    }

    #[test]
    fn decode_avc444_wire_to_surface_1_chroma_only_reuses_cached_main_frame() {
        let width = 16usize;
        let height = 16usize;
        let luma_rgb = solid_rgb(width, height, [200, 40, 40]);
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };

        let stream1_payload = encode_avc420_bitmap_stream(width, height, &luma_rgb, vec![rectangle.clone()]);
        let stream2_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle.clone()]);

        let luma_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA,
                stream1,
                stream2: None,
            })
            .expect("encode luma-only avc444 bitmap stream")
        };

        let dual_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            let stream2 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA_AND_CHROMA,
                stream1,
                stream2: Some(stream2),
            })
            .expect("encode dual-stream avc444 bitmap stream")
        };

        let chroma_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::CHROMA,
                stream1,
                stream2: None,
            })
            .expect("encode chroma-only avc444 bitmap stream")
        };

        let mut dual_decoders = SurfaceAvcDecoders::default();
        let dual_regions = dual_decoders
            .decode_wire_to_surface_1(16, Codec1Type::Avc444, &dual_payload)
            .expect("decode dual-stream avc444 stream");

        let mut chroma_decoders = SurfaceAvcDecoders::default();
        let luma_regions = chroma_decoders
            .decode_wire_to_surface_1(16, Codec1Type::Avc444, &luma_payload)
            .expect("decode cached luma avc444 stream");
        let chroma_regions = chroma_decoders
            .decode_wire_to_surface_1(16, Codec1Type::Avc444, &chroma_payload)
            .expect("decode chroma-only avc444 stream");

        assert_eq!(chroma_regions.len(), 1);
        assert_eq!(chroma_regions[0].rectangle, rectangle);
        assert_eq!(chroma_regions[0].rgba_data, dual_regions[0].rgba_data);
        assert_ne!(chroma_regions[0].rgba_data, luma_regions[0].rgba_data);
    }

    #[test]
    fn decode_avc444_wire_to_surface_1_chroma_only_requires_cached_main_frame() {
        let width = 16usize;
        let height = 16usize;
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };
        let stream1_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle]);
        let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode chroma avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::CHROMA,
            stream1,
            stream2: None,
        })
        .expect("encode chroma-only avc444 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let error = decoders
            .decode_wire_to_surface_1(17, Codec1Type::Avc444, &avc444_payload)
            .expect_err("chroma-only avc444 should require cached luma");

        assert!(error.to_string().contains("requires a cached main luma frame"));
    }

    #[test]
    fn decode_avc444v2_wire_to_surface_1_dual_stream_yields_rgba_region() {
        let width = 16usize;
        let height = 16usize;
        let luma_rgb = solid_rgb(width, height, [200, 40, 40]);
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };
        let stream1_payload = encode_avc420_bitmap_stream(width, height, &luma_rgb, vec![rectangle.clone()]);
        let stream2_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle.clone()]);
        let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
        let stream2 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::LUMA_AND_CHROMA,
            stream1,
            stream2: Some(stream2),
        })
        .expect("encode dual-stream avc444v2 bitmap stream");

        let luma_only_payload = {
            let avc420_stream = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA,
                stream1: avc420_stream,
                stream2: None,
            })
            .expect("encode luma-only avc444v2 bitmap stream")
        };

        let mut luma_decoders = SurfaceAvcDecoders::default();
        let luma_regions = luma_decoders
            .decode_wire_to_surface_1(18, Codec1Type::Avc444v2, &luma_only_payload)
            .expect("decode luma-only avc444v2 stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let regions = decoders
            .decode_wire_to_surface_1(18, Codec1Type::Avc444v2, &avc444_payload)
            .expect("dual-stream avc444v2 should decode");

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].rectangle, rectangle);
        assert_eq!(regions[0].rgba_data.len(), width * height * 4);
        assert_ne!(regions[0].rgba_data, luma_regions[0].rgba_data);
    }

    #[test]
    fn decode_avc444v2_wire_to_surface_1_chroma_only_reuses_cached_main_frame() {
        let width = 16usize;
        let height = 16usize;
        let luma_rgb = solid_rgb(width, height, [200, 40, 40]);
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };

        let stream1_payload = encode_avc420_bitmap_stream(width, height, &luma_rgb, vec![rectangle.clone()]);
        let stream2_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle.clone()]);

        let luma_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA,
                stream1,
                stream2: None,
            })
            .expect("encode luma-only avc444v2 bitmap stream")
        };

        let dual_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode luma avc420 stream");
            let stream2 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::LUMA_AND_CHROMA,
                stream1,
                stream2: Some(stream2),
            })
            .expect("encode dual-stream avc444v2 bitmap stream")
        };

        let chroma_payload = {
            let stream1 = decode::<Avc420BitmapStream<'_>>(&stream2_payload).expect("decode chroma avc420 stream");
            encode_vec(&Avc444BitmapStream {
                encoding: Encoding::CHROMA,
                stream1,
                stream2: None,
            })
            .expect("encode chroma-only avc444v2 bitmap stream")
        };

        let mut dual_decoders = SurfaceAvcDecoders::default();
        let dual_regions = dual_decoders
            .decode_wire_to_surface_1(19, Codec1Type::Avc444v2, &dual_payload)
            .expect("decode dual-stream avc444v2 stream");

        let mut chroma_decoders = SurfaceAvcDecoders::default();
        let luma_regions = chroma_decoders
            .decode_wire_to_surface_1(19, Codec1Type::Avc444v2, &luma_payload)
            .expect("decode cached luma avc444v2 stream");
        let chroma_regions = chroma_decoders
            .decode_wire_to_surface_1(19, Codec1Type::Avc444v2, &chroma_payload)
            .expect("decode chroma-only avc444v2 stream");

        assert_eq!(chroma_regions.len(), 1);
        assert_eq!(chroma_regions[0].rectangle, rectangle);
        assert_eq!(chroma_regions[0].rgba_data, dual_regions[0].rgba_data);
        assert_ne!(chroma_regions[0].rgba_data, luma_regions[0].rgba_data);
    }

    #[test]
    fn decode_avc444v2_wire_to_surface_1_chroma_only_requires_cached_main_frame() {
        let width = 16usize;
        let height = 16usize;
        let chroma_rgb = solid_rgb(width, height, [40, 40, 200]);
        let rectangle = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 15,
            bottom: 15,
        };
        let stream1_payload = encode_avc420_bitmap_stream(width, height, &chroma_rgb, vec![rectangle]);
        let stream1 = decode::<Avc420BitmapStream<'_>>(&stream1_payload).expect("decode chroma avc420 stream");
        let avc444_payload = encode_vec(&Avc444BitmapStream {
            encoding: Encoding::CHROMA,
            stream1,
            stream2: None,
        })
        .expect("encode chroma-only avc444v2 bitmap stream");

        let mut decoders = SurfaceAvcDecoders::default();
        let error = decoders
            .decode_wire_to_surface_1(20, Codec1Type::Avc444v2, &avc444_payload)
            .expect_err("chroma-only avc444v2 should require cached luma");

        assert!(error.to_string().contains("requires a cached main luma frame"));
    }
}
