use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use ironrdp_core::{ReadCursor, decode_cursor};
use ironrdp_graphics::color_conversion::{self, YCbCrBuffer};
use ironrdp_graphics::rectangle_processing::Region;
use ironrdp_graphics::{dwt, quantization, rlgr, subband_reconstruction};
use ironrdp_pdu::codecs::rfx::{self, CodecChannel, EntropyAlgorithm, Quant, RfxRectangle, Tile};
use ironrdp_pdu::geometry::InclusiveRectangle;

const TILE_SIZE: u16 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRfxRegion {
    pub rectangle: InclusiveRectangle,
    pub rgba_data: Vec<u8>,
}

#[derive(Default)]
pub struct SurfaceRemoteFxDecoders {
    wire_to_surface_1_contexts: HashMap<u16, RemoteFxDecodingContext>,
    wire_to_surface_2_contexts: HashMap<(u16, u32), RemoteFxDecodingContext>,
}

impl SurfaceRemoteFxDecoders {
    pub fn remove_surface(&mut self, surface_id: u16) {
        self.wire_to_surface_1_contexts.remove(&surface_id);
        self.wire_to_surface_2_contexts
            .retain(|(tracked_surface_id, _), _| *tracked_surface_id != surface_id);
    }

    pub fn remove_context(&mut self, surface_id: u16, codec_context_id: u32) {
        self.wire_to_surface_2_contexts.remove(&(surface_id, codec_context_id));
    }

    pub fn decode_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        surface_width: u16,
        surface_height: u16,
        destination: &InclusiveRectangle,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedRfxRegion>> {
        let decoder = self.wire_to_surface_1_contexts.entry(surface_id).or_default();
        decoder.decode(
            surface_width,
            surface_height,
            bitmap_data,
            &RemoteFxPlacement::Destination(destination.clone()),
        )
    }

    pub fn decode_wire_to_surface_2(
        &mut self,
        surface_id: u16,
        codec_context_id: u32,
        surface_width: u16,
        surface_height: u16,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedRfxRegion>> {
        let decoder = self
            .wire_to_surface_2_contexts
            .entry((surface_id, codec_context_id))
            .or_default();
        decoder.decode(
            surface_width,
            surface_height,
            bitmap_data,
            &RemoteFxPlacement::SurfaceOrigin,
        )
    }
}

#[derive(Debug, Clone)]
enum RemoteFxPlacement {
    SurfaceOrigin,
    Destination(InclusiveRectangle),
}

struct RemoteFxDecodingContext {
    context: rfx::ContextPdu,
    channels: rfx::ChannelsPdu,
    decoding_tiles: DecodingTileContext,
}

impl Default for RemoteFxDecodingContext {
    fn default() -> Self {
        Self {
            context: rfx::ContextPdu {
                flags: rfx::OperatingMode::empty(),
                entropy_algorithm: EntropyAlgorithm::Rlgr1,
            },
            channels: rfx::ChannelsPdu(Vec::new()),
            decoding_tiles: DecodingTileContext::new(),
        }
    }
}

impl RemoteFxDecodingContext {
    fn decode(
        &mut self,
        surface_width: u16,
        surface_height: u16,
        bitmap_data: &[u8],
        placement: &RemoteFxPlacement,
    ) -> Result<Vec<DecodedRfxRegion>> {
        let mut input = ReadCursor::new(bitmap_data);
        let mut decoded_regions = Vec::new();

        while !input.is_empty() {
            let block: rfx::Block<'_> = decode_cursor(&mut input).context("decode RFX block")?;
            match block {
                rfx::Block::Sync(_) => self.process_headers(&mut input)?,
                rfx::Block::CodecChannel(CodecChannel::FrameBegin(frame_begin)) => {
                    decoded_regions.extend(self.process_frame(
                        &mut input,
                        frame_begin,
                        surface_width,
                        surface_height,
                        placement,
                    )?);
                }
                unsupported => bail!("unexpected RFX block at stream root: {unsupported:?}"),
            }
        }

        Ok(decoded_regions)
    }

    fn process_headers(&mut self, input: &mut ReadCursor<'_>) -> Result<()> {
        let mut context = None;
        let mut channels = None;

        for _ in 0..3 {
            let block: rfx::Block<'_> = decode_cursor(input).context("decode RFX header block")?;
            match block {
                rfx::Block::CodecChannel(CodecChannel::Context(value)) => context = Some(value),
                rfx::Block::Channels(value) => channels = Some(value),
                rfx::Block::CodecVersions(_) => {}
                unsupported => bail!("unexpected RFX header block: {unsupported:?}"),
            }
        }

        let context = context.context("RFX context header is missing")?;
        let channels = channels.context("RFX channels header is missing")?;

        if channels.0.is_empty() {
            bail!("RFX channels header announced no channels");
        }

        self.context = context;
        self.channels = channels;
        Ok(())
    }

    fn process_frame(
        &mut self,
        input: &mut ReadCursor<'_>,
        _frame_begin: rfx::FrameBeginPdu,
        surface_width: u16,
        surface_height: u16,
        placement: &RemoteFxPlacement,
    ) -> Result<Vec<DecodedRfxRegion>> {
        let channel = self
            .channels
            .0
            .first()
            .context("RFX frame arrived before channel context was initialized")?;
        let channel_width = u16::try_from(channel.width).context("RFX channel width is negative")?;
        let channel_height = u16::try_from(channel.height).context("RFX channel height is negative")?;
        let entropy_algorithm = self.context.entropy_algorithm;

        let region = match decode_cursor(input).context("decode RFX region block")? {
            rfx::Block::CodecChannel(CodecChannel::Region(region)) => region,
            unsupported => bail!("expected RFX region block after frame begin, got {unsupported:?}"),
        };
        let tile_set = match decode_cursor(input).context("decode RFX tileset block")? {
            rfx::Block::CodecChannel(CodecChannel::TileSet(tile_set)) => tile_set,
            unsupported => bail!("expected RFX tileset block after region, got {unsupported:?}"),
        };
        match decode_cursor(input).context("decode RFX frame end block")? {
            rfx::Block::CodecChannel(CodecChannel::FrameEnd(_)) => {}
            unsupported => bail!("expected RFX frame end block after tileset, got {unsupported:?}"),
        }

        let mut region = region;
        if region.rectangles.is_empty() {
            region.rectangles = vec![RfxRectangle {
                x: 0,
                y: 0,
                width: channel_width,
                height: channel_height,
            }];
        }

        let clipping_region = clipping_region(
            region.rectangles.as_slice(),
            surface_width,
            surface_height,
            channel_width,
            channel_height,
            placement,
        );
        let mut decoded_regions = Vec::new();

        for (tile_rectangle, tile_data) in tiles_to_rectangles(tile_set.tiles.as_slice(), placement)
            .zip(map_tiles_data(tile_set.tiles.as_slice(), tile_set.quants.as_slice()))
        {
            decode_tile(
                &tile_data,
                entropy_algorithm,
                self.decoding_tiles.tile_output.as_mut_slice(),
                self.decoding_tiles.ycbcr_buffer.as_mut_slice(),
                self.decoding_tiles.ycbcr_temp_buffer.as_mut_slice(),
            )?;

            decoded_regions.extend(crop_tile_regions(
                self.decoding_tiles.tile_output.as_slice(),
                &clipping_region,
                &tile_rectangle,
            )?);
        }

        Ok(decoded_regions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodingTileContext {
    tile_output: Vec<u8>,
    ycbcr_buffer: Vec<Vec<i16>>,
    ycbcr_temp_buffer: Vec<i16>,
}

impl DecodingTileContext {
    fn new() -> Self {
        Self {
            tile_output: vec![0; usize::from(TILE_SIZE) * usize::from(TILE_SIZE) * 4],
            ycbcr_buffer: vec![vec![0; usize::from(TILE_SIZE) * usize::from(TILE_SIZE)]; 3],
            ycbcr_temp_buffer: vec![0; usize::from(TILE_SIZE) * usize::from(TILE_SIZE)],
        }
    }
}

#[derive(Debug, Clone)]
struct TileData<'a> {
    quants: [Quant; 3],
    data: [&'a [u8]; 3],
}

fn decode_tile(
    tile: &TileData<'_>,
    entropy_algorithm: EntropyAlgorithm,
    output: &mut [u8],
    ycbcr_temp: &mut [Vec<i16>],
    temp: &mut [i16],
) -> Result<()> {
    for ((quant, data), ycbcr_buffer) in tile.quants.iter().zip(tile.data.iter()).zip(ycbcr_temp.iter_mut()) {
        decode_component(quant, entropy_algorithm, data, ycbcr_buffer.as_mut_slice(), temp)?;
    }

    let ycbcr_buffer = YCbCrBuffer {
        y: ycbcr_temp[0].as_slice(),
        cb: ycbcr_temp[1].as_slice(),
        cr: ycbcr_temp[2].as_slice(),
    };

    color_conversion::ycbcr_to_rgba(ycbcr_buffer, output).context("convert RFX tile from YCbCr to RGBA")?;
    Ok(())
}

fn decode_component(
    quant: &Quant,
    entropy_algorithm: EntropyAlgorithm,
    data: &[u8],
    output: &mut [i16],
    temp: &mut [i16],
) -> Result<()> {
    rlgr::decode(entropy_algorithm, data, output).context("decode RFX RLGR stream")?;
    subband_reconstruction::decode(&mut output[4032..]);
    quantization::decode(output, quant);
    dwt::decode(output, temp);
    Ok(())
}

fn clipping_region(
    rectangles: &[RfxRectangle],
    surface_width: u16,
    surface_height: u16,
    channel_width: u16,
    channel_height: u16,
    placement: &RemoteFxPlacement,
) -> Region {
    let mut clipping_region = Region::new();
    let (origin_left, origin_top, max_right, max_bottom) = match placement {
        RemoteFxPlacement::SurfaceOrigin => (
            0,
            0,
            surface_width.saturating_sub(1).min(channel_width.saturating_sub(1)),
            surface_height.saturating_sub(1).min(channel_height.saturating_sub(1)),
        ),
        RemoteFxPlacement::Destination(destination) => (
            destination.left,
            destination.top,
            surface_width
                .saturating_sub(1)
                .min(destination.left.saturating_add(channel_width.saturating_sub(1))),
            surface_height
                .saturating_sub(1)
                .min(destination.top.saturating_add(channel_height.saturating_sub(1))),
        ),
    };

    for rectangle in rectangles {
        let left = origin_left.saturating_add(rectangle.x).min(max_right);
        let top = origin_top.saturating_add(rectangle.y).min(max_bottom);
        let right = rectangle
            .width
            .saturating_sub(1)
            .saturating_add(origin_left.saturating_add(rectangle.x))
            .min(max_right);
        let bottom = rectangle
            .height
            .saturating_sub(1)
            .saturating_add(origin_top.saturating_add(rectangle.y))
            .min(max_bottom);

        if left <= right && top <= bottom {
            clipping_region.union_rectangle(InclusiveRectangle {
                left,
                top,
                right,
                bottom,
            });
        }
    }

    clipping_region
}

fn tiles_to_rectangles<'a>(
    tiles: &'a [Tile<'a>],
    placement: &'a RemoteFxPlacement,
) -> impl Iterator<Item = InclusiveRectangle> + 'a {
    let (origin_left, origin_top) = match placement {
        RemoteFxPlacement::SurfaceOrigin => (0, 0),
        RemoteFxPlacement::Destination(destination) => (destination.left, destination.top),
    };

    tiles.iter().map(move |tile| InclusiveRectangle {
        left: origin_left.saturating_add(tile.x * TILE_SIZE),
        top: origin_top.saturating_add(tile.y * TILE_SIZE),
        right: origin_left.saturating_add(tile.x * TILE_SIZE + TILE_SIZE - 1),
        bottom: origin_top.saturating_add(tile.y * TILE_SIZE + TILE_SIZE - 1),
    })
}

fn map_tiles_data<'a>(tiles: &'a [Tile<'a>], quants: &[Quant]) -> Vec<TileData<'a>> {
    tiles
        .iter()
        .map(|tile| TileData {
            quants: [
                quants[usize::from(tile.y_quant_index)].clone(),
                quants[usize::from(tile.cb_quant_index)].clone(),
                quants[usize::from(tile.cr_quant_index)].clone(),
            ],
            data: [tile.y_data, tile.cb_data, tile.cr_data],
        })
        .collect()
}

fn crop_tile_regions(
    tile_bgra: &[u8],
    clipping_region: &Region,
    tile_rectangle: &InclusiveRectangle,
) -> Result<Vec<DecodedRfxRegion>> {
    let update_region = clipping_region.intersect_rectangle(tile_rectangle);
    let mut decoded_regions = Vec::with_capacity(update_region.rectangles.len());

    for region_rectangle in update_region.rectangles {
        let width = usize::from(region_rectangle.right.saturating_sub(region_rectangle.left)) + 1;
        let height = usize::from(region_rectangle.bottom.saturating_sub(region_rectangle.top)) + 1;
        let source_x = usize::from(region_rectangle.left.saturating_sub(tile_rectangle.left));
        let source_y = usize::from(region_rectangle.top.saturating_sub(tile_rectangle.top));
        let mut rgba_data = vec![0; width * height * 4];

        for row in 0..height {
            for col in 0..width {
                let src_index = ((source_y + row) * usize::from(TILE_SIZE) + (source_x + col)) * 4;
                let dst_index = (row * width + col) * 4;
                rgba_data[dst_index..dst_index + 4].copy_from_slice(&tile_bgra[src_index..src_index + 4]);
            }
        }

        decoded_regions.push(DecodedRfxRegion {
            rectangle: region_rectangle,
            rgba_data,
        });
    }

    Ok(decoded_regions)
}

#[cfg(all(test, target_os = "none"))]
pub(crate) fn encode_test_remote_fx_bitmap(width: u16, height: u16, color: [u8; 4], include_headers: bool) -> Vec<u8> {
    use ironrdp_core::encode_vec;
    use ironrdp_graphics::color_conversion::to_64x64_ycbcr_tile;
    use ironrdp_graphics::image_processing::PixelFormat as GraphicsPixelFormat;
    use ironrdp_graphics::rfx_encode_component;

    let entropy_algorithm = EntropyAlgorithm::Rlgr1;
    let quant = Quant::default();
    const TILE_PIXELS: usize = 64 * 64;
    let mut bitmap = vec![0; usize::from(width) * usize::from(height) * 4];
    for pixel in bitmap.chunks_exact_mut(4) {
        pixel.copy_from_slice(&color);
    }

    let tiles_x = usize::from(width).div_ceil(usize::from(TILE_SIZE));
    let tiles_y = usize::from(height).div_ceil(usize::from(TILE_SIZE));
    let mut tiles = Vec::with_capacity(tiles_x * tiles_y);
    let mut encoded_components = vec![0u8; usize::from(TILE_SIZE) * usize::from(TILE_SIZE) * 3 * tiles_x * tiles_y];
    let mut rest = encoded_components.as_mut_slice();

    for tile_y in 0..tiles_y {
        for tile_x in 0..tiles_x {
            let x = tile_x * usize::from(TILE_SIZE);
            let y = tile_y * usize::from(TILE_SIZE);
            let tile_width = (usize::from(width) - x).min(usize::from(TILE_SIZE));
            let tile_height = (usize::from(height) - y).min(usize::from(TILE_SIZE));
            let stride = usize::from(width) * 4;
            let input = &bitmap[y * stride + x * 4..];

            let y_plane = &mut [0i16; TILE_PIXELS];
            let cb_plane = &mut [0i16; TILE_PIXELS];
            let cr_plane = &mut [0i16; TILE_PIXELS];
            to_64x64_ycbcr_tile(
                input,
                tile_width,
                tile_height,
                stride,
                GraphicsPixelFormat::RgbA32,
                y_plane,
                cb_plane,
                cr_plane,
            );

            let (y_data, next_rest) = rest.split_at_mut(4096);
            let (cb_data, next_rest) = next_rest.split_at_mut(4096);
            let (cr_data, next_rest) = next_rest.split_at_mut(4096);
            rest = next_rest;

            let y_len = rfx_encode_component(y_plane, y_data, &quant, entropy_algorithm).expect("encode RFX Y");
            let cb_len = rfx_encode_component(cb_plane, cb_data, &quant, entropy_algorithm).expect("encode RFX Cb");
            let cr_len = rfx_encode_component(cr_plane, cr_data, &quant, entropy_algorithm).expect("encode RFX Cr");

            tiles.push(Tile {
                y_quant_index: 0,
                cb_quant_index: 0,
                cr_quant_index: 0,
                x: u16::try_from(tile_x).expect("tile x index fits u16"),
                y: u16::try_from(tile_y).expect("tile y index fits u16"),
                y_data: &y_data[..y_len],
                cb_data: &cb_data[..cb_len],
                cr_data: &cr_data[..cr_len],
            });
        }
    }

    let region = rfx::RegionPdu {
        rectangles: vec![RfxRectangle {
            x: 0,
            y: 0,
            width,
            height,
        }],
    };
    let tile_set = rfx::TileSetPdu {
        entropy_algorithm,
        quants: vec![quant],
        tiles,
    };
    let frame_begin = rfx::FrameBeginPdu {
        index: 0,
        number_of_regions: 1,
    };
    let frame_end = rfx::FrameEndPdu;
    let channels = rfx::Block::Channels(rfx::ChannelsPdu(vec![rfx::RfxChannel {
        width: i16::try_from(width).expect("width fits i16"),
        height: i16::try_from(height).expect("height fits i16"),
    }]));
    let context = rfx::Block::CodecChannel(CodecChannel::Context(rfx::ContextPdu {
        flags: rfx::OperatingMode::IMAGE_MODE,
        entropy_algorithm,
    }));
    let version = rfx::Block::CodecVersions(rfx::CodecVersionsPdu);
    let sync = rfx::Block::Sync(rfx::SyncPdu);
    let frame_begin = rfx::Block::CodecChannel(CodecChannel::FrameBegin(frame_begin));
    let region = rfx::Block::CodecChannel(CodecChannel::Region(region));
    let tile_set = rfx::Block::CodecChannel(CodecChannel::TileSet(tile_set));
    let frame_end = rfx::Block::CodecChannel(CodecChannel::FrameEnd(frame_end));

    let mut output = Vec::new();
    if include_headers {
        output.extend(encode_vec(&sync).expect("encode RFX sync"));
        output.extend(encode_vec(&version).expect("encode RFX codec versions"));
        output.extend(encode_vec(&channels).expect("encode RFX channels"));
        output.extend(encode_vec(&context).expect("encode RFX context"));
    }
    output.extend(encode_vec(&frame_begin).expect("encode RFX frame begin"));
    output.extend(encode_vec(&region).expect("encode RFX region"));
    output.extend(encode_vec(&tile_set).expect("encode RFX tileset"));
    output.extend(encode_vec(&frame_end).expect("encode RFX frame end"));

    output
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use super::*;

    #[test]
    fn decode_wire_to_surface_2_yields_rgba_regions() {
        let mut decoders = SurfaceRemoteFxDecoders::default();
        let bitmap_data = encode_test_remote_fx_bitmap(64, 64, [220, 10, 10, 255], true);

        let decoded = decoders
            .decode_wire_to_surface_2(1, 7, 64, 64, &bitmap_data)
            .expect("decode RFX bitmap");

        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].rectangle,
            InclusiveRectangle {
                left: 0,
                top: 0,
                right: 63,
                bottom: 63,
            }
        );

        let pixel = &decoded[0].rgba_data[..4];
        assert!(pixel[0] > pixel[1]);
        assert!(pixel[0] > pixel[2]);
        assert_eq!(pixel[3], 255);
    }

    #[test]
    fn decode_wire_to_surface_2_reuses_cached_context() {
        let mut decoders = SurfaceRemoteFxDecoders::default();
        let first = encode_test_remote_fx_bitmap(64, 64, [220, 10, 10, 255], true);
        let second = encode_test_remote_fx_bitmap(64, 64, [10, 220, 10, 255], false);

        decoders
            .decode_wire_to_surface_2(2, 3, 64, 64, &first)
            .expect("decode first RFX bitmap");
        let decoded = decoders
            .decode_wire_to_surface_2(2, 3, 64, 64, &second)
            .expect("decode second RFX bitmap");

        assert_eq!(decoded.len(), 1);
        let pixel = &decoded[0].rgba_data[..4];
        assert!(pixel[1] > pixel[0]);
        assert!(pixel[1] > pixel[2]);
        assert_eq!(pixel[3], 255);
    }

    #[test]
    fn decode_wire_to_surface_1_offsets_regions_to_destination() {
        let mut decoders = SurfaceRemoteFxDecoders::default();
        let bitmap_data = encode_test_remote_fx_bitmap(64, 64, [10, 220, 10, 255], true);
        let destination = InclusiveRectangle {
            left: 11,
            top: 12,
            right: 74,
            bottom: 75,
        };

        let decoded = decoders
            .decode_wire_to_surface_1(9, 128, 128, &destination, &bitmap_data)
            .expect("decode wire to surface1 RFX bitmap");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rectangle, destination);
        let pixel = &decoded[0].rgba_data[..4];
        assert!(pixel[1] > pixel[0]);
        assert!(pixel[1] > pixel[2]);
        assert_eq!(pixel[3], 255);
    }
}
