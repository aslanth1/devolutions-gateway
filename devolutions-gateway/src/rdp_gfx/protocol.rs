//! Minimal RDPEGFX protocol parsing shared by the filter and future producer work.

use ironrdp_core::decode;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::vc::dvc::gfx::{Codec1Type, Codec2Type, PixelFormat, Point, ServerPdu};

pub const RDPEGFX_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfxPduType {
    CreateSurface,
    DeleteSurface,
    WireToSurface1,
    WireToSurface2,
    DeleteEncodingContext,
    SurfaceToCache,
    CacheToSurface,
    EvictCacheEntry,
}

impl GfxPduType {
    pub fn from_cmd_id(cmd_id: u16) -> Option<Self> {
        match cmd_id {
            0x0001 => Some(Self::WireToSurface1),
            0x0002 => Some(Self::WireToSurface2),
            0x0003 => Some(Self::DeleteEncodingContext),
            0x0006 => Some(Self::SurfaceToCache),
            0x0007 => Some(Self::CacheToSurface),
            0x0008 => Some(Self::EvictCacheEntry),
            0x0009 => Some(Self::CreateSurface),
            0x000A => Some(Self::DeleteSurface),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxPduHeader {
    pub cmd_id: u16,
    pub flags: u16,
    pub pdu_length: u32,
    pub pdu_type: GfxPduType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedGfxPdu {
    CreateSurface {
        header: GfxPduHeader,
        surface_id: u16,
        width: u16,
        height: u16,
        pixel_format: PixelFormat,
    },
    DeleteSurface {
        header: GfxPduHeader,
        surface_id: u16,
    },
    WireToSurface1 {
        header: GfxPduHeader,
        surface_id: u16,
        codec_id: Codec1Type,
        pixel_format: PixelFormat,
        destination_rectangle: InclusiveRectangle,
        bitmap_data: Vec<u8>,
    },
    WireToSurface2 {
        header: GfxPduHeader,
        surface_id: u16,
        codec_id: Codec2Type,
        codec_context_id: u32,
        pixel_format: PixelFormat,
        bitmap_data: Vec<u8>,
    },
    DeleteEncodingContext {
        header: GfxPduHeader,
        surface_id: u16,
        codec_context_id: u32,
    },
    SurfaceToCache {
        header: GfxPduHeader,
        surface_id: u16,
        cache_key: u64,
        cache_slot: u16,
        source_rectangle: InclusiveRectangle,
    },
    CacheToSurface {
        header: GfxPduHeader,
        cache_slot: u16,
        surface_id: u16,
        destination_points: Vec<Point>,
    },
    EvictCacheEntry {
        header: GfxPduHeader,
        cache_slot: u16,
    },
    Unsupported {
        header: GfxPduHeader,
        payload: Vec<u8>,
    },
}

impl ParsedGfxPdu {
    pub fn header(&self) -> &GfxPduHeader {
        match self {
            Self::CreateSurface { header, .. }
            | Self::DeleteSurface { header, .. }
            | Self::WireToSurface1 { header, .. }
            | Self::WireToSurface2 { header, .. }
            | Self::DeleteEncodingContext { header, .. }
            | Self::SurfaceToCache { header, .. }
            | Self::CacheToSurface { header, .. }
            | Self::EvictCacheEntry { header, .. }
            | Self::Unsupported { header, .. } => header,
        }
    }

    pub fn pdu_type(&self) -> GfxPduType {
        self.header().pdu_type
    }
}

pub fn parse_gfx_pdu_header(data: &[u8]) -> Option<GfxPduHeader> {
    if data.len() < RDPEGFX_HEADER_LEN {
        return None;
    }

    let cmd_id = u16::from_le_bytes([data[0], data[1]]);
    let flags = u16::from_le_bytes([data[2], data[3]]);
    let pdu_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let pdu_type = GfxPduType::from_cmd_id(cmd_id)?;

    Some(GfxPduHeader {
        cmd_id,
        flags,
        pdu_length,
        pdu_type,
    })
}

pub fn parse_gfx_pdu(data: &[u8]) -> Option<ParsedGfxPdu> {
    let header = parse_gfx_pdu_header(data)?;
    let pdu = decode::<ServerPdu>(data).ok()?;

    match pdu {
        ServerPdu::CreateSurface(pdu) => Some(ParsedGfxPdu::CreateSurface {
            header,
            surface_id: pdu.surface_id,
            width: pdu.width,
            height: pdu.height,
            pixel_format: pdu.pixel_format,
        }),
        ServerPdu::DeleteSurface(pdu) => Some(ParsedGfxPdu::DeleteSurface {
            header,
            surface_id: pdu.surface_id,
        }),
        ServerPdu::WireToSurface1(pdu) => Some(ParsedGfxPdu::WireToSurface1 {
            header,
            surface_id: pdu.surface_id,
            codec_id: pdu.codec_id,
            pixel_format: pdu.pixel_format,
            destination_rectangle: pdu.destination_rectangle,
            bitmap_data: pdu.bitmap_data,
        }),
        ServerPdu::WireToSurface2(pdu) => Some(ParsedGfxPdu::WireToSurface2 {
            header,
            surface_id: pdu.surface_id,
            codec_id: pdu.codec_id,
            codec_context_id: pdu.codec_context_id,
            pixel_format: pdu.pixel_format,
            bitmap_data: pdu.bitmap_data,
        }),
        ServerPdu::DeleteEncodingContext(pdu) => Some(ParsedGfxPdu::DeleteEncodingContext {
            header,
            surface_id: pdu.surface_id,
            codec_context_id: pdu.codec_context_id,
        }),
        ServerPdu::SurfaceToCache(pdu) => Some(ParsedGfxPdu::SurfaceToCache {
            header,
            surface_id: pdu.surface_id,
            cache_key: pdu.cache_key,
            cache_slot: pdu.cache_slot,
            source_rectangle: pdu.source_rectangle,
        }),
        ServerPdu::CacheToSurface(pdu) => Some(ParsedGfxPdu::CacheToSurface {
            header,
            cache_slot: pdu.cache_slot,
            surface_id: pdu.surface_id,
            destination_points: pdu.destination_points,
        }),
        ServerPdu::EvictCacheEntry(pdu) => Some(ParsedGfxPdu::EvictCacheEntry {
            header,
            cache_slot: pdu.cache_slot,
        }),
        _ => Some(ParsedGfxPdu::Unsupported {
            header,
            payload: data[RDPEGFX_HEADER_LEN..].to_vec(),
        }),
    }
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::geometry::InclusiveRectangle;
    use ironrdp_pdu::rdp::vc::dvc::gfx::{
        CacheToSurfacePdu, Codec2Type, CreateSurfacePdu, DeleteEncodingContextPdu, EvictCacheEntryPdu, PixelFormat,
        Point, ServerPdu, SurfaceToCachePdu, WireToSurface1Pdu, WireToSurface2Pdu,
    };

    use super::*;

    #[test]
    fn parse_header_extracts_type_and_flags() {
        let pdu = [0x01, 0x00, 0x34, 0x12, 0x14, 0x00, 0x00, 0x00];
        let header = parse_gfx_pdu_header(&pdu).expect("header");

        assert_eq!(header.pdu_type, GfxPduType::WireToSurface1);
        assert_eq!(header.flags, 0x1234);
        assert_eq!(header.pdu_length, 20);
    }

    #[test]
    fn parse_wire_to_surface_extracts_bitmap_payload() {
        let pdu = encode_vec(&ServerPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id: 2,
            codec_id: Codec1Type::Uncompressed,
            pixel_format: PixelFormat::ARgb,
            destination_rectangle: InclusiveRectangle {
                left: 3,
                top: 4,
                right: 7,
                bottom: 9,
            },
            bitmap_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }))
        .expect("encode gfx pdu");

        let parsed = parse_gfx_pdu(&pdu).expect("pdu");
        match parsed {
            ParsedGfxPdu::WireToSurface1 {
                surface_id,
                destination_rectangle,
                bitmap_data,
                ..
            } => {
                assert_eq!(surface_id, 2);
                assert_eq!(destination_rectangle.left, 3);
                assert_eq!(destination_rectangle.top, 4);
                assert_eq!(destination_rectangle.right, 7);
                assert_eq!(destination_rectangle.bottom, 9);
                assert_eq!(bitmap_data, &[0xAA, 0xBB, 0xCC, 0xDD]);
            }
            other => panic!("unexpected parsed PDU: {other:?}"),
        }
    }

    #[test]
    fn parse_wire_to_surface2_uses_real_irondrp_layout() {
        let pdu = encode_vec(&ServerPdu::WireToSurface2(WireToSurface2Pdu {
            surface_id: 9,
            codec_id: Codec2Type::RemoteFxProgressive,
            codec_context_id: 0x0102_0304,
            pixel_format: PixelFormat::ARgb,
            bitmap_data: vec![0x11, 0x22, 0x33, 0x44],
        }))
        .expect("encode wire to surface2");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::WireToSurface2 {
                surface_id: 9,
                codec_id: Codec2Type::RemoteFxProgressive,
                codec_context_id: 0x0102_0304,
                pixel_format: PixelFormat::ARgb,
                bitmap_data,
                ..
            }) if bitmap_data == vec![0x11, 0x22, 0x33, 0x44]
        ));
    }

    #[test]
    fn parse_delete_encoding_context_uses_real_irondrp_layout() {
        let pdu = encode_vec(&ServerPdu::DeleteEncodingContext(DeleteEncodingContextPdu {
            surface_id: 12,
            codec_context_id: 0x1122_3344,
        }))
        .expect("encode delete encoding context");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::DeleteEncodingContext {
                surface_id: 12,
                codec_context_id: 0x1122_3344,
                ..
            })
        ));
    }

    #[test]
    fn parse_create_surface_uses_real_irondrp_layout() {
        let pdu = encode_vec(&ServerPdu::CreateSurface(CreateSurfacePdu {
            surface_id: 7,
            width: 1920,
            height: 1080,
            pixel_format: PixelFormat::ARgb,
        }))
        .expect("encode create surface");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::CreateSurface {
                surface_id: 7,
                width: 1920,
                height: 1080,
                pixel_format: PixelFormat::ARgb,
                ..
            })
        ));
    }

    #[test]
    fn parse_surface_to_cache_uses_real_irondrp_layout() {
        let rectangle = InclusiveRectangle {
            left: 10,
            top: 11,
            right: 19,
            bottom: 20,
        };
        let pdu = encode_vec(&ServerPdu::SurfaceToCache(SurfaceToCachePdu {
            surface_id: 7,
            cache_key: 0x1122_3344_5566_7788,
            cache_slot: 9,
            source_rectangle: rectangle.clone(),
        }))
        .expect("encode surface to cache");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::SurfaceToCache {
                surface_id: 7,
                cache_key: 0x1122_3344_5566_7788,
                cache_slot: 9,
                source_rectangle,
                ..
            }) if source_rectangle == rectangle
        ));
    }

    #[test]
    fn parse_cache_to_surface_uses_real_irondrp_layout() {
        let destination_points = vec![Point { x: 30, y: 40 }, Point { x: 50, y: 60 }];
        let pdu = encode_vec(&ServerPdu::CacheToSurface(CacheToSurfacePdu {
            cache_slot: 4,
            surface_id: 8,
            destination_points: destination_points.clone(),
        }))
        .expect("encode cache to surface");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::CacheToSurface {
                cache_slot: 4,
                surface_id: 8,
                destination_points: parsed_points,
                ..
            }) if parsed_points == destination_points
        ));
    }

    #[test]
    fn parse_evict_cache_entry_uses_real_irondrp_layout() {
        let pdu = encode_vec(&ServerPdu::EvictCacheEntry(EvictCacheEntryPdu { cache_slot: 6 }))
            .expect("encode evict cache entry");

        assert!(matches!(
            parse_gfx_pdu(&pdu),
            Some(ParsedGfxPdu::EvictCacheEntry { cache_slot: 6, .. })
        ));
    }
}
