#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::similar_names,
    reason = "imported RDPEGFX NSCodec decoder keeps upstream structure while playback is being proven"
)]

use anyhow::{Context, Result, bail};

pub(crate) fn decode_nsc_bitmap_to_rgba(width: u16, height: u16, bitmap_data: &[u8]) -> Result<Vec<u8>> {
    let width = usize::from(width);
    let height = usize::from(height);

    if width == 0 || height == 0 {
        return Ok(Vec::new());
    }

    if bitmap_data.len() < 20 {
        bail!("NSCodec bitmap data is shorter than the 20-byte header");
    }

    let mut offset = 0usize;
    let mut plane_byte_counts = [0usize; 4];
    for plane_byte_count in &mut plane_byte_counts {
        *plane_byte_count = usize::try_from(u32::from_le_bytes(
            bitmap_data[offset..offset + 4]
                .try_into()
                .expect("slice length is validated"),
        ))
        .context("NSCodec plane byte count exceeds usize")?;
        offset += 4;
    }

    let color_loss_level = bitmap_data[offset];
    offset += 1;
    if !(1..=7).contains(&color_loss_level) {
        bail!("NSCodec ColorLossLevel must be in the inclusive range [1, 7]");
    }

    let chroma_subsampling = bitmap_data[offset] != 0;
    offset += 1;

    offset += 2; // reserved

    let total_plane_len = plane_byte_counts.iter().try_fold(0usize, |total, plane_len| {
        total
            .checked_add(*plane_len)
            .context("NSCodec plane byte counts overflow")
    })?;
    let plane_bytes_end = offset
        .checked_add(total_plane_len)
        .context("NSCodec plane payload end overflow")?;
    let plane_bytes = bitmap_data
        .get(offset..plane_bytes_end)
        .context("NSCodec plane payload extends past end of bitmap data")?;
    if plane_bytes_end != bitmap_data.len() {
        bail!("NSCodec bitmap data contains trailing bytes after the plane payload");
    }

    let plane_dimensions = NscPlaneDimensions::new(width, height, chroma_subsampling)?;
    let mut plane_offset = 0usize;
    let mut decoded_planes = Vec::with_capacity(4);
    for (plane_index, original_size) in plane_dimensions.original_sizes.iter().copied().enumerate() {
        let plane_size = plane_byte_counts[plane_index];
        let plane = plane_bytes
            .get(plane_offset..plane_offset + plane_size)
            .context("NSCodec plane bytes extend past end of payload")?;
        plane_offset += plane_size;
        decoded_planes.push(decode_nsc_plane(plane, plane_size, original_size)?);
    }

    let mut rgba_data = Vec::with_capacity(
        width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .context("NSCodec RGBA size overflow")?,
    );
    let shift = u32::from(color_loss_level - 1);
    let rw = plane_dimensions.rounded_width;
    let cw = plane_dimensions.chroma_width;

    for y in 0..height {
        for x in 0..width {
            let y_index = if chroma_subsampling { y * rw + x } else { y * width + x };
            let chroma_index = if chroma_subsampling {
                (y / 2) * cw + (x / 2)
            } else {
                y * width + x
            };
            let alpha_index = y * width + x;

            let y_value = i16::from(decoded_planes[0][y_index]);
            let co_value = i16::from(((i16::from(decoded_planes[1][chroma_index])) << shift) as i8);
            let cg_value = i16::from(((i16::from(decoded_planes[2][chroma_index])) << shift) as i8);
            let alpha = decoded_planes[3][alpha_index];

            let red = (y_value + co_value - cg_value).clamp(0, 0xFF) as u8;
            let green = (y_value + cg_value).clamp(0, 0xFF) as u8;
            let blue = (y_value - co_value - cg_value).clamp(0, 0xFF) as u8;

            rgba_data.extend_from_slice(&[red, green, blue, alpha]);
        }
    }

    Ok(rgba_data)
}

fn decode_nsc_plane(plane: &[u8], plane_size: usize, original_size: usize) -> Result<Vec<u8>> {
    if plane_size == 0 {
        return Ok(vec![0xFF; original_size]);
    }

    if plane_size < original_size {
        return decode_nsc_rle(plane, original_size);
    }

    Ok(plane
        .get(..original_size)
        .context("NSCodec raw plane bytes are shorter than the expected plane size")?
        .to_vec())
}

fn decode_nsc_rle(input: &[u8], original_size: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(original_size);
    let mut offset = 0usize;
    let mut left = original_size;

    while left > 4 {
        let value = *input
            .get(offset)
            .context("NSCodec RLE payload is truncated while reading a value byte")?;
        offset += 1;

        if left == 5 {
            output.push(value);
            left -= 1;
            continue;
        }

        if offset >= input.len() {
            bail!("NSCodec RLE payload is truncated while checking run prefix");
        }

        if value == input[offset] {
            offset += 1;
            let run_length = if *input
                .get(offset)
                .context("NSCodec RLE payload is truncated while reading run length")?
                < 0xFF
            {
                let run_length = usize::from(input[offset]) + 2;
                offset += 1;
                run_length
            } else {
                offset += 1;
                let run_length = usize::try_from(u32::from_le_bytes(
                    input
                        .get(offset..offset + 4)
                        .context("NSCodec RLE extended run length is truncated")?
                        .try_into()
                        .expect("slice length is validated"),
                ))
                .context("NSCodec RLE extended run length exceeds usize")?;
                offset += 4;
                run_length
            };
            if run_length > left {
                bail!("NSCodec RLE run length exceeds the remaining output size");
            }
            output.extend(std::iter::repeat_n(value, run_length));
            left -= run_length;
        } else {
            output.push(value);
            left -= 1;
        }
    }

    if left != 4 {
        bail!("NSCodec RLE output must end with a four-byte literal tail");
    }

    let tail = input
        .get(offset..offset + 4)
        .context("NSCodec RLE literal tail is truncated")?;
    output.extend_from_slice(tail);

    Ok(output)
}

struct NscPlaneDimensions {
    original_sizes: [usize; 4],
    rounded_width: usize,
    chroma_width: usize,
}

impl NscPlaneDimensions {
    fn new(width: usize, height: usize, chroma_subsampling: bool) -> Result<Self> {
        let alpha_size = width.checked_mul(height).context("NSCodec alpha plane size overflow")?;

        if !chroma_subsampling {
            return Ok(Self {
                original_sizes: [alpha_size; 4],
                rounded_width: width,
                chroma_width: width,
            });
        }

        let rounded_width = round_up_to(width, 8).context("NSCodec rounded width overflow")?;
        let rounded_height = round_up_to(height, 2).context("NSCodec rounded height overflow")?;
        let y_plane_size = rounded_width
            .checked_mul(height)
            .context("NSCodec luma plane size overflow")?;
        let chroma_width = rounded_width / 2;
        let chroma_height = rounded_height / 2;
        let chroma_plane_size = chroma_width
            .checked_mul(chroma_height)
            .context("NSCodec chroma plane size overflow")?;

        Ok(Self {
            original_sizes: [y_plane_size, chroma_plane_size, chroma_plane_size, alpha_size],
            rounded_width,
            chroma_width,
        })
    }
}

fn round_up_to(value: usize, multiple: usize) -> Option<usize> {
    let remainder = value % multiple;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(multiple - remainder)
    }
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use super::decode_nsc_bitmap_to_rgba;

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

    #[test]
    fn decode_nsc_bitmap_to_rgba_decodes_raw_planes_without_subsampling() {
        let bitmap_data = encode_nsc_bitmap([&[0x10, 0x20], &[0x00, 0x00], &[0x00, 0x00], &[0x30, 0x40]], 1, false);

        let decoded = decode_nsc_bitmap_to_rgba(2, 1, &bitmap_data).expect("decode NSCodec");

        assert_eq!(decoded, vec![0x10, 0x10, 0x10, 0x30, 0x20, 0x20, 0x20, 0x40]);
    }

    #[test]
    fn decode_nsc_bitmap_to_rgba_decodes_subsampled_planes() {
        let bitmap_data = encode_nsc_bitmap(
            [
                &[10, 20, 0, 0, 0, 0, 0, 0, 30, 40, 0, 0, 0, 0, 0, 0],
                &[0, 0, 0, 0],
                &[0, 0, 0, 0],
                &[0x80, 0x81, 0x82, 0x83],
            ],
            1,
            true,
        );

        let decoded = decode_nsc_bitmap_to_rgba(2, 2, &bitmap_data).expect("decode subsampled NSCodec");

        assert_eq!(
            decoded,
            vec![10, 10, 10, 0x80, 20, 20, 20, 0x81, 30, 30, 30, 0x82, 40, 40, 40, 0x83,]
        );
    }

    #[test]
    fn decode_nsc_bitmap_to_rgba_decodes_rle_planes() {
        let y_plane = [7, 7, 4, 7, 7, 7, 7];
        let chroma_plane = [0; 10];
        let bitmap_data = encode_nsc_bitmap([&y_plane, &chroma_plane, &chroma_plane, &[]], 1, false);

        let decoded = decode_nsc_bitmap_to_rgba(10, 1, &bitmap_data).expect("decode RLE NSCodec");

        assert_eq!(decoded, vec![7, 7, 7, 0xFF].repeat(10));
    }

    #[test]
    fn decode_nsc_bitmap_to_rgba_rejects_invalid_color_loss_level() {
        let bitmap_data = encode_nsc_bitmap([&[0x10], &[0x00], &[0x00], &[0xFF]], 0, false);

        let error = decode_nsc_bitmap_to_rgba(1, 1, &bitmap_data).unwrap_err();

        assert!(error.to_string().contains("ColorLossLevel"));
    }
}
