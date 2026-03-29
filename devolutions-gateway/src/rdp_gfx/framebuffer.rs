//! Framebuffer management for RDPEGFX surfaces
//!
//! Maintains RGBA framebuffers for RDP graphics surfaces to enable
//! visual manipulation and steganography.

use anyhow::{Context, Result};

const BYTES_PER_PIXEL: u64 = 4;
const MAX_FRAMEBUFFER_BYTES: usize = 512 * 1024 * 1024;

/// RGBA framebuffer for a graphics surface
#[derive(Debug, Clone)]
pub struct Framebuffer {
    width: u32,
    height: u32,
    data: Vec<u8>, // RGBA format: 4 bytes per pixel
}

impl Framebuffer {
    /// Create a new framebuffer with given dimensions
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let size = checked_buffer_len(width, height)?;

        Ok(Self {
            width,
            height,
            data: vec![0; size],
        })
    }

    /// Get framebuffer width
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get framebuffer height
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get reference to pixel data (RGBA format)
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable reference to pixel data (RGBA format)
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Update a rectangular region of the framebuffer
    pub fn update_region(&mut self, x: u32, y: u32, width: u32, height: u32, source_data: &[u8]) -> Result<()> {
        // Validate bounds
        let right = x.checked_add(width).context("update region x overflow")?;
        let bottom = y.checked_add(height).context("update region y overflow")?;
        if right > self.width || bottom > self.height {
            anyhow::bail!(
                "Update region out of bounds: {}x{} at ({},{}) exceeds framebuffer {}x{}",
                width,
                height,
                x,
                y,
                self.width,
                self.height
            );
        }

        let expected_size = checked_buffer_len(width, height)?;
        if source_data.len() < expected_size {
            anyhow::bail!(
                "Source data too small: {} bytes, expected {}",
                source_data.len(),
                expected_size
            );
        }

        // Copy data row by row
        let row_bytes = checked_row_bytes(width)?;
        for row in 0..height {
            let dest_y = y + row;
            let dest_offset = checked_pixel_offset(self.width, x, dest_y)?;
            let source_offset = checked_pixel_offset(width, 0, row)?;

            if dest_offset
                .checked_add(row_bytes)
                .is_none_or(|end| end > self.data.len())
            {
                anyhow::bail!("Destination framebuffer offset overflow");
            }
            if source_offset
                .checked_add(row_bytes)
                .is_none_or(|end| end > source_data.len())
            {
                anyhow::bail!("Source framebuffer offset overflow");
            }

            self.data[dest_offset..dest_offset + row_bytes]
                .copy_from_slice(&source_data[source_offset..source_offset + row_bytes]);
        }

        Ok(())
    }

    /// Update only the alpha channel of a rectangular region
    pub fn update_alpha_region(&mut self, x: u32, y: u32, width: u32, height: u32, alpha_data: &[u8]) -> Result<()> {
        let right = x.checked_add(width).context("alpha region x overflow")?;
        let bottom = y.checked_add(height).context("alpha region y overflow")?;
        if right > self.width || bottom > self.height {
            anyhow::bail!(
                "Alpha update region out of bounds: {}x{} at ({},{}) exceeds framebuffer {}x{}",
                width,
                height,
                x,
                y,
                self.width,
                self.height
            );
        }

        let expected_pixels = usize::try_from(
            u64::from(width)
                .checked_mul(u64::from(height))
                .context("alpha region pixel count overflow")?,
        )
        .context("alpha region pixel count exceeds usize")?;
        if alpha_data.len() < expected_pixels {
            anyhow::bail!(
                "Alpha data too small: {} bytes, expected {}",
                alpha_data.len(),
                expected_pixels
            );
        }

        let width_usize = usize::try_from(width).context("alpha region width exceeds usize")?;
        let height_usize = usize::try_from(height).context("alpha region height exceeds usize")?;
        for row in 0..height_usize {
            for col in 0..width_usize {
                let dest_x = x + u32::try_from(col).context("alpha region column exceeds u32")?;
                let dest_y = y + u32::try_from(row).context("alpha region row exceeds u32")?;
                let dest_offset = checked_pixel_offset(self.width, dest_x, dest_y)?;
                let alpha_offset = row
                    .checked_mul(width_usize)
                    .and_then(|base| base.checked_add(col))
                    .context("alpha region source offset overflow")?;
                self.data[dest_offset + 3] = alpha_data[alpha_offset];
            }
        }

        Ok(())
    }

    /// Copy a rectangular RGBA region out of the framebuffer
    pub fn copy_region(&self, x: u32, y: u32, width: u32, height: u32) -> Result<Vec<u8>> {
        let right = x.checked_add(width).context("copy region x overflow")?;
        let bottom = y.checked_add(height).context("copy region y overflow")?;
        if right > self.width || bottom > self.height {
            anyhow::bail!(
                "Copy region out of bounds: {}x{} at ({},{}) exceeds framebuffer {}x{}",
                width,
                height,
                x,
                y,
                self.width,
                self.height
            );
        }

        let expected_size = checked_buffer_len(width, height)?;
        let row_bytes = checked_row_bytes(width)?;
        let mut out = vec![0; expected_size];

        for row in 0..height {
            let dest_offset = checked_pixel_offset(width, 0, row)?;
            let source_offset = checked_pixel_offset(self.width, x, y + row)?;
            out[dest_offset..dest_offset + row_bytes]
                .copy_from_slice(&self.data[source_offset..source_offset + row_bytes]);
        }

        Ok(out)
    }

    /// Get pixel at (x, y) as RGBA tuple
    pub fn get_pixel(&self, x: u32, y: u32) -> Option<(u8, u8, u8, u8)> {
        if x >= self.width || y >= self.height {
            return None;
        }

        let offset = checked_pixel_offset(self.width, x, y).ok()?;
        Some((
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ))
    }

    /// Set pixel at (x, y) to RGBA value
    pub fn set_pixel(&mut self, x: u32, y: u32, r: u8, g: u8, b: u8, a: u8) -> Result<()> {
        if x >= self.width || y >= self.height {
            anyhow::bail!("Pixel out of bounds: ({},{}) in {}x{}", x, y, self.width, self.height);
        }

        let offset = checked_pixel_offset(self.width, x, y)?;
        self.data[offset] = r;
        self.data[offset + 1] = g;
        self.data[offset + 2] = b;
        self.data[offset + 3] = a;

        Ok(())
    }

    /// Clear framebuffer to black
    pub fn clear(&mut self) {
        self.data.fill(0);
    }
}

fn checked_row_bytes(width: u32) -> Result<usize> {
    usize::try_from(
        u64::from(width)
            .checked_mul(BYTES_PER_PIXEL)
            .context("framebuffer row byte count overflow")?,
    )
    .context("framebuffer row byte count exceeds usize")
}

fn checked_buffer_len(width: u32, height: u32) -> Result<usize> {
    let size = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(BYTES_PER_PIXEL))
        .context("framebuffer allocation size overflow")?;
    let size = usize::try_from(size).context("framebuffer allocation exceeds usize")?;

    if size > MAX_FRAMEBUFFER_BYTES {
        anyhow::bail!(
            "framebuffer allocation too large: {} bytes exceeds {} bytes",
            size,
            MAX_FRAMEBUFFER_BYTES
        );
    }

    Ok(size)
}

fn checked_pixel_offset(width: u32, x: u32, y: u32) -> Result<usize> {
    usize::try_from(
        u64::from(y)
            .checked_mul(u64::from(width))
            .and_then(|row| row.checked_add(u64::from(x)))
            .and_then(|pixel| pixel.checked_mul(BYTES_PER_PIXEL))
            .context("framebuffer pixel offset overflow")?,
    )
    .context("framebuffer pixel offset exceeds usize")
}

#[cfg(all(test, target_os = "none"))]
mod tests {
    use super::*;

    #[test]
    fn test_framebuffer_creation() {
        let fb = Framebuffer::new(640, 480).unwrap();
        assert_eq!(fb.width(), 640);
        assert_eq!(fb.height(), 480);
        assert_eq!(fb.data().len(), 640 * 480 * 4);
    }

    #[test]
    fn test_framebuffer_clear() {
        let mut fb = Framebuffer::new(10, 10).unwrap();
        fb.data_mut().fill(255); // Fill with white
        assert_eq!(fb.data()[0], 255);

        fb.clear();
        assert_eq!(fb.data()[0], 0);
    }

    #[test]
    fn test_set_get_pixel() {
        let mut fb = Framebuffer::new(10, 10).unwrap();

        fb.set_pixel(5, 5, 255, 128, 64, 255).unwrap();
        let pixel = fb.get_pixel(5, 5).unwrap();

        assert_eq!(pixel, (255, 128, 64, 255));
    }

    #[test]
    fn test_get_pixel_out_of_bounds() {
        let fb = Framebuffer::new(10, 10).unwrap();
        assert!(fb.get_pixel(10, 10).is_none());
        assert!(fb.get_pixel(5, 15).is_none());
    }

    #[test]
    fn test_set_pixel_out_of_bounds() {
        let mut fb = Framebuffer::new(10, 10).unwrap();
        let result = fb.set_pixel(10, 10, 255, 255, 255, 255);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_region() {
        let mut fb = Framebuffer::new(100, 100).unwrap();

        // Create 10x10 red square data
        let mut region_data = vec![0u8; 10 * 10 * 4];
        for i in 0..10 * 10 {
            region_data[i * 4] = 255; // R
            region_data[i * 4 + 1] = 0; // G
            region_data[i * 4 + 2] = 0; // B
            region_data[i * 4 + 3] = 255; // A
        }

        // Update region at (50, 50)
        fb.update_region(50, 50, 10, 10, &region_data).unwrap();

        // Verify pixel in updated region
        let pixel = fb.get_pixel(55, 55).unwrap();
        assert_eq!(pixel, (255, 0, 0, 255)); // Red

        // Verify pixel outside updated region
        let pixel = fb.get_pixel(10, 10).unwrap();
        assert_eq!(pixel, (0, 0, 0, 0)); // Black (untouched)
    }

    #[test]
    fn test_update_region_out_of_bounds() {
        let mut fb = Framebuffer::new(100, 100).unwrap();
        let region_data = vec![0u8; 20 * 20 * 4];

        // Try to update region that exceeds bounds
        let result = fb.update_region(95, 95, 20, 20, &region_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_region_insufficient_data() {
        let mut fb = Framebuffer::new(100, 100).unwrap();
        let region_data = vec![0u8; 10]; // Too small for 10x10 region

        let result = fb.update_region(10, 10, 10, 10, &region_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_framebuffer_creation_rejects_oversized_surface() {
        let result = Framebuffer::new(u16::MAX as u32, u16::MAX as u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_region_rejects_coordinate_overflow() {
        let mut fb = Framebuffer::new(100, 100).unwrap();
        let region_data = vec![0u8; 4];

        let result = fb.update_region(u32::MAX, 0, 1, 1, &region_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_alpha_region() {
        let mut fb = Framebuffer::new(4, 4).unwrap();
        fb.set_pixel(1, 2, 10, 20, 30, 40).unwrap();
        fb.set_pixel(2, 2, 50, 60, 70, 80).unwrap();

        fb.update_alpha_region(1, 2, 2, 1, &[0xAA, 0xBB]).unwrap();

        assert_eq!(fb.get_pixel(1, 2), Some((10, 20, 30, 0xAA)));
        assert_eq!(fb.get_pixel(2, 2), Some((50, 60, 70, 0xBB)));
    }

    #[test]
    fn test_copy_region() {
        let mut fb = Framebuffer::new(4, 4).unwrap();
        fb.set_pixel(1, 1, 10, 20, 30, 40).unwrap();
        fb.set_pixel(2, 1, 50, 60, 70, 80).unwrap();

        let region = fb.copy_region(1, 1, 2, 1).unwrap();
        assert_eq!(region, vec![10, 20, 30, 40, 50, 60, 70, 80]);
    }
}
