use std::path::Path;

use image::Luma;
use qrcode::render::unicode;
use qrcode::QrCode;

use crate::error::Error;

/// Terminal-friendly QR using half-block Unicode characters.
pub fn qr_ascii(uri: &str) -> Result<String, Error> {
    let code = QrCode::new(uri.as_bytes()).map_err(|_| Error::InvalidOtpAuth)?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

pub fn write_qr_png(uri: &str, path: &Path) -> Result<(), Error> {
    let code = QrCode::new(uri.as_bytes()).map_err(|_| Error::InvalidOtpAuth)?;
    let image = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(256, 256)
        .build();
    image.save(path).map_err(|_| Error::Image)?;
    Ok(())
}

pub fn read_uri_from_image(path: &Path) -> Result<String, Error> {
    let img = image24::open(path).map_err(|_| Error::Image)?;
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    let grid = grids.into_iter().next().ok_or(Error::InvalidOtpAuth)?;
    let (_, content) = grid.decode().map_err(|_| Error::InvalidOtpAuth)?;
    Ok(content)
}

pub fn is_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            matches!(
                e.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp"
            )
        })
        .unwrap_or(false)
}
