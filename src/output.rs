//! Formats device lists for display. Ported from Go `internal/output`.

use std::io::{self, Write};

use crate::model::Device;

/// Writes devices as an aligned table with columns URL, PRODUCT, FIRMWARE,
/// SERIAL. Optional columns are only shown when at least one device has data
/// for them. Column widths are sized to fit the data.
pub fn plain<W: Write>(w: &mut W, devices: &[Device]) -> io::Result<()> {
    if devices.is_empty() {
        return Ok(());
    }

    struct Row {
        url: String,
        product: String,
        firmware: String,
        serial: String,
    }

    let mut rows = Vec::with_capacity(devices.len());
    let (mut w_url, mut w_prod, mut w_fw, mut w_ser) = (
        chars("URL"),
        chars("PRODUCT"),
        chars("FIRMWARE"),
        chars("SERIAL"),
    );

    for d in devices {
        let product = d.hints.device_name.clone();
        let firmware = d.hints.firmware.clone();
        let serial = if !d.hints.serial_number.is_empty() {
            d.hints.serial_number.clone()
        } else {
            d.hints.mac.clone()
        };
        let r = Row {
            url: d.url.clone(),
            product,
            firmware,
            serial,
        };
        w_url = w_url.max(chars(&r.url));
        w_prod = w_prod.max(chars(&r.product));
        w_fw = w_fw.max(chars(&r.firmware));
        w_ser = w_ser.max(chars(&r.serial));
        rows.push(r);
    }

    let has_prod = rows.iter().any(|r| !r.product.is_empty());
    let has_fw = rows.iter().any(|r| !r.firmware.is_empty());
    let has_ser = rows.iter().any(|r| !r.serial.is_empty());

    // Header + separator.
    let mut hdr = pad_right("URL", w_url);
    let mut sep = "─".repeat(w_url);
    if has_prod {
        hdr += &("  ".to_string() + &pad_right("PRODUCT", w_prod));
        sep += &("  ".to_string() + &"─".repeat(w_prod));
    }
    if has_fw {
        hdr += &("  ".to_string() + &pad_right("FIRMWARE", w_fw));
        sep += &("  ".to_string() + &"─".repeat(w_fw));
    }
    if has_ser {
        hdr += &("  ".to_string() + &pad_right("SERIAL", w_ser));
        sep += &("  ".to_string() + &"─".repeat(w_ser));
    }
    writeln!(w, "{}", hdr)?;
    writeln!(w, "{}", sep)?;

    for r in &rows {
        let mut line = pad_right(&r.url, w_url);
        if has_prod {
            let v = if r.product.is_empty() {
                "—"
            } else {
                &r.product
            };
            line += &("  ".to_string() + &pad_right(v, w_prod));
        }
        if has_fw {
            let v = if r.firmware.is_empty() {
                "—"
            } else {
                &r.firmware
            };
            line += &("  ".to_string() + &pad_right(v, w_fw));
        }
        if has_ser {
            let v = if r.serial.is_empty() {
                "—"
            } else {
                &r.serial
            };
            line += &("  ".to_string() + &pad_right(v, w_ser));
        }
        writeln!(w, "{}", line.trim_end())?;
    }

    Ok(())
}

/// Writes the device list as indented JSON, followed by a trailing newline
/// (matching Go's `json.Encoder`).
pub fn json<W: Write>(w: &mut W, devices: &[Device]) -> io::Result<()> {
    let s = serde_json::to_string_pretty(devices).map_err(io::Error::other)?;
    writeln!(w, "{}", s)
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Left-justifies `s`, padding with spaces to `width` characters.
fn pad_right(s: &str, width: usize) -> String {
    let len = chars(s);
    if len >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + (width - len));
        out.push_str(s);
        out.extend(std::iter::repeat_n(' ', width - len));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Device;
    use std::net::IpAddr;

    fn dev(ip: &str) -> Device {
        Device::new(ip.parse::<IpAddr>().unwrap(), "test")
    }

    #[test]
    fn empty_produces_no_output() {
        let mut buf = Vec::new();
        plain(&mut buf, &[]).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn plain_includes_url_header() {
        let mut buf = Vec::new();
        plain(&mut buf, &[dev("192.168.1.10")]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("URL"));
        assert!(s.contains("http://192.168.1.10/"));
    }

    #[test]
    fn json_is_array_with_trailing_newline() {
        let mut buf = Vec::new();
        json(&mut buf, &[dev("10.0.0.1")]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with('['));
        assert!(s.ends_with("\n"));
        assert!(s.contains("\"ip\": \"10.0.0.1\""));
        assert!(s.contains("\"confidence\": \"none\""));
    }
}
