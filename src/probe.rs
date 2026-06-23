//! HTTP probing of discovered hosts: generic HEAD/GET probing plus the
//! Axis-specific `/axis-cgi/basicdeviceinfo.cgi` API. Ported from Go
//! `internal/probe`.

use std::time::Duration;

use reqwest::{Client, Method};

/// Maximum bytes read from a response body.
const MAX_BODY_READ: usize = 8192;
/// Per-request HTTP timeout.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const USER_AGENT: &str = "vapx-scan/1.0";

/// Outcome of probing a single host:port over plain HTTP(S).
#[derive(Debug, Default, Clone)]
pub struct HttpResult {
    pub server_header: String,
    pub body_markers: Vec<String>,
    pub title: String,
    pub status_code: u16,
}

/// Structured device information from the VAPIX
/// `basicdeviceinfo.cgi` `getAllUnrestrictedProperties` API.
#[derive(Debug, Default, Clone)]
pub struct DeviceInfo {
    pub prod_full_name: String,
    pub prod_short_name: String,
    pub prod_nbr: String,
    pub prod_type: String,
    pub serial_number: String,
    pub firmware: String,
    pub is_axis: bool,
}

/// Outcome of probing `/axis-cgi/basicdeviceinfo.cgi` with GET.
#[derive(Debug, Default, Clone)]
pub struct AxisCgiResult {
    pub is_axis: bool,
    pub status_code: u16,
}

fn build_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .expect("reqwest client build")
}

fn scheme_for(port: u16) -> &'static str {
    if port == 443 {
        "https"
    } else {
        "http"
    }
}

/// Probes the given IP and port with HEAD, falling back to GET. Extracts the
/// `Server` header and scans the body for Axis markers.
pub async fn http(ip: &str, port: u16) -> HttpResult {
    let url = format!("{}://{}:{}/", scheme_for(port), ip, port);
    let client = build_client();

    // Try HEAD first.
    if let Some(r) = do_request(&client, Method::HEAD, &url).await {
        if r.status_code >= 200 && r.status_code < 400 {
            return r;
        }
    }
    // Fallback to GET.
    do_request(&client, Method::GET, &url)
        .await
        .unwrap_or_default()
}

/// Performs a single request. Returns `None` on transport error (mirrors Go's
/// `Result{Err: err}` short-circuit). On GET, scans a limited body slice.
async fn do_request(client: &Client, method: Method, url: &str) -> Option<HttpResult> {
    let is_get = method == Method::GET;
    let resp = client.request(method, url).send().await.ok()?;

    let status_code = resp.status().as_u16();
    let server_header = resp
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut result = HttpResult {
        server_header,
        status_code,
        ..Default::default()
    };

    if is_get {
        if let Ok(bytes) = resp.bytes().await {
            let slice = &bytes[..bytes.len().min(MAX_BODY_READ)];
            let body = String::from_utf8_lossy(slice);
            result.body_markers = scan_markers(&body);
            result.title = extract_title(&body);
        }
    }
    Some(result)
}

/// Calls `basicdeviceinfo.cgi` with POST `getAllUnrestrictedProperties`,
/// returning rich device info (product name, serial, firmware) where the device
/// exposes it without authentication.
pub async fn get_device_info(ip: &str, port: u16) -> DeviceInfo {
    let url = format!(
        "{}://{}:{}/axis-cgi/basicdeviceinfo.cgi",
        scheme_for(port),
        ip,
        port
    );
    let client = build_client();
    let payload = r#"{"apiVersion":"1.3","method":"getAllUnrestrictedProperties"}"#;

    let resp = match client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return DeviceInfo::default(),
    };

    if resp.status().as_u16() != 200 {
        return DeviceInfo::default();
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return DeviceInfo::default(),
    };
    let slice = &bytes[..bytes.len().min(MAX_BODY_READ)];
    let body = String::from_utf8_lossy(slice);

    let mut info = DeviceInfo {
        prod_full_name: extract_json_field(&body, "ProdFullName"),
        prod_short_name: extract_json_field(&body, "ProdShortName"),
        prod_nbr: extract_json_field(&body, "ProdNbr"),
        prod_type: extract_json_field(&body, "ProdType"),
        serial_number: extract_json_field(&body, "SerialNumber"),
        firmware: extract_json_field(&body, "Version"),
        is_axis: false,
    };
    if !info.prod_full_name.is_empty() || !info.prod_short_name.is_empty() {
        info.is_axis = true;
    }
    info
}

/// Probes `/axis-cgi/basicdeviceinfo.cgi` with GET for legacy Axis detection.
/// A 200 or 401 response is treated as a strong Axis signal; a 200 whose body
/// lacks Axis markers is rejected (generic always-200 servers).
pub async fn axis_cgi(ip: &str, port: u16) -> AxisCgiResult {
    let url = format!(
        "{}://{}:{}/axis-cgi/basicdeviceinfo.cgi",
        scheme_for(port),
        ip,
        port
    );
    let client = build_client();

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return AxisCgiResult::default(),
    };
    let status_code = resp.status().as_u16();
    let mut result = AxisCgiResult {
        is_axis: status_code == 200 || status_code == 401,
        status_code,
    };

    if status_code == 200 {
        let body = resp
            .bytes()
            .await
            .map(|b| {
                let slice = &b[..b.len().min(MAX_BODY_READ)];
                String::from_utf8_lossy(slice).to_string()
            })
            .unwrap_or_default();
        let upper = body.to_uppercase();
        if !upper.contains("AXIS") && !upper.contains("BASICDEVICEINFO") {
            result.is_axis = false;
        }
    }
    result
}

/// Fetches `/webapp/index.shtml` and extracts the `<title>` tag. Axis devices
/// typically serve the product name here without authentication.
pub async fn webapp_title(ip: &str, port: u16) -> String {
    let url = format!("{}://{}:{}/webapp/index.shtml", scheme_for(port), ip, port);
    let client = build_client();

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return String::new(),
    };
    if resp.status().as_u16() != 200 {
        return String::new();
    }
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let slice = &bytes[..bytes.len().min(MAX_BODY_READ)];
    extract_title(&String::from_utf8_lossy(slice))
}

/// Strings we look for in a response body to identify Axis devices.
const AXIS_MARKERS: &[&str] = &["AXIS", "Axis Communications", "axis-cgi"];

fn scan_markers(body: &str) -> Vec<String> {
    let upper = body.to_uppercase();
    AXIS_MARKERS
        .iter()
        .filter(|m| upper.contains(&m.to_uppercase()))
        .map(|m| m.to_string())
        .collect()
}

/// Extracts the content of the first `<title>...</title>` tag. Returns empty
/// string if not found or if the title is generic ("Index page").
pub fn extract_title(body: &str) -> String {
    let lower = body.to_lowercase();
    let idx = match lower.find("<title>") {
        Some(i) => i,
        None => return String::new(),
    };
    let start = idx + "<title>".len();
    let end = match lower[start..].find("</title>") {
        Some(e) => e,
        None => return String::new(),
    };
    let title = body[start..start + end].trim();
    if title.is_empty() || title.eq_ignore_ascii_case("Index page") {
        return String::new();
    }
    title.to_string()
}

/// Minimal extraction of `"key": "value"` from a JSON string, tolerating an
/// optional space after the colon. Mirrors the Go helper.
fn extract_json_field(body: &str, key: &str) -> String {
    let mut needle = format!("\"{}\": \"", key);
    let idx = match body.find(&needle) {
        Some(i) => i,
        None => {
            needle = format!("\"{}\":\"", key);
            match body.find(&needle) {
                Some(i) => i,
                None => return String::new(),
            }
        }
    };
    let start = idx + needle.len();
    match body[start..].find('"') {
        Some(end) => body[start..start + end].to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_title_basic() {
        assert_eq!(
            extract_title("<html><title>AXIS P1375</title>"),
            "AXIS P1375"
        );
    }

    #[test]
    fn extract_title_skips_generic() {
        assert_eq!(extract_title("<title>Index page</title>"), "");
        assert_eq!(extract_title("<title>  </title>"), "");
        assert_eq!(extract_title("no title here"), "");
    }

    #[test]
    fn scan_markers_finds_axis() {
        let m = scan_markers("<html>AXIS Communications axis-cgi</html>");
        assert!(m.contains(&"AXIS".to_string()));
        assert!(m.contains(&"axis-cgi".to_string()));
    }

    #[test]
    fn json_field_extraction() {
        let body = r#"{"data":{"ProdNbr": "Q1615 Mk III","Version":"12.6.104"}}"#;
        assert_eq!(extract_json_field(body, "ProdNbr"), "Q1615 Mk III");
        // no space after colon variant
        assert_eq!(extract_json_field(body, "Version"), "12.6.104");
        assert_eq!(extract_json_field(body, "Missing"), "");
    }

    // HEAD→GET fallback against a tiny mock server: HEAD returns 405 so the
    // prober must fall back to GET, whose body yields a title + markers.
    #[tokio::test]
    async fn head_falls_back_to_get() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req.starts_with("HEAD") {
                        "HTTP/1.1 405 Method Not Allowed\r\nServer: AxisTest\r\nContent-Length: 0\r\n\r\n".to_string()
                    } else {
                        let body = "<html><title>AXIS Test Cam</title>axis-cgi</html>";
                        format!(
                            "HTTP/1.1 200 OK\r\nServer: AxisTest\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });

        let r = http(&addr.ip().to_string(), addr.port()).await;
        assert_eq!(r.server_header, "AxisTest");
        assert_eq!(r.title, "AXIS Test Cam");
        assert!(r.body_markers.contains(&"axis-cgi".to_string()));
    }
}
