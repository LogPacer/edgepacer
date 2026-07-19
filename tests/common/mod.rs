use std::io::Read;

use axum::http::{HeaderMap, header};
use flate2::read::GzDecoder;
use logpacer_wire::WireRequest;
use prost::Message;

pub fn decode_wire_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, String> {
    match headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    {
        None => Ok(body.to_vec()),
        Some(value) if value.eq_ignore_ascii_case("gzip") => {
            let mut decoded = Vec::new();
            GzDecoder::new(body)
                .read_to_end(&mut decoded)
                .map_err(|error| format!("invalid gzip wire body: {error}"))?;
            Ok(decoded)
        }
        Some(value) => Err(format!("unsupported wire content encoding: {value}")),
    }
}

pub fn decode_wire_request(request: &wiremock::Request) -> WireRequest {
    let decoded = decode_wire_body(&request.headers, &request.body)
        .expect("captured request body should use a supported encoding");
    WireRequest::decode(decoded.as_slice()).expect("captured body should be a valid WireRequest")
}

pub fn assert_gzip(request: &wiremock::Request) {
    assert_eq!(
        request
            .headers
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
}
