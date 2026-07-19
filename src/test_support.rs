use std::io::Read;

use flate2::read::GzDecoder;
use logpacer_wire::WireRequest;
use prost::Message;
use reqwest::header::CONTENT_ENCODING;

pub(crate) fn gunzip_wire_body(request: &wiremock::Request) -> Vec<u8> {
    assert_eq!(
        request
            .headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let mut decoded = Vec::new();
    GzDecoder::new(request.body.as_slice())
        .read_to_end(&mut decoded)
        .expect("request body should be valid gzip");
    decoded
}

pub(crate) fn decode_gzip_wire_request(request: &wiremock::Request) -> WireRequest {
    WireRequest::decode(gunzip_wire_body(request).as_slice())
        .expect("request body should decode as WireRequest")
}
