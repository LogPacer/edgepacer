# logpacer_wire

Vendored protobuf schema and generated Rust types for EdgePacer traffic to
LogPacer services.

The canonical schema lives in `proto/logpacer_wire.proto`. This crate is kept in
the EdgePacer workspace so the public repository builds from one checkout.

## Endpoint

| Endpoint | Format | Payload |
|----------|--------|---------|
| `POST /v1/logpacer-wire` | protobuf, optionally gzip-encoded | `WireRequest` with routed logs, metrics, graph, traces, or eBPF batches |

Producers may send the protobuf body raw or with `Content-Encoding: gzip`.
Receivers must accept both forms during mixed-version rollouts and must bound
the decompressed body size. EdgePacer sends gzip bodies and keeps
`Content-Type: application/x-protobuf`.

## Compatibility

- Protobuf field numbers are never reused.
- Removed fields stay reserved in the schema.
- `schema_version` on `RoutedBatch` is available for runtime negotiation.
