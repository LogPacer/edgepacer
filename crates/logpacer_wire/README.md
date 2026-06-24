# logpacer_wire

Vendored protobuf schema and generated Rust types for EdgePacer traffic to
LogPacer services.

The canonical schema lives in `proto/logpacer_wire.proto`. This crate is kept in
the EdgePacer workspace so the public repository builds from one checkout.

## Endpoint

| Endpoint | Format | Payload |
|----------|--------|---------|
| `POST /v1/logpacer-wire` | protobuf | `WireRequest` with routed logs, metrics, graph, traces, or eBPF batches |

## Compatibility

- Protobuf field numbers are never reused.
- Removed fields stay reserved in the schema.
- `schema_version` on `RoutedBatch` is available for runtime negotiation.
