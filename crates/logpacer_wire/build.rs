fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc (built from source by the `protobuf-src` crate
    // at build time) instead of whatever system / container protoc is
    // available. This makes the build reproducible across hosts and inside
    // cross-compile containers whose default protoc is too old to support
    // proto3 `optional` fields.
    // SAFETY: build.rs runs single-threaded before any cargo-spawned
    // threads exist. set_var was marked unsafe in edition 2024 because it
    // races with other threads reading env; not a concern here.
    unsafe {
        std::env::set_var("PROTOC", protobuf_src::protoc());
    }

    prost_build::compile_protos(&["proto/logpacer_wire.proto"], &["proto/"])?;
    Ok(())
}
