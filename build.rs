use std::path::Path;

fn main() {
    let out_dir = Path::new("src/proto_bridge/generated/");
    std::fs::create_dir_all(out_dir).unwrap();

    prost_build::Config::new()
        .out_dir(out_dir) // Output directory for generated files
        .compile_protos(
            &["src/protos/fuse_bridge.proto"],
            &["src/protos/"], // Include paths for .proto files
        )
        .expect("Failed to compile Protobuf");
}
