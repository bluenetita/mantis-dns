fn main() {
    let file_descriptor_set =
        protox::compile(["../../../proto/bundle.proto"], ["../../../proto"])
            .expect("failed to parse bundle.proto via protox");

    prost_build::Config::new()
        .compile_fds(file_descriptor_set)
        .expect("failed to generate Rust types from bundle.proto");
}
