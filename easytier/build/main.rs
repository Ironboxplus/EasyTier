mod rpc;

use crate::rpc::ServiceGenerator;
use cfg_aliases::cfg_aliases;
use std::{env, path::PathBuf};

fn configure_windows_link_search() {
    let target = env::var("TARGET").unwrap_or_default();

    if target.contains("x86_64") {
        println!("cargo:rustc-link-search=native=easytier/third_party/x86_64/");
    } else if target.contains("i686") {
        println!("cargo:rustc-link-search=native=easytier/third_party/i686/");
    } else if target.contains("aarch64") {
        println!("cargo:rustc-link-search=native=easytier/third_party/arm64/");
    }
}

fn workdir() -> Option<String> {
    if let Ok(cargo_manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        return Some(cargo_manifest_dir);
    }

    let dest = std::env::var("OUT_DIR");
    if dest.is_err() {
        return None;
    }
    let dest = dest.unwrap();

    let seperator = regex::Regex::new(r"(/target/(.+?)/build/)|(\\target\\(.+?)\\build\\)")
        .expect("Invalid regex");
    let parts = seperator.split(dest.as_str()).collect::<Vec<_>>();

    if parts.len() >= 2 {
        return Some(parts[0].to_string());
    }

    None
}

fn check_locale() {
    let workdir = workdir().unwrap_or("./".to_string());

    let locale_path = format!("{workdir}/**/locales/**/*");
    if let Ok(globs) = globwalk::glob(locale_path) {
        for entry in globs {
            if let Err(e) = entry {
                println!("cargo:i18n-error={e}");
                continue;
            }

            let entry = entry.unwrap().into_path();
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cfg_aliases! {
        mobile: {
            any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            )
        }
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    // enable thunk-rs when target os is windows and arch is x86_64 or i686
    if target_os == "windows" && (target_arch == "x86" || target_arch == "x86_64") {
        thunk::thunk();
    }

    if target_os == "windows" {
        configure_windows_link_search();
    }

    let proto_files_reflect = ["src/proto/peer_rpc.proto", "src/proto/common.proto"];

    let proto_files = [
        "src/proto/error.proto",
        "src/proto/tests.proto",
        "src/proto/api_instance.proto",
        "src/proto/api_logger.proto",
        "src/proto/api_config_patch.proto",
        "src/proto/api_config.proto",
        "src/proto/api_manage.proto",
        "src/proto/web.proto",
        "src/proto/magic_dns.proto",
        "src/proto/acl.proto",
    ];

    for proto_file in proto_files.iter().chain(proto_files_reflect.iter()) {
        println!("cargo:rerun-if-changed={proto_file}");
    }

    let out = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor = out.join("descriptors.bin");
    let file_descriptors = protox::compile(proto_files, ["src/proto/"])?;
    std::fs::write(
        &descriptor,
        protox::prost::Message::encode_to_vec(&file_descriptors),
    )?;

    let mut config = prost_build::Config::new();
    config
        .extern_path(".google.protobuf.Any", "::prost_wkt_types::Any")
        .extern_path(".google.protobuf.Timestamp", "::prost_wkt_types::Timestamp")
        .extern_path(".google.protobuf.Value", "::prost_wkt_types::Value")
        .file_descriptor_set_path(&descriptor)
        .service_generator(Box::new(ServiceGenerator::default()))
        .btree_map(["."])
        .skip_debug([".common.Ipv4Addr", ".common.Ipv6Addr", ".common.UUID"]);

    config
        .skip_protoc_run()
        .compile_protos(&proto_files, &["src/proto/"])?;

    let reflect_descriptor = out.join("file_descriptor_set.bin");
    let reflect_file_descriptors = protox::compile(proto_files_reflect, ["src/proto/"])?;
    std::fs::write(
        reflect_descriptor,
        protox::prost::Message::encode_to_vec(&reflect_file_descriptors),
    )?;

    prost_reflect_build::Builder::new()
        .file_descriptor_set_bytes("crate::proto::DESCRIPTOR_POOL_BYTES")
        .compile_protos_with_config(config, &proto_files_reflect, &["src/proto/"])?;

    let descriptor = std::fs::read(descriptor)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor)?
        .preserve_proto_field_names()
        .btree_map(["."])
        .build(&["."])?;

    check_locale();
    Ok(())
}
