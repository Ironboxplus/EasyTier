//! Compiles the unmodified Linux `net/sched/sch_cake.c` together with a thin kernel-API shim.
//!
//! The vendored file must be byte-identical to the upstream one: the build fails if its SHA-256
//! differs from [`SCH_CAKE_SHA256`].

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::Path;

/// Linux mainline `net/sched/sch_cake.c` at 7cbfb180945c (master 3857c2fe5449), 3393 lines.
const SCH_CAKE_SHA256: &str = "bafe5df74aa52b00ff1625985ca8b592f418dff79fd9cc21d1c1dce17d7607f9";

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let csrc = Path::new(&manifest).join("csrc");

    let cake = std::fs::read(csrc.join("linux/sch_cake.c")).expect("csrc/linux/sch_cake.c");
    let digest = Sha256::digest(&cake);
    let mut got = String::new();
    for b in digest {
        write!(got, "{b:02x}").unwrap();
    }
    assert_eq!(
        got, SCH_CAKE_SHA256,
        "csrc/linux/sch_cake.c is not the pristine upstream file (SHA-256 mismatch); it must stay \
         byte-identical, put every adaptation into csrc/shim or csrc/cake_glue.c"
    );
    println!("cargo:rustc-env=CAKE_SQM_SCH_CAKE_SHA256={SCH_CAKE_SHA256}");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=build.rs");

    let mut build = cc::Build::new();
    build
        .file(csrc.join("cake_glue.c"))
        .file(csrc.join("shim/kshim.c"))
        // <linux/...> and <net/...> resolve to the shim; the uapi excerpt sits in csrc/linux.
        .include(csrc.join("shim"))
        .include(csrc.join("linux"))
        .warnings(false)
        .opt_level(2)
        .debug(false)
        .define("NDEBUG", None);
    if build.get_compiler().is_like_msvc() {
        build.flag("/std:c11");
    } else {
        // The kernel is built with -fno-strict-aliasing -fwrapv; sch_cake.c relies on both
        // (it casts header buffers between struct types and does wrapping u32 arithmetic).
        build
            .flag("-std=gnu11")
            .flag("-fno-strict-aliasing")
            .flag("-fwrapv");
    }
    build.compile("cake_sqm_c");
}
