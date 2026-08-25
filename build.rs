extern crate winres;

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;

/// Reads a `const NAME: &str = "..."` literal straight out of src/canary.rs, so
/// the source stays the single source of truth for the build script, the binary
/// and tools/canary_check.py alike (same pattern as LICENSE_BASE_SECRET).
fn const_from_canary_rs(src: &str, name: &str) -> String {
    let needle = format!("pub const {}: &str = \"", name);
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("{} not found in src/canary.rs", name))
        + needle.len();
    let rest = &src[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated {} literal in src/canary.rs", name));
    rest[..end].to_string()
}

/// Must stay identical to canary::token_for() and to tools/canary_check.py.
fn token_for(seed: &str, sep: &str, version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(sep.as_bytes());
    hasher.update(version.as_bytes());
    let hex = hex::encode(hasher.finalize()).to_uppercase();
    format!("AGU-{}-{}-{}", &hex[0..5], &hex[5..10], &hex[10..15])
}

fn main() {
    println!("cargo:rerun-if-changed=src/canary.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let canary_src = fs::read_to_string("src/canary.rs").expect("src/canary.rs is missing");
    let seed = const_from_canary_rs(&canary_src, "CANARY_SEED");
    let sep = const_from_canary_rs(&canary_src, "CANARY_SEP");
    let static_canary = const_from_canary_rs(&canary_src, "STATIC_CANARY");
    let release_token = token_for(&seed, &sep, &version);

    // Emitted for canary.rs to include!(), so the token itself is a literal in
    // .rdata rather than something computed at runtime - a plain `strings` dump
    // of an unpacked binary shows it.
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR unset")).join("canary_gen.rs");
    fs::write(
        &out,
        format!(
            "/// Canary for this exact release, derived from CANARY_SEED + version.\n\
             pub const RELEASE_TOKEN: &str = \"{}\";\n",
            release_token
        ),
    )
    .expect("failed to write canary_gen.rs");

    // Visible to anyone running the build, and to build_rust.py's release log.
    println!(
        "cargo:warning=release canary {} (v{})",
        release_token, version
    );

    // The fast relay route's whole method lives in the gitignored `src/relay.rs`
    // and is compiled in only when it AND the credential file are present (owner
    // build) - the `relay` cfg. A public clone lacks both, builds under
    // `cfg(not(relay))`, and runs the DNS route. The credential is AES-256-GCM
    // encrypted here with a random per-build key; neither the key nor the method
    // is in any committed source. This is not un-reversible (agy's AES-GCM vault
    // was reversed, and so can an official binary): it keeps the method off the
    // public repo and off a `strings` dump of the packed binary.
    println!("cargo::rustc-check-cfg=cfg(relay)");
    println!("cargo:rerun-if-changed=.relay_key");
    println!("cargo:rerun-if-changed=src/relay.rs");
    if Path::new("src/relay.rs").exists() && Path::new(".relay_key").exists() {
        println!("cargo:rustc-cfg=relay");
        let cred = fs::read_to_string(".relay_key")
            .expect("read .relay_key")
            .trim()
            .to_string();
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut key).expect("random key");
        getrandom::getrandom(&mut nonce).expect("random nonce");
        let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), cred.as_bytes())
            .expect("encrypt relay credential");
        let bytes = |b: &[u8]| {
            b.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let relay_out =
            Path::new(&env::var("OUT_DIR").expect("OUT_DIR unset")).join("relay_gen.rs");
        fs::write(
            &relay_out,
            format!(
                "pub const RELAY_KEY: [u8; 32] = [{}];\n\
                 pub const RELAY_NONCE: [u8; 12] = [{}];\n\
                 pub const RELAY_CT: &[u8] = &[{}];\n",
                bytes(&key),
                bytes(&nonce),
                bytes(&ct)
            ),
        )
        .expect("failed to write relay_gen.rs");
    }

    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set("FileDescription", "Antigravity Configuration Tool");
        res.set("ProductName", "Antigravity Configurator");
        res.set("LegalCopyright", "Brent t.me/nova_txt");
        // Copyright management information in the version resource: survives
        // UPX (the resource directory stays readable on the packed file) and is
        // visible in the file's Properties dialog without any tooling.
        res.set(
            "LegalTrademarks",
            "Antigravity Unlocker (c) 2026 Brent - github.com/confeden/Antigravity",
        );
        res.set(
            "Comments",
            &format!(
                "Antigravity Unlocker (c) 2026 Brent, t.me/nova_txt. \
                 Origin: github.com/confeden/Antigravity. \
                 Non-Commercial & Restricted Use License - derivative works not permitted. \
                 mark {} build {}",
                static_canary, release_token
            ),
        );
        // Kept in step with Cargo.toml, which build_rust.py rewrites per release.
        res.set("FileVersion", &version);
        res.set("ProductVersion", &version);
        res.compile().unwrap();
    }
}
