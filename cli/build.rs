// `fido`: builds that can talk to USB security keys. ctap-hid-fido2 links
// libudev on Linux, which the static musl release can't, and Windows lets only
// administrators open FIDO devices directly (others go through webauthn.dll).
// Keep this in step with the target table in Cargo.toml.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(fido)");
    let var = |k| std::env::var(k).unwrap_or_default();
    let (os, env) = (var("CARGO_CFG_TARGET_OS"), var("CARGO_CFG_TARGET_ENV"));
    if os == "macos" || (os == "linux" && env == "gnu") {
        println!("cargo::rustc-cfg=fido");
    }
}
