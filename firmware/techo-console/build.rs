// Embedded build script: copy `memory.x` into the output directory and
// instruct the linker to add it to the search path. Standard cortex-m-rt
// boilerplate. Skipped on non-bare-metal targets so host `cargo check`
// stays simple.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("-none-") {
        return;
    }

    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");

    // Capture the current git short SHA so main.rs can embed it in the
    // e-paper boot screen. Falls back to "unknown" if git is unavailable
    // or the binary is built outside a repo.
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_SHORT_SHA={sha}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
