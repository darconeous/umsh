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
}
