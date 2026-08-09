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

    // `PROP_DEV_VERSION` reports this. `UMSH_FW_VERSION` wins when set:
    // the release build passes the tag explicitly, because creating a tag
    // touches neither HEAD nor the branch ref, so the `git describe` below
    // would happily hand back a cached pre-tag build. Otherwise ask Git,
    // matching only firmware tags so a future crate or app tag can never
    // claim the firmware version. Falls back to "unknown" outside a repo.
    println!("cargo:rerun-if-env-changed=UMSH_FW_VERSION");
    let describe = std::env::var("UMSH_FW_VERSION")
        .ok()
        .filter(|version| !version.is_empty())
        .or_else(|| {
            git_output(&[
                "describe", "--tags", "--match", "fw-*", "--always", "--dirty",
            ])
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_DESCRIBE={describe}");
    if let Some(path) = git_path("HEAD") {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_path(&reference)
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn git_path(name: &str) -> Option<String> {
    git_output(&["rev-parse", "--git-path", name])
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
