// `PROP_NCP_VERSION` reports this: a bare short hash today, and the
// nearest-tag form automatically once release tags exist. Falls back
// to "unknown" if git is unavailable or the build is outside a repo.
// (No memory.x handling — the ESP32 linker script comes from esp-hal.)

fn main() {
    let describe = git_output(&["describe", "--always"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_DESCRIBE={describe}");
    // `.git/HEAD` contains a stable `ref: ...` line on a normal branch; the
    // referenced file changes on commit, not HEAD itself. Ask Git for both
    // paths so revision strings cannot silently survive from a cached build.
    if let Some(path) = git_path("HEAD") {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_path(&reference)
    {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed=build.rs");
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
