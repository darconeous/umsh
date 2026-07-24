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

    // `PROP_NCP_VERSION` reports this: a bare short hash today, and the
    // nearest-tag form automatically once release tags exist. Falls back
    // to "unknown" if git is unavailable or the build is outside a repo.
    let describe = git_output(&["describe", "--always"]).unwrap_or_else(|| "unknown".to_string());
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
