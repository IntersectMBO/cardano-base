//! Support to both static and dynamic library, require in user crate a small
//! `build.rs` script.
//!
//! This build file was written with the constraint in mind of no-dependency to
//! keep user setup simple and be easily mergeable with an existing `build.rs`
//! automation!

fn main() {
    // Support to static library require that library name is prefixed by `C`
    // https://gitlab.haskell.org/ghc/ghc/-/issues/22564#note_469030
    let path = format!("target/{}", std::env::var("PROFILE").unwrap());
    #[cfg(target_family = "windows")]
    let prefix = "";
    #[cfg(target_family = "unix")]
    let prefix = "lib";
    let name = env!("CARGO_PKG_NAME");
    let lib_name = name.replace("-", "_");
    let lib_name_non_prefixed: &str = &lib_name[1..];
    #[cfg(target_family = "windows")]
    let ext = "lib";
    #[cfg(target_family = "unix")]
    let ext = "a";
    let source = format!("{prefix}{lib_name}.{ext}");
    let target = format!("{prefix}{lib_name_non_prefixed}.{ext}");
    symlink(&path, &source, &target);

    // Support to dynamic library require to generated a filename with GHC
    // version suffix, e.g. `libNAME-ghcVERSION.so`, `libNAME-ghcVERSION.dylib`
    // or `NAME-ghcVERSION.dll`
    //
    // Version is the one of `ghc` in `$PATH`, but could be overide with
    // `$CABAL_PACK_GHC_VERSION` env variable!
    let suffix = format!(
        "-ghc{}",
        std::env::var("CABAL_PACK_GHC_VERSION")
            .or_else(|_| String::from_utf8(
                std::process::Command::new("ghc")
                    .arg("--version")
                    .output()
                    .unwrap()
                    .stdout
            ))
            .unwrap()
            .trim()
            .strip_prefix("The Glorious Glasgow Haskell Compilation System, version ")
            .unwrap()
    );
    #[cfg(target_os = "windows")]
    let ext = "dll";
    #[cfg(target_os = "macos")]
    let ext = "dylib";
    #[cfg(target_os = "linux")]
    let ext = "so";
    let source = format!("{prefix}{name}.{ext}");
    let target = format!("{prefix}{name}{suffix}.{ext}");
    symlink(&path, &source, &target);
    let target = format!("C{prefix}{name}{suffix}.{ext}");
    symlink(&path, &source, &target);
}

fn symlink(path: &str, source: &str, target: &str) {
    if !std::path::Path::new(&format!("{path}/{target}")).exists() {
        std::env::set_current_dir(path).unwrap();
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(source)
            .unwrap();
        #[cfg(target_family = "windows")]
        std::os::windows::fs::symlink_file(source, target).unwrap();
        #[cfg(target_family = "unix")]
        std::os::unix::fs::symlink(source, target).unwrap();
    }
}
