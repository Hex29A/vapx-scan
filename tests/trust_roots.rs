//! The release binaries trust the roots embedded in `webpki-roots`, not the operating system's.
//! 1.0.10 dropped emSign ECC Root CA - G3 (distrusted in October 2026); an older locked version
//! would put it back, for example after a careless `cargo update` of the lock file.

fn locked_version(lock: &str, name: &str) -> Vec<u64> {
    let at = lock
        .find(&format!("name = \"{name}\"\n"))
        .unwrap_or_else(|| panic!("{name} not in Cargo.lock"));
    let rest = &lock[at..];
    let line = rest.lines().nth(1).expect("version line");
    let version = line
        .trim()
        .strip_prefix("version = \"")
        .and_then(|v| v.strip_suffix('"'))
        .expect("version = \"x.y.z\"");
    version
        .split('.')
        .map(|n| n.parse().expect("numeric version"))
        .collect()
}

#[test]
fn webpki_roots_is_new_enough_to_exclude_the_distrusted_emsign_root() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("read Cargo.lock");
    let v = locked_version(&lock, "webpki-roots");
    assert!(
        v >= vec![1, 0, 10],
        "webpki-roots {v:?} still trusts emSign ECC Root CA - G3; need 1.0.10 or later"
    );
}
