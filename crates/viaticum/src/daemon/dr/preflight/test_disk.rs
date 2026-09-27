// Test support: a temp dir on a filesystem that really reuses freed inode numbers,
// for the tests proving a DR never takes another DR's file for its own.
//
// `tempfile::tempdir()` lives in /tmp, which is tmpfs on the build server: tmpfs
// never hands out a freed inode number again, so there those tests pass even with
// the old (dev, ino)-only check. The dir is made under the workspace `target/`
// (a disk filesystem, ext4 on the server) and a control checks that a freed number
// is in fact reused there; if not, the test fails loudly instead of passing blind.

use std::path::Path;

/// Rounds of "create, remove, create" the control tries before giving up.
const CONTROL_ROUNDS: u32 = 32;

/// A fresh temp dir under `<workspace>/target/dr-inode-tests/` (removed on drop)
/// on which a removed file's inode number goes to the next file created.
pub(crate) fn inode_reusing_tempdir() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/dr-inode-tests");
    std::fs::create_dir_all(&base).expect("create target/dr-inode-tests");
    let dir = tempfile::Builder::new()
        .prefix("dr-")
        .tempdir_in(&base)
        .expect("temp dir under target/");
    assert_reuses_inode_numbers(dir.path());
    dir
}

#[cfg(unix)]
fn assert_reuses_inode_numbers(dir: &Path) {
    use std::os::unix::fs::MetadataExt;
    let probe = dir.join("inode-probe");
    let ino = |p: &Path| std::fs::metadata(p).expect("probe metadata").ino();
    for _ in 0..CONTROL_ROUNDS {
        std::fs::write(&probe, b"first").expect("write probe");
        let before = ino(&probe);
        std::fs::remove_file(&probe).expect("remove probe");
        std::fs::write(&probe, b"second").expect("write probe");
        let after = ino(&probe);
        std::fs::remove_file(&probe).expect("remove probe");
        if before == after {
            return;
        }
    }
    panic!(
        "CONTROL FAILED: the filesystem of {} never reused a freed inode number in {} \
         rounds of create/remove/create. The DR inode-reuse tests would pass here \
         without proving anything; run them where target/ is on a filesystem that \
         reuses inode numbers (ext4).",
        dir.display(),
        CONTROL_ROUNDS
    );
}

#[cfg(not(unix))]
fn assert_reuses_inode_numbers(_dir: &Path) {}
