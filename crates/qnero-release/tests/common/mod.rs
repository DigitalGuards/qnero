use rand::TryRngCore;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
pub const OTHER_REVISION: &str = "1123456789abcdef0123456789abcdef01234567";
pub const BIN: &str = env!("CARGO_BIN_EXE_qnero-release");

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("qnero-release-test-{}", hex::encode(nonce)));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn join(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
    pub fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let file = self.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn keygen(dir: &TestDir) {
    let output = Command::new(BIN)
        .arg("keygen")
        .arg("--private-key")
        .arg(dir.join("signer.release-key"))
        .arg("--public-key")
        .arg(dir.join("trusted.pub"))
        .output()
        .unwrap();
    success(&output);
}
