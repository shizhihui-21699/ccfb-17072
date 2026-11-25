use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub path: PathBuf,
    pub exists: bool,
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub generation: Option<u64>,
    pub mode: Option<u32>,
    pub sha256: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("failed to stat {path}: {source}")]
    Stat {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read {path} for hashing: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Read stable metadata and, optionally, a full SHA-256 content hash.
///
/// The hash is a deployment-time trust input. The fast in-kernel key is
/// normally `(dev, ino[, generation])`; the daemon periodically revalidates the
/// content hash and removes the key if the file changes.
pub fn identify(path: impl AsRef<Path>, hash_content: bool) -> Result<FileIdentity, IdentityError> {
    let path = path.as_ref().to_path_buf();
    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileIdentity {
                path,
                exists: false,
                dev: None,
                ino: None,
                generation: None,
                mode: None,
                sha256: None,
            });
        }
        Err(source) => return Err(IdentityError::Stat { path, source }),
    };

    #[cfg(unix)]
    let (dev, ino, mode) = {
        use std::os::unix::fs::MetadataExt;
        (
            Some(metadata.dev()),
            Some(metadata.ino()),
            Some(metadata.mode()),
        )
    };
    #[cfg(not(unix))]
    let (dev, ino, mode) = (None, None, None);

    let sha256 = if hash_content {
        Some(hash_file(&path)?)
    } else {
        None
    };
    let generation = read_inode_generation(&path);

    Ok(FileIdentity {
        path,
        exists: true,
        dev,
        ino,
        generation,
        mode,
        sha256,
    })
}

#[cfg(target_os = "linux")]
fn read_inode_generation(path: &Path) -> Option<u64> {
    use std::os::unix::io::AsRawFd;

    // Linux FS_IOC_GETVERSION: _IOR('v', 1, long), 64-bit userspace encoding.
    // Casting to libc::Ioctl also handles musl's signed int request type.
    const FS_IOC_GETVERSION: u64 = 0x8008_7601;

    let file = File::open(path).ok()?;
    let mut generation: libc::c_long = 0;
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            FS_IOC_GETVERSION as libc::Ioctl,
            &mut generation as *mut libc::c_long as *mut libc::c_void,
        )
    };
    if rc == 0 {
        Some(generation as u64)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn read_inode_generation(_path: &Path) -> Option<u64> {
    None
}

pub fn hash_file(path: impl AsRef<Path>) -> Result<String, IdentityError> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(|source| IdentityError::Read {
        path: path.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 128 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|source| IdentityError::Read {
                path: path.clone(),
                source,
            })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
