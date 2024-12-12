/*
 * Copyright (C) 2024 Nos Doughty
 *
 * Licensed under:
 * 1. Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 * 2. GNU General Public License, Version 3 (https://www.gnu.org/licenses/gpl-3.0.html)
 */
use clap::{Arg, Command};
use fs::Metadata;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request,
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const BLOCK_SIZE: u32 = 4096;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Mapping {
    path: String,
    target: Option<String>,
}

#[derive(Clone)]
struct CachedAttr {
    attr: FileAttr,
}

fn to_system_time(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs as u64)
}

struct PassthroughFS {
    target_dir: PathBuf,
    file_mapping: RwLock<HashMap<String, Mapping>>,
    file_cache: RwLock<HashMap<u64, CachedAttr>>,
    mapping_file: String,
    last_modified: RwLock<Option<SystemTime>>,
    last_size: RwLock<Option<u64>>,

    next_ino: AtomicU64,
    ino_to_path: RwLock<HashMap<u64, PathBuf>>,
    path_to_ino: RwLock<HashMap<PathBuf, u64>>,
}

impl PassthroughFS {
    fn new(target_dir: PathBuf, mapping_file: String) -> Self {
        Self {
            target_dir,
            file_mapping: RwLock::new(HashMap::new()),
            file_cache: RwLock::new(HashMap::new()),
            mapping_file,
            last_modified: RwLock::new(None),
            last_size: RwLock::new(None),
            next_ino: AtomicU64::new(2),
            ino_to_path: RwLock::new(HashMap::new()),
            path_to_ino: RwLock::new(HashMap::new()),
        }
    }

    fn generate_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    fn get_path_by_ino(&self, ino: u64) -> Option<PathBuf> {
        self.ino_to_path.read().unwrap().get(&ino).cloned()
    }

    fn get_ino_by_path(&self, path: &Path) -> Option<u64> {
        self.path_to_ino.read().unwrap().get(path).cloned()
    }

    fn insert_path(&self, path: PathBuf) -> u64 {
        if let Some(ino) = self.get_ino_by_path(&path) {
            return ino;
        }
        let ino = self.generate_ino();
        {
            let mut ino_map = self.ino_to_path.write().unwrap();
            let mut path_map = self.path_to_ino.write().unwrap();
            ino_map.insert(ino, path.clone());
            path_map.insert(path, ino);
        }
        ino
    }

    // Updated logic for resolve_mapped_path:
    // 1. If there's a mapping for the path and it has a target, return that.
    // 2. If there's a mapping for the path with no target, return ENOENT (i.e. removed).
    // 3. If no mapping, fallback to target_dir.
    fn resolve_mapped_path(&self, path: &str) -> io::Result<PathBuf> {
        let mappings = self.file_mapping.read().unwrap();
        if let Some(mapping) = mappings.get(path) {
            if let Some(target) = &mapping.target {
                let target_path = PathBuf::from(target);
                let final_path = if target_path.is_absolute() {
                    // Mapped to a specific target
                    target_path
                } else {
                    // If it's not absolute, join with target_dir
                    self.target_dir.join(target_path)
                };
                Ok(final_path)
            } else {
                // Mapping present but no target => treat as removed
                Err(io::Error::new(io::ErrorKind::NotFound, "Path removed"))
            }
        } else {
            // No mapping => fallback to target_dir passthrough
            Ok(self.target_dir.join(path.trim_start_matches('/')))
        }
    }

    fn to_file_attr(&self, metadata: Metadata, ino: u64) -> FileAttr {
        FileAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: to_system_time(metadata.atime()),
            mtime: to_system_time(metadata.mtime()),
            ctime: to_system_time(metadata.ctime()),
            crtime: to_system_time(metadata.ctime()),
            kind: if metadata.is_dir() {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: metadata.mode() as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn get_cached_attr(&self, ino: u64) -> Option<FileAttr> {
        self.file_cache
            .read()
            .unwrap()
            .get(&ino)
            .map(|c| c.attr.clone())
    }

    fn set_cached_attr(&self, ino: u64, attr: FileAttr) {
        self.file_cache
            .write()
            .unwrap()
            .insert(ino, CachedAttr { attr });
    }

    fn invalidate_attr(&self, ino: u64) {
        self.file_cache.write().unwrap().remove(&ino);
    }

    fn invalidate_all_attrs(&self) {
        self.file_cache.write().unwrap().clear();
    }

    fn read_target_metadata(&self, path: &Path) -> io::Result<FileAttr> {
        let metadata = fs::metadata(path)?;
        let ino = self
            .get_ino_by_path(path)
            .expect("Path should have ino after insert");
        Ok(self.to_file_attr(metadata, ino))
    }

    fn log_operation(&self, operation: &str, details: &str) {
        debug!("Operation: {}, {}", operation, details);
    }
}

/// Read exactly `buf.len()` bytes from `reader`.
fn read_exact_bytes<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                return Ok(false);
            }
            Ok(n) => offset += n,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Reads a length-prefixed JSON message from `reader`.
fn read_length_prefixed_json<R: Read>(reader: &mut R) -> io::Result<Option<String>> {
    let mut length_buf = [0u8; 4];
    match read_exact_bytes(reader, &mut length_buf)? {
        true => {
            let length = u32::from_be_bytes(length_buf) as usize;
            let mut payload = vec![0; length];
            if !read_exact_bytes(reader, &mut payload)? {
                return Ok(None);
            }
            let s = String::from_utf8(payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
            Ok(Some(s))
        }
        false => Ok(None),
    }
}

fn reload_mappings(fs: &PassthroughFS) {
    // Attempt to read from the named pipe
    let metadata = match fs::metadata(&fs.mapping_file) {
        Ok(m) => m,
        Err(err) => {
            warn!("Failed to get metadata for {}: {:?}", fs.mapping_file, err);
            return;
        }
    };

    let modified = match metadata.modified() {
        Ok(m) => m,
        Err(err) => {
            warn!(
                "Failed to get modification time for {}: {:?}",
                fs.mapping_file, err
            );
            return;
        }
    };

    let size = metadata.len();

    let lm_val = *fs.last_modified.read().unwrap();
    let ls_val = *fs.last_size.read().unwrap();

    // Check both size and mtime to see if something changed
    if lm_val == Some(modified) && ls_val == Some(size) {
        return;
    }

    info!("Reloading mappings from named pipe {}", fs.mapping_file);

    let mut fifo = match OpenOptions::new().read(true).open(&fs.mapping_file) {
        Ok(f) => f,
        Err(err) => {
            warn!("Failed to open named pipe {}: {:?}", fs.mapping_file, err);
            return;
        }
    };

    match read_length_prefixed_json(&mut fifo) {
        Ok(Some(json_str)) => match serde_json::from_str::<HashMap<String, Mapping>>(&json_str) {
            Ok(parsed) => {
                let mut mappings = fs.file_mapping.write().unwrap();
                mappings.clear();
                mappings.extend(parsed);
                {
                    let mut lm = fs.last_modified.write().unwrap();
                    *lm = Some(modified);
                    let mut ls = fs.last_size.write().unwrap();
                    *ls = Some(size);
                }
                info!(
                    "Mappings successfully reloaded: {:?}",
                    mappings.keys().collect::<Vec<_>>()
                );
                fs.invalidate_all_attrs();
            }
            Err(err) => {
                warn!(
                    "Failed to parse JSON from named pipe {}: {:?}",
                    fs.mapping_file, err
                );
            }
        },
        Ok(None) => {
            warn!(
                "No complete message available in named pipe {}",
                fs.mapping_file
            );
        }
        Err(err) => {
            warn!(
                "Error reading from named pipe {}: {:?}",
                fs.mapping_file, err
            );
        }
    }
}

struct MyFS {
    fs: Arc<PassthroughFS>,
}

impl MyFS {
    fn new(fs: Arc<PassthroughFS>) -> Self {
        MyFS { fs }
    }
}

impl Filesystem for MyFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let fs = &*self.fs;
        fs.log_operation(
            "lookup",
            &format!("parent ino: {}, name: {:?}", parent, name),
        );

        let parent_path = if parent == 1 {
            PathBuf::from("/")
        } else {
            match fs.get_path_by_ino(parent) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let child_path = if parent_path == PathBuf::from("/") {
            PathBuf::from("/").join(name)
        } else {
            parent_path.join(name)
        };

        let path_str = if child_path == PathBuf::from("/") {
            "/".to_string()
        } else {
            child_path.to_string_lossy().to_string()
        };

        match fs.resolve_mapped_path(&path_str) {
            Ok(full_path) => match fs::metadata(&full_path) {
                Ok(metadata) => {
                    let ino = fs
                        .get_ino_by_path(&child_path)
                        .unwrap_or_else(|| fs.insert_path(child_path.clone()));
                    let attr = fs.to_file_attr(metadata, ino);
                    fs.set_cached_attr(ino, attr.clone());
                    reply.entry(&Duration::from_secs(0), &attr, 0);
                }
                Err(_) => reply.error(libc::ENOENT),
            },
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let fs = &*self.fs;
        fs.log_operation("getattr", &format!("ino: {}", ino));

        if let Some(attr) = fs.get_cached_attr(ino) {
            reply.attr(&Duration::from_secs(0), &attr);
            return;
        }

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match fs.read_target_metadata(&path) {
            Ok(attr) => {
                fs.set_cached_attr(ino, attr.clone());
                reply.attr(&Duration::from_secs(0), &attr);
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "read",
            &format!("ino: {}, offset: {}, size: {}", ino, offset, size),
        );

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match fs::File::open(&path) {
            Ok(file) => {
                let mut buffer = vec![0; size as usize];
                match file.read_at(&mut buffer, offset as u64) {
                    Ok(bytes_read) => {
                        reply.data(&buffer[..bytes_read]);
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                    }
                }
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "write",
            &format!("ino: {}, offset: {}, size: {}", ino, offset, data.len()),
        );

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match OpenOptions::new().write(true).open(&path) {
            Ok(file) => match file.write_at(data, offset as u64) {
                Ok(bytes_written) => {
                    fs.invalidate_attr(ino);
                    reply.written(bytes_written as u32);
                }
                Err(err) => {
                    error!("Write operation failed: {}, Error: {}", path.display(), err);
                    reply.error(libc::EIO);
                }
            },
            Err(_) => {
                error!("File not found for writing: {}", path.display());
                reply.error(libc::ENOENT);
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let fs = &*self.fs;
        fs.log_operation("release", "no-op");
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let fs = &*self.fs;
        fs.log_operation("readdir", &format!("ino: {}", ino));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if let Ok(entries) = fs::read_dir(&path) {
            for (i, entry) in entries.enumerate().skip(offset as usize) {
                if let Ok(entry) = entry {
                    let file_type = match entry.file_type() {
                        Ok(ft) => {
                            if ft.is_dir() {
                                FileType::Directory
                            } else {
                                FileType::RegularFile
                            }
                        }
                        Err(_) => FileType::RegularFile,
                    };
                    let name = entry.file_name();
                    let child_path = if path == PathBuf::from("/") {
                        PathBuf::from("/").join(&name)
                    } else {
                        path.join(&name)
                    };

                    let child_ino = fs
                        .get_ino_by_path(&child_path)
                        .unwrap_or_else(|| fs.insert_path(child_path));
                    let _ = reply.add(child_ino, (i + 1) as i64, file_type, &name);
                }
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "create",
            &format!("parent: {}, name: {:?}, mode: {:o}", parent, name, mode),
        );

        let parent_path = if parent == 1 {
            PathBuf::from("/")
        } else {
            match fs.get_path_by_ino(parent) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let full_path = if parent_path == PathBuf::from("/") {
            PathBuf::from("/").join(name)
        } else {
            parent_path.join(name)
        };

        match OpenOptions::new()
            .write(true)
            .create(true)
            .mode(mode)
            .open(&full_path)
        {
            Ok(_) => {
                let ino = fs
                    .get_ino_by_path(&full_path)
                    .unwrap_or_else(|| fs.insert_path(full_path.clone()));

                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        let attr = fs.to_file_attr(metadata, ino);
                        fs.set_cached_attr(ino, attr.clone());
                        reply.created(&Duration::from_secs(0), &attr, 0, 0, 0);
                    }
                    Err(err) => {
                        error!(
                            "Failed to retrieve metadata for created file: {}, Error: {}",
                            full_path.display(),
                            err
                        );
                        reply.error(libc::EIO);
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to create file: {}, Error: {}",
                    full_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }
}

fn main() {
    env_logger::init();

    let matches = Command::new("PassthroughFS")
        .version("1.0")
        .author("Nos Doughty <cetic.nos@gmail.com>")
        .about("A FUSE-based passthrough filesystem with JSON-based mappings (Named Pipe Mode)")
        .arg(
            Arg::new("mountpoint")
                .help("Directory where the FUSE filesystem will be mounted")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("target")
                .help("The target directory to passthrough")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("mapping_file")
                .help("The named pipe containing length-prefixed JSON mappings")
                .required(false)
                .default_value("mapping.pipe")
                .value_parser(clap::value_parser!(String)),
        )
        .get_matches();

    let mountpoint = matches.get_one::<String>("mountpoint").unwrap();
    let target = matches.get_one::<String>("target").unwrap();
    let mapping_file = matches.get_one::<String>("mapping_file").unwrap();

    let fs = Arc::new(PassthroughFS::new(
        PathBuf::from(target),
        mapping_file.clone(),
    ));

    // Initially load mappings from the pipe once
    reload_mappings(&fs);

    let my_fs = MyFS::new(fs);
    fuser::mount2(my_fs, mountpoint, &[]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use std::thread;

    fn create_temp_dir_for_test(test_name: &str) -> PathBuf {
        let base = env::temp_dir();
        let temp_dir = base.join(format!("passthroughfs_pipe_test_{}", test_name));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        temp_dir
    }

    // Integration test for named pipe:
    // 1. Create a named pipe using `mkfifo`.
    // 2. Write a length-prefixed JSON payload to the pipe.
    // 3. Call reload_mappings and verify the mappings are loaded.

    #[test]
    fn test_reload_mappings_from_pipe() {
        let temp_dir = create_temp_dir_for_test("test_reload_mappings_from_pipe");
        let pipe_path = temp_dir.join("mapping.pipe");

        // Create FIFO (mkfifo)
        let status = Command::new("mkfifo")
            .arg(&pipe_path)
            .status()
            .expect("Failed to run mkfifo");
        assert!(status.success(), "mkfifo should succeed");

        let fs = PassthroughFS::new(temp_dir.clone(), pipe_path.to_string_lossy().to_string());

        // Prepare a mapping
        let mappings = HashMap::from([
            (
                "/foo".to_string(),
                Mapping {
                    path: "/foo".to_string(),
                    target: Some("/real_target/foo".to_string()),
                },
            ),
            (
                "/bar".to_string(),
                Mapping {
                    path: "/bar".to_string(),
                    target: Some("/real_target/bar".to_string()),
                },
            ),
        ]);

        let json_data = serde_json::to_string(&mappings).unwrap();
        let length = json_data.len() as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(json_data.as_bytes());

        // Write to the pipe in a separate thread.
        {
            let pipe_path_clone = pipe_path.clone();
            let payload_clone = payload.clone();
            thread::spawn(move || {
                // Open in write mode after some delay to ensure the main thread tries to read
                thread::sleep(Duration::from_millis(100));
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .open(pipe_path_clone)
                    .expect("Failed to open pipe for writing");
                file.write_all(&payload_clone)
                    .expect("Failed to write to pipe");
            });
        }

        // Attempt to reload mappings
        reload_mappings(&fs);

        // Verify mappings are loaded
        let loaded = fs.file_mapping.read().unwrap();
        assert!(
            loaded.contains_key("/foo"),
            "Should have loaded /foo mapping"
        );
        assert!(
            loaded.contains_key("/bar"),
            "Should have loaded /bar mapping"
        );
    }

    #[test]
    fn test_inode_mapping_pipe() {
        let temp_dir = create_temp_dir_for_test("test_inode_mapping_pipe");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let path1 = temp_dir.join("file1");
        let path2 = temp_dir.join("file2");
        let ino1 = fs.insert_path(path1.clone());
        let ino2 = fs.insert_path(path2.clone());

        assert_ne!(ino1, ino2);
        assert_eq!(fs.get_path_by_ino(ino1), Some(path1));
        assert_eq!(fs.get_path_by_ino(ino2), Some(path2));
    }

    #[test]
    fn test_attribute_caching_pipe() {
        let temp_dir = create_temp_dir_for_test("test_attribute_caching_pipe");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let file_path = temp_dir.join("testfile");
        fs::write(&file_path, b"Hello").unwrap();

        let ino = fs.insert_path(file_path.clone());
        let metadata = fs::metadata(&file_path).unwrap();
        let attr = fs.to_file_attr(metadata, ino);

        fs.set_cached_attr(ino, attr.clone());
        let cached = fs.get_cached_attr(ino).expect("Attribute should be cached");
        assert_eq!(cached.ino, attr.ino);

        fs.invalidate_attr(ino);
        assert!(fs.get_cached_attr(ino).is_none());
    }

    #[test]
    fn test_invalidate_all_attrs_pipe() {
        let temp_dir = create_temp_dir_for_test("test_invalidate_all_attrs_pipe");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let file_path = temp_dir.join("testfile2");
        fs::write(&file_path, b"Hello").unwrap();
        let ino = fs.insert_path(file_path.clone());
        let metadata = fs::metadata(&file_path).unwrap();
        let attr = fs.to_file_attr(metadata, ino);

        fs.set_cached_attr(ino, attr.clone());
        assert!(fs.get_cached_attr(ino).is_some());

        fs.invalidate_all_attrs();
        assert!(fs.get_cached_attr(ino).is_none());
    }
}
