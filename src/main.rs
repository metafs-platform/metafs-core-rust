/*
 * Copyright (C) 2024 Nos Doughty
 *
 * Licensed under:
 * 1. Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 * 2. GNU General Public License, Version 3 (https://www.gnu.org/licenses/gpl-3.0.html)
 */
use clap::{Arg, Command};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request,
};
use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const BLOCK_SIZE: u32 = 4096;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Mapping {
    // req - path relative to mount point
    path: String,
    // optional - if missing path is treated as deleted
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

    fn to_file_attr(&self, metadata: fs::Metadata, ino: u64) -> FileAttr {
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

/// Read exactly `buf.len()` bytes from `reader`. Returns Ok(true) if successful, Ok(false) if EOF is reached early, Err otherwise.
fn read_exact_bytes<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                // EOF before reading all data
                return Ok(false);
            }
            Ok(n) => offset += n,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Reads a length-prefixed JSON message from `reader`.
/// Format:
/// - First 4 bytes: u32 length in big-endian
/// - Next `length` bytes: JSON data
fn read_length_prefixed_json<R: Read>(reader: &mut R) -> io::Result<Option<String>> {
    let mut length_buf = [0u8; 4];
    // Try to read length
    match read_exact_bytes(reader, &mut length_buf)? {
        true => {
            let length = u32::from_be_bytes(length_buf) as usize;
            let mut payload = vec![0; length];
            if !read_exact_bytes(reader, &mut payload)? {
                // EOF in the middle of payload
                return Ok(None); // Indicate incomplete message
            }
            let s = String::from_utf8(payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in JSON"))?;
            Ok(Some(s))
        }
        false => Ok(None), // no more data
    }
}

fn reload_mappings(fs: &PassthroughFS) {
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
        // No change
        return;
    }

    info!("Reloading mappings from {}", fs.mapping_file);

    // Determine if it's a named pipe or a regular file
    let file_type = metadata.file_type();
    let is_fifo = file_type.is_fifo(); // On Unix, named pipes can be checked with is_fifo()

    let result: Option<HashMap<String, Mapping>> = if is_fifo {
        // Named pipe: use length-prefixed reading
        let mut fifo = match OpenOptions::new().read(true).open(&fs.mapping_file) {
            Ok(f) => f,
            Err(err) => {
                warn!("Failed to open named pipe {}: {:?}", fs.mapping_file, err);
                return;
            }
        };

        // Attempt to read one complete message
        match read_length_prefixed_json(&mut fifo) {
            Ok(Some(json_str)) => {
                match serde_json::from_str::<HashMap<String, Mapping>>(&json_str) {
                    Ok(parsed) => Some(parsed),
                    Err(err) => {
                        warn!(
                            "Failed to parse JSON from named pipe {}: {:?}",
                            fs.mapping_file, err
                        );
                        None
                    }
                }
            }
            Ok(None) => {
                // No data or incomplete message
                warn!(
                    "No complete message available in named pipe {}",
                    fs.mapping_file
                );
                None
            }
            Err(err) => {
                warn!(
                    "Error reading from named pipe {}: {:?}",
                    fs.mapping_file, err
                );
                None
            }
        }
    } else {
        // Regular file: read the entire file
        match fs::read_to_string(&fs.mapping_file) {
            Ok(data) => match serde_json::from_str::<HashMap<String, Mapping>>(&data) {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    warn!("Failed to parse JSON in {}: {:?}", fs.mapping_file, err);
                    None
                }
            },
            Err(err) => {
                warn!("Failed to read {}: {:?}", fs.mapping_file, err);
                None
            }
        }
    };

    if let Some(parsed) = result {
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
}

fn fallback_polling(fs: &Arc<PassthroughFS>, mapping_path: &Path) {
    thread::sleep(Duration::from_millis(500));
    if mapping_path.exists() {
        reload_mappings(fs);
    }
}

fn start_mapping_monitor(fs: Arc<PassthroughFS>) {
    let mapping_path = PathBuf::from(&fs.mapping_file);

    thread::spawn(move || {
        // Attempt to initialize inotify
        let inotify_result = Inotify::init();
        let mut inotify: Option<Inotify> = None;
        let mut use_inotify = false;

        match inotify_result {
            Ok(mut ino) => {
                match ino.add_watch(&mapping_path, WatchMask::MODIFY | WatchMask::CLOSE_WRITE) {
                    Ok(_) => {
                        use_inotify = true;
                        inotify = Some(ino);
                    }
                    Err(err) => {
                        warn!(
                            "Inotify watch failed for {}: {:?}",
                            mapping_path.display(),
                            err
                        );
                    }
                }
            }
            Err(err) => {
                warn!("Inotify init failed: {:?}", err);
            }
        }

        let mut buffer = [0u8; 1024];

        loop {
            if use_inotify {
                let ino_ref = inotify.as_mut().unwrap();
                match ino_ref.read_events_blocking(&mut buffer) {
                    Ok(events) => {
                        for _ in events {
                            reload_mappings(&fs);
                        }
                    }
                    Err(err) => {
                        warn!("Inotify error: {:?}, falling back to polling", err);
                        use_inotify = false;
                    }
                }
            } else {
                fallback_polling(&fs, &mapping_path);
            }
        }
    });
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

        match fs::OpenOptions::new().write(true).open(&path) {
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
        .about("A FUSE-based passthrough filesystem with JSON-based mappings")
        .arg(
            Arg::new("mountpoint")
                .help("The directory where the FUSE filesystem will be mounted")
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
                .help("The JSON file (or named pipe) containing mappings. Missing 'target' means removed.")
                .required(false)
                .default_value("filemapping.json")
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

    start_mapping_monitor(fs.clone());
    reload_mappings(&fs);

    let my_fs = MyFS::new(fs);
    fuser::mount2(my_fs, mountpoint, &[]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    fn create_temp_dir_for_test(test_name: &str) -> PathBuf {
        let base = env::temp_dir();
        let temp_dir = base.join(format!("passthroughfs_test_{}", test_name));
        let _ = fs::remove_dir_all(&temp_dir); // Clean up before starting
        fs::create_dir_all(&temp_dir).unwrap();
        temp_dir
    }

    #[test]
    fn test_inode_mapping() {
        let temp_dir = create_temp_dir_for_test("test_inode_mapping");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.json".to_string());

        let path1 = temp_dir.join("file1");
        let path2 = temp_dir.join("file2");
        let ino1 = fs.insert_path(path1.clone());
        let ino2 = fs.insert_path(path2.clone());

        assert_ne!(ino1, ino2, "Inodes for different paths should be different");
        assert_eq!(fs.get_path_by_ino(ino1), Some(path1));
        assert_eq!(fs.get_path_by_ino(ino2), Some(path2));
    }

    #[test]
    fn test_attribute_caching() {
        let temp_dir = create_temp_dir_for_test("test_attribute_caching");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.json".to_string());

        let file_path = temp_dir.join("testfile");
        fs::write(&file_path, b"Hello").unwrap();

        let ino = fs.insert_path(file_path.clone());
        let metadata = fs::metadata(&file_path).unwrap();
        let attr = fs.to_file_attr(metadata, ino);

        fs.set_cached_attr(ino, attr.clone());
        let cached = fs.get_cached_attr(ino).expect("Attribute should be cached");
        assert_eq!(cached.ino, attr.ino);

        fs.invalidate_attr(ino);
        assert!(
            fs.get_cached_attr(ino).is_none(),
            "Attribute should be invalidated"
        );
    }

    #[test]
    fn test_invalidate_all_attrs() {
        let temp_dir = create_temp_dir_for_test("test_invalidate_all_attrs");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.json".to_string());

        let file_path = temp_dir.join("testfile2");
        fs::write(&file_path, b"Hello").unwrap();
        let ino = fs.insert_path(file_path.clone());
        let metadata = fs::metadata(&file_path).unwrap();
        let attr = fs.to_file_attr(metadata, ino);

        fs.set_cached_attr(ino, attr.clone());
        assert!(
            fs.get_cached_attr(ino).is_some(),
            "Attribute should be cached"
        );

        fs.invalidate_all_attrs();
        assert!(
            fs.get_cached_attr(ino).is_none(),
            "All attributes should be invalidated"
        );
    }

    #[test]
    fn test_reload_mappings_logic() {
        let temp_dir = create_temp_dir_for_test("test_reload_mappings_logic");
        let mapping_file = temp_dir.join("filemapping.json");

        fs::write(&mapping_file, "{}").unwrap();

        let fs = PassthroughFS::new(temp_dir.clone(), mapping_file.to_string_lossy().to_string());
        reload_mappings(&fs);
        {
            let mappings = fs.file_mapping.read().unwrap();
            assert!(mappings.is_empty(), "Mappings should be empty initially");
        }

        // Update mappings
        let updated_mappings = r#"
        {
            "/foo": {
                "path": "/foo",
                "target": "/real_target/foo",
                "permissions": null
            },
            "/bar": {
                "path": "/bar",
                "target": "/real_target/bar",
                "permissions": null
            }
        }
        "#;
        fs::write(&mapping_file, updated_mappings).unwrap();
        reload_mappings(&fs);
        {
            let mappings = fs.file_mapping.read().unwrap();
            assert!(mappings.contains_key("/foo"), "Mapping /foo should exist");
            assert!(mappings.contains_key("/bar"), "Mapping /bar should exist");
        }
    }

    #[test]
    fn test_resolve_mapped_path_with_and_without_mapping() {
        let temp_dir =
            create_temp_dir_for_test("test_resolve_mapped_path_with_and_without_mapping");
        let mapping_file = temp_dir.join("filemapping.json");

        let mappings = r#"
        {
            "/mapped_file": {
                "path": "/mapped_file",
                "target": "/real_target/mapped_file",
                "permissions": null
            }
        }
        "#;
        fs::write(&mapping_file, mappings).unwrap();

        let fs = PassthroughFS::new(temp_dir.clone(), mapping_file.to_string_lossy().to_string());
        reload_mappings(&fs);

        {
            let loaded = fs.file_mapping.read().unwrap();
            assert!(
                loaded.contains_key("/mapped_file"),
                "Should have loaded /mapped_file mapping"
            );
        }

        let resolved = fs.resolve_mapped_path("/mapped_file").unwrap();
        assert_eq!(
            resolved,
            PathBuf::from("/real_target/mapped_file"),
            "Should resolve to mapped target"
        );

        let resolved = fs.resolve_mapped_path("/no_such_mapping").unwrap();
        let expected = temp_dir.join("no_such_mapping");
        assert_eq!(
            resolved, expected,
            "Fallback to target_dir for unmapped paths"
        );
    }

    #[test]
    fn test_no_target_means_removed() {
        let temp_dir = create_temp_dir_for_test("test_no_target_means_removed");
        let mapping_file = temp_dir.join("filemapping.json");
        let underlying_file = temp_dir.join("realfile.txt");
        fs::write(&underlying_file, "Hello").unwrap();

        // Create a mapping where:
        // - "/removed_path" has no 'target' => should be treated as removed
        // - "/existing_path" has a 'target' => should map to underlying_file
        let mappings = r#"
    {
        "/removed_path": {
            "path": "/removed_path"
        },
        "/existing_path": {
            "path": "/existing_path",
            "target": "realfile.txt"
        }
    }
    "#;
        fs::write(&mapping_file, mappings).unwrap();

        let fs = PassthroughFS::new(temp_dir.clone(), mapping_file.to_string_lossy().to_string());
        reload_mappings(&fs);

        // "/existing_path" should map successfully to underlying_file
        let resolved = fs.resolve_mapped_path("/existing_path");
        assert!(resolved.is_ok(), "existing_path should resolve to a file");
        assert_eq!(resolved.unwrap(), temp_dir.join("realfile.txt"));

        // "/removed_path" should return ENOENT since 'target' is absent
        let removed = fs.resolve_mapped_path("/removed_path");
        assert!(
            removed.is_err(),
            "removed_path should be treated as removed"
        );
        let err = removed.err().unwrap();
        assert_eq!(
            err.kind(),
            io::ErrorKind::NotFound,
            "Should return NotFound error for removed_path"
        );
    }
}
