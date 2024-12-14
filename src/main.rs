/*
 * Copyright (C) 2024 Nos Doughty
 *
 * Licensed under:
 * 1. Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 * 2. GNU General Public License, Version 3 (https://www.gnu.org/licenses/gpl-3.0.html)
 */
use fs::Metadata;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
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

use clap::{Arg, Command};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use log::{debug, error, info, warn};
use r2d2::{ManageConnection, Pool};
use serde::{Deserialize, Serialize};

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

#[allow(dead_code)]
struct PoolMetrics {
    active_connections: AtomicU64,
    idle_connections: AtomicU64,
    total_checkouts: AtomicU64,
    total_timeouts: AtomicU64,
}

struct FSConnectionManager {
    max_handles_per_conn: usize,
    handle_timeout: Duration,
}

impl FSConnectionManager {
    fn check_connection_limits(&self, conn: &FSConnection) -> bool {
        conn.file_handles.len() < self.max_handles_per_conn
    }

    fn cleanup_old_handles(&self, conn: &mut FSConnection) {
        conn.cleanup_stale_handles(self.handle_timeout);
    }
}

impl ManageConnection for FSConnectionManager {
    type Connection = FSConnection;
    type Error = io::Error;

    fn connect(&self) -> Result<FSConnection, Self::Error> {
        Ok(FSConnection {
            file_handles: HashMap::new(),
            max_handles: self.max_handles_per_conn,
        })
    }

    fn is_valid(&self, conn: &mut FSConnection) -> Result<(), io::Error> {
        self.cleanup_old_handles(conn);
        self.check_connection_limits(conn)
            .then_some(())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Too many handles"))
    }

    fn has_broken(&self, conn: &mut FSConnection) -> bool {
        conn.file_handles.len() >= conn.max_handles
    }
}

struct FSConnection {
    file_handles: HashMap<u64, fs::File>,
    max_handles: usize,
}

impl FSConnection {
    fn cleanup_stale_handles(&mut self, max_age: Duration) {
        let now = SystemTime::now();
        self.file_handles.retain(|_, file| {
            if let Ok(metadata) = file.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = now.duration_since(modified) {
                        return age <= max_age;
                    }
                }
            }
            false
        });
    }
}

impl Drop for FSConnection {
    fn drop(&mut self) {
        // Ensure all file handles are properly closed
        self.file_handles.clear();
    }
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
    connection_pool: Arc<Pool<FSConnectionManager>>,
    total_checkouts: AtomicU64,
}

impl PassthroughFS {
    fn new(target_dir: PathBuf, mapping_file: String) -> Self {
        let pool_config = r2d2::Pool::builder()
            .max_size((num_cpus::get() * 4) as u32)
            .min_idle(Some((num_cpus::get()) as u32))
            .max_lifetime(Some(Duration::from_secs(3600)))
            .idle_timeout(Some(Duration::from_secs(300)))
            .connection_timeout(Duration::from_secs(10))
            .build(FSConnectionManager {
                max_handles_per_conn: 1000,
                handle_timeout: Duration::from_secs(60),
            })
            .expect("Failed to create connection pool");

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
            connection_pool: Arc::new(pool_config),
            total_checkouts: AtomicU64::new(0),
        }
    }

    fn get_connection(&self) -> r2d2::PooledConnection<FSConnectionManager> {
        let conn = self
            .connection_pool
            .get()
            .expect("Failed to get connection from pool");

        // Update checkout count
        self.total_checkouts.fetch_add(1, Ordering::Relaxed);

        conn
    }

    fn get_pool_metrics(&self) -> PoolMetrics {
        PoolMetrics {
            active_connections: AtomicU64::new(self.connection_pool.state().connections as u64),
            idle_connections: AtomicU64::new(self.connection_pool.state().idle_connections as u64),
            // Use the separate counter we maintain
            total_checkouts: AtomicU64::new(self.total_checkouts.load(Ordering::Relaxed)),
            total_timeouts: AtomicU64::new(0),
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

    fn get_parent_path(&self, parent: u64) -> Option<PathBuf> {
        if parent == 1 {
            Some(PathBuf::from("/"))
        } else {
            self.get_path_by_ino(parent)
        }
    }

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
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.file_type().is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: to_system_time(metadata.atime()),
            mtime: to_system_time(metadata.mtime()),
            ctime: to_system_time(metadata.ctime()),
            crtime: to_system_time(metadata.ctime()),
            kind: file_type,
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

impl Clone for PassthroughFS {
    fn clone(&self) -> Self {
        Self {
            target_dir: self.target_dir.clone(),
            file_mapping: RwLock::new(self.file_mapping.read().unwrap().clone()),
            file_cache: RwLock::new(self.file_cache.read().unwrap().clone()),
            mapping_file: self.mapping_file.clone(),
            last_modified: RwLock::new(*self.last_modified.read().unwrap()),
            last_size: RwLock::new(*self.last_size.read().unwrap()),
            next_ino: AtomicU64::new(self.next_ino.load(Ordering::Relaxed)),
            ino_to_path: RwLock::new(self.ino_to_path.read().unwrap().clone()),
            path_to_ino: RwLock::new(self.path_to_ino.read().unwrap().clone()),
            connection_pool: self.connection_pool.clone(),
            total_checkouts: AtomicU64::new(self.total_checkouts.load(Ordering::Relaxed)),
        }
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

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
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

        let mut conn = fs.get_connection();

        // Try to get existing file handle from pool
        if let Some(file) = conn.file_handles.get(&ino) {
            let mut buffer = vec![0; size as usize];
            match file.read_at(&mut buffer, offset as u64) {
                Ok(bytes_read) => {
                    reply.data(&buffer[..bytes_read]);
                    return;
                }
                Err(_) => {
                    // Handle error but continue to try fresh open
                }
            }
        }

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
                        conn.file_handles.insert(ino, file);
                        reply.data(&buffer[..bytes_read]);
                    }
                    Err(_) => reply.error(libc::EIO),
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

        let mut conn = fs.get_connection();

        if let Some(file) = conn.file_handles.get_mut(&ino) {
            match file.write_at(data, offset as u64) {
                Ok(bytes_written) => {
                    fs.invalidate_attr(ino);
                    reply.written(bytes_written as u32);
                    return;
                }
                Err(_) => {
                    conn.file_handles.remove(&ino);
                }
            }
        }

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match OpenOptions::new().write(true).open(&path) {
            Ok(file) => {
                match file.write_at(data, offset as u64) {
                    Ok(bytes_written) => {
                        conn.file_handles.insert(ino, file);
                        fs.invalidate_attr(ino);
                        reply.written(bytes_written as u32);
                    }
                    Err(err) => {
                        error!("Write operation failed: {}, Error: {}", path.display(), err);
                        reply.error(libc::EIO);
                    }
                }
            }
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
                            } else if ft.is_symlink() {
                                FileType::Symlink
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

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
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
            Ok(file) => {
                let ino = fs
                    .get_ino_by_path(&full_path)
                    .unwrap_or_else(|| fs.insert_path(full_path.clone()));

                // Store the handle
                let mut conn = fs.get_connection();
                conn.file_handles.insert(ino, file);

                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        let attr = fs.to_file_attr(metadata, ino);
                        fs.set_cached_attr(ino, attr.clone());
                        // Use ino as the file handle (fh)
                        reply.created(&Duration::from_secs(0), &attr, 0, ino, 0);
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

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "mkdir",
            &format!("parent: {}, name: {:?}, mode: {:o}", parent, name, mode),
        );

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let full_path = if parent_path == PathBuf::from("/") {
            PathBuf::from("/").join(name)
        } else {
            parent_path.join(name)
        };

        match fs::create_dir(&full_path) {
            Ok(()) => {
                let ino = fs
                    .get_ino_by_path(&full_path)
                    .unwrap_or_else(|| fs.insert_path(full_path.clone()));

                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        let attr = fs.to_file_attr(metadata, ino);
                        fs.set_cached_attr(ino, attr.clone());
                        reply.entry(&Duration::from_secs(0), &attr, 0);
                    }
                    Err(err) => {
                        error!(
                            "Failed to get metadata for created directory: {}, Error: {}",
                            full_path.display(),
                            err
                        );
                        reply.error(libc::EIO);
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to create directory: {}, Error: {}",
                    full_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let fs = &*self.fs;
        fs.log_operation("unlink", &format!("parent: {}, name: {:?}", parent, name));

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let full_path = parent_path.join(name);
        match fs::remove_file(&full_path) {
            Ok(()) => reply.ok(),
            Err(err) => {
                error!(
                    "Failed to remove file: {}, Error: {}",
                    full_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let fs = &*self.fs;
        fs.log_operation("rmdir", &format!("parent: {}, name: {:?}", parent, name));

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let full_path = parent_path.join(name);
        match fs::remove_dir(&full_path) {
            Ok(()) => reply.ok(),
            Err(err) => {
                error!(
                    "Failed to remove directory: {}, Error: {}",
                    full_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "rename",
            &format!(
                "parent: {}, name: {:?}, newparent: {}, newname: {:?}",
                parent, name, newparent, newname
            ),
        );

        let parent_path = match fs.get_parent_path(parent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let new_parent_path = match fs.get_parent_path(newparent) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let old_path = parent_path.join(name);
        let new_path = new_parent_path.join(newname);

        match fs::rename(&old_path, &new_path) {
            Ok(()) => {
                // Update inode mappings
                if let Some(ino) = fs.get_ino_by_path(&old_path) {
                    let mut ino_map = fs.ino_to_path.write().unwrap();
                    let mut path_map = fs.path_to_ino.write().unwrap();
                    ino_map.insert(ino, new_path.clone());
                    path_map.remove(&old_path);
                    path_map.insert(new_path, ino);
                }
                fs.invalidate_all_attrs();
                reply.ok();
            }
            Err(err) => {
                error!(
                    "Failed to rename {} to {}, Error: {}",
                    old_path.display(),
                    new_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let fs = &*self.fs;
        fs.log_operation("setattr", &format!("ino: {}", ino));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Handle mode change (chmod)
        if let Some(mode) = mode {
            if let Err(err) = fs::set_permissions(&path, fs::Permissions::from_mode(mode)) {
                error!("Failed to chmod {}, Error: {}", path.display(), err);
                reply.error(libc::EIO);
                return;
            }
        }

        // Handle ownership change (chown)
        if uid.is_some() || gid.is_some() {
            unsafe {
                let res = libc::chown(
                    path.as_os_str().as_bytes().as_ptr() as *const i8,
                    uid.unwrap_or(u32::MAX),
                    gid.unwrap_or(u32::MAX),
                );
                if res != 0 {
                    error!(
                        "Failed to chown {}, Error: {}",
                        path.display(),
                        io::Error::last_os_error()
                    );
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

        // Handle size change (truncate)
        if let Some(size) = size {
            if let Err(err) = OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(size))
            {
                error!("Failed to truncate {}, Error: {}", path.display(), err);
                reply.error(libc::EIO);
                return;
            }
        }

        match fs::metadata(&path) {
            Ok(metadata) => {
                let attr = fs.to_file_attr(metadata, ino);
                fs.set_cached_attr(ino, attr.clone());
                reply.attr(&Duration::from_secs(0), &attr);
            }
            Err(err) => {
                error!("Failed to get metadata {}, Error: {}", path.display(), err);
                reply.error(libc::EIO);
            }
        }
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let fs = &*self.fs;
        fs.log_operation(
            "symlink",
            &format!("parent: {}, name: {:?}, link: {:?}", parent, name, link),
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

        let full_path = parent_path.join(name);
        match std::os::unix::fs::symlink(link, &full_path) {
            Ok(()) => {
                let ino = fs
                    .get_ino_by_path(&full_path)
                    .unwrap_or_else(|| fs.insert_path(full_path.clone()));

                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        let attr = fs.to_file_attr(metadata, ino);
                        fs.set_cached_attr(ino, attr.clone());
                        reply.entry(&Duration::from_secs(0), &attr, 0);
                    }
                    Err(err) => {
                        error!(
                            "Failed to get metadata for symlink: {}, Error: {}",
                            full_path.display(),
                            err
                        );
                        reply.error(libc::EIO);
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to create symlink: {}, Error: {}",
                    full_path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let fs = &*self.fs;
        fs.log_operation("readlink", &format!("ino: {}", ino));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match fs::read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(err) => {
                error!("Failed to read symlink: {}, Error: {}", path.display(), err);
                reply.error(libc::EIO);
            }
        }
    }

    fn fsync(&mut self, _req: &Request, ino: u64, _fh: u64, datasync: bool, reply: ReplyEmpty) {
        let fs = &*self.fs;
        fs.log_operation("fsync", &format!("ino: {}, datasync: {}", ino, datasync));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match OpenOptions::new().write(true).open(&path) {
            Ok(file) => {
                if datasync {
                    match file.sync_data() {
                        Ok(()) => reply.ok(),
                        Err(err) => {
                            error!("Failed to sync data for {}, Error: {}", path.display(), err);
                            reply.error(libc::EIO);
                        }
                    }
                } else {
                    match file.sync_all() {
                        Ok(()) => reply.ok(),
                        Err(err) => {
                            error!("Failed to sync all for {}, Error: {}", path.display(), err);
                            reply.error(libc::EIO);
                        }
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to open file for fsync {}, Error: {}",
                    path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn fsyncdir(&mut self, _req: &Request, ino: u64, _fh: u64, datasync: bool, reply: ReplyEmpty) {
        let fs = &*self.fs;
        fs.log_operation("fsyncdir", &format!("ino: {}, datasync: {}", ino, datasync));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match fs::File::open(&path) {
            Ok(file) => {
                if datasync {
                    match file.sync_data() {
                        Ok(()) => reply.ok(),
                        Err(err) => {
                            error!(
                                "Failed to sync dir data for {}, Error: {}",
                                path.display(),
                                err
                            );
                            reply.error(libc::EIO);
                        }
                    }
                } else {
                    match file.sync_all() {
                        Ok(()) => reply.ok(),
                        Err(err) => {
                            error!(
                                "Failed to sync dir all for {}, Error: {}",
                                path.display(),
                                err
                            );
                            reply.error(libc::EIO);
                        }
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to open dir for fsync {}, Error: {}",
                    path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn flush(&mut self, _req: &Request, ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        let fs = &*self.fs;
        fs.log_operation("flush", &format!("ino: {}", ino));

        let path = match fs.get_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match OpenOptions::new().write(true).open(&path) {
            Ok(file) => match file.sync_all() {
                Ok(()) => reply.ok(),
                Err(err) => {
                    error!("Failed to flush {}, Error: {}", path.display(), err);
                    reply.error(libc::EIO);
                }
            },
            Err(err) => {
                error!(
                    "Failed to open file for flush {}, Error: {}",
                    path.display(),
                    err
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let fs = &*self.fs;
        fs.log_operation("statfs", "querying filesystem statistics");

        match nix::sys::statfs::statfs(&fs.target_dir) {
            Ok(stat) => {
                reply.statfs(
                    stat.blocks(),            // Total blocks
                    stat.blocks_free(),       // Free blocks
                    stat.blocks_available(),  // Available blocks
                    stat.files(),             // Total inodes
                    stat.files_free(),        // Free inodes
                    stat.block_size() as u32, // Block size
                    256,                      // Maximum name length (common value)
                    stat.block_size() as u32, // Fragment size
                );
            }
            Err(err) => {
                error!("Failed to get filesystem statistics: {}", err);
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
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::thread;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use crate::PassthroughFS;

    use super::*;

    fn create_temp_dir_for_test(test_name: &str) -> PathBuf {
        let base = env::temp_dir();
        let temp_dir = base.join(format!("passthroughfs_pipe_test_{}", test_name));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        temp_dir
    }

    // Add to your existing test setup functions
    fn create_test_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn create_test_dir(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        // Clean up any existing directory
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
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
                let mut file = OpenOptions::new()
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

    #[test]
    fn test_mkdir_and_rmdir() {
        let temp_dir = create_temp_dir_for_test("test_mkdir_rmdir");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let dir_path = temp_dir.join("testdir");
        let _dir_ino = fs.insert_path(dir_path.clone());

        // Test directory creation
        fs::create_dir(&dir_path).unwrap();
        let metadata = fs::metadata(&dir_path).unwrap();
        assert!(metadata.is_dir());

        // Test directory removal
        fs::remove_dir(&dir_path).unwrap();
        assert!(!dir_path.exists());
    }

    #[test]
    fn test_rename_operations() {
        let temp_dir = create_temp_dir_for_test("test_rename");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let old_path = create_test_file(&temp_dir, "old.txt", b"test");
        let new_path = temp_dir.join("new.txt");

        let _old_ino = fs.insert_path(old_path.clone());
        fs::rename(&old_path, &new_path).unwrap();

        assert!(!old_path.exists());
        assert!(new_path.exists());
        assert_eq!(fs::read(&new_path).unwrap(), b"test");
    }

    #[test]
    fn test_chmod_and_chown() {
        let temp_dir = create_temp_dir_for_test("test_permissions");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let file_path = create_test_file(&temp_dir, "test.txt", b"test");
        let _ino = fs.insert_path(file_path.clone());

        // Test chmod
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
        let metadata = fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    #[test]
    fn test_symlink_operations() {
        let temp_dir = create_temp_dir_for_test("test_symlink");
        let _fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let target_path = create_test_file(&temp_dir, "target.txt", b"test");
        let link_path = temp_dir.join("link.txt");

        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();
        assert!(link_path.exists());

        let link_target = fs::read_link(&link_path).unwrap();
        assert_eq!(link_target, target_path);
    }

    #[test]
    fn test_truncate() {
        let temp_dir = create_temp_dir_for_test("test_truncate");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let file_path = create_test_file(&temp_dir, "test.txt", b"hello world");
        let _ino = fs.insert_path(file_path.clone());

        // Truncate to 5 bytes
        let file = OpenOptions::new().write(true).open(&file_path).unwrap();
        file.set_len(5).unwrap();

        assert_eq!(fs::read(&file_path).unwrap(), b"hello");
    }

    #[test]
    fn test_directory_operations() {
        let temp_dir = create_temp_dir_for_test("test_directory_ops");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Create a test directory
        let dir_path = create_test_dir(&temp_dir, "test_dir");
        let _dir_ino = fs.insert_path(dir_path.clone());

        // Create a file inside the test directory
        let file_path = create_test_file(&dir_path, "test.txt", b"hello");
        let _file_ino = fs.insert_path(file_path.clone());

        // Verify directory structure
        assert!(dir_path.is_dir());
        assert!(file_path.is_file());
        assert_eq!(fs::read(&file_path).unwrap(), b"hello");

        // Test directory attributes
        let dir_metadata = fs::metadata(&dir_path).unwrap();
        assert!(dir_metadata.is_dir());

        // Clean up
        fs::remove_file(&file_path).unwrap();
        fs::remove_dir(&dir_path).unwrap();
    }

    fn spawn_concurrent_file_operations(
        fs: Arc<PassthroughFS>,
        temp_dir: Arc<PathBuf>,
        num_threads: u32,
        ops_per_thread: u32,
    ) -> Vec<JoinHandle<()>> {
        (0..num_threads)
            .map(|i| {
                let fs_clone = fs.clone();
                let temp_dir = temp_dir.clone();
                thread::spawn(move || {
                    for j in 0..ops_per_thread {
                        let mut conn = fs_clone.get_connection();
                        let file_path = temp_dir.join(format!("test_file_{}_{}.txt", i, j));
                        fs::write(&file_path, "test").unwrap();
                        conn.file_handles
                            .insert((i * 100 + j) as u64, fs::File::open(&file_path).unwrap());
                        thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect()
    }

    #[test]
    fn test_nested_directory_structure() {
        let temp_dir = create_temp_dir_for_test("test_nested_dirs");
        let _fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Create nested directory structure
        let parent_dir = create_test_dir(&temp_dir, "parent");
        let child_dir = create_test_dir(&parent_dir, "child");
        let grandchild_dir = create_test_dir(&child_dir, "grandchild");

        // Create files at different levels
        let file1 = create_test_file(&parent_dir, "file1.txt", b"level1");
        let file2 = create_test_file(&child_dir, "file2.txt", b"level2");
        let file3 = create_test_file(&grandchild_dir, "file3.txt", b"level3");

        // Verify structure and contents
        assert!(parent_dir.is_dir());
        assert!(child_dir.is_dir());
        assert!(grandchild_dir.is_dir());
        assert_eq!(fs::read(&file1).unwrap(), b"level1");
        assert_eq!(fs::read(&file2).unwrap(), b"level2");
        assert_eq!(fs::read(&file3).unwrap(), b"level3");
    }

    #[test]
    fn test_directory_permissions() {
        let temp_dir = create_temp_dir_for_test("test_dir_perms");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let dir_path = create_test_dir(&temp_dir, "restricted_dir");
        let _dir_ino = fs.insert_path(dir_path.clone());

        // Set restrictive permissions
        fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&dir_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }

    #[test]
    fn test_symlink_edge_cases() {
        let temp_dir = create_temp_dir_for_test("test_symlink_edges");
        let _fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Test circular symlinks
        let link1_path = temp_dir.join("link1");
        let link2_path = temp_dir.join("link2");

        std::os::unix::fs::symlink(&link2_path, &link1_path).unwrap();
        std::os::unix::fs::symlink(&link1_path, &link2_path).unwrap();

        // Test dangling symlink
        let nonexistent = temp_dir.join("nonexistent");
        let dangling_link = temp_dir.join("dangling");
        std::os::unix::fs::symlink(&nonexistent, &dangling_link).unwrap();

        // Use symlink_metadata instead of exists()
        assert!(fs::symlink_metadata(&dangling_link).is_ok());
        assert!(fs::read_link(&dangling_link).is_ok());
    }

    #[test]
    fn test_file_operations_with_special_characters() {
        let temp_dir = create_temp_dir_for_test("test_special_chars");
        let _fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Test files with spaces and special characters
        let special_names = vec![
            "file with spaces.txt",
            "file_with_उनिकोड.txt",
            "file_with_symbols!@#$%.txt",
            ".hidden_file",
        ];

        for name in special_names {
            let file_path = create_test_file(&temp_dir, name, b"content");
            assert!(file_path.exists());
            assert_eq!(fs::read(&file_path).unwrap(), b"content");
        }
    }

    #[test]
    fn test_concurrent_directory_access() {
        let temp_dir = create_temp_dir_for_test("test_concurrent");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());
        let temp_dir = Arc::new(temp_dir);
        let fs = Arc::new(fs);

        let handles = spawn_concurrent_file_operations(fs, temp_dir.clone(), 20, 50);

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Check the count in temp_dir itself
        let count = fs::read_dir(&*temp_dir).unwrap().count();
        assert_eq!(count, 1000); // 20 threads * 50 files each
    }

    #[test]
    fn test_empty_and_large_files() {
        let temp_dir = create_temp_dir_for_test("test_file_sizes");
        let _fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Test empty file
        let empty_file = create_test_file(&temp_dir, "empty.txt", b"");
        assert_eq!(fs::metadata(&empty_file).unwrap().len(), 0);

        // Test large file (1MB)
        let large_data = vec![0u8; 1024 * 1024];
        let large_file = create_test_file(&temp_dir, "large.txt", &large_data);
        assert_eq!(fs::metadata(&large_file).unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn test_connection_pool_metrics() {
        let temp_dir = create_temp_dir_for_test("test_pool_metrics");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Create multiple connections to test metrics
        let mut connections = Vec::new();
        for _ in 0..5 {
            connections.push(fs.get_connection());
        }

        let metrics = fs.get_pool_metrics();
        assert!(metrics.active_connections.load(Ordering::Relaxed) > 0);
        assert!(metrics.total_checkouts.load(Ordering::Relaxed) >= 5);

        // Test idle connections
        drop(connections);
        let metrics = fs.get_pool_metrics();
        assert!(metrics.idle_connections.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_connection_pool_limits_and_timeouts() {
        let temp_dir = create_temp_dir_for_test("test_pool_limits");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let max_connections = (num_cpus::get() * 4) as u32;
        let mut connections = Vec::new();

        // Get connections until we hit an error
        for _ in 0..=max_connections + 1 {
            match fs.connection_pool.get() {
                Ok(conn) => connections.push(conn),
                Err(_) => {
                    // Expected error when pool is exhausted
                    return;
                }
            }
        }

        panic!("Should have hit connection pool limit");
    }

    #[test]
    fn test_connection_cleanup() {
        let temp_dir = create_temp_dir_for_test("test_cleanup");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let mut conn = fs.get_connection();

        // Create test file
        let test_file = temp_dir.join("test.txt");
        fs::write(&test_file, "test").unwrap();

        let file = fs::File::open(&test_file).unwrap();
        conn.file_handles.insert(1, file);

        conn.cleanup_stale_handles(Duration::from_secs(0));
        assert!(conn.file_handles.is_empty());
    }

    #[test]
    fn test_connection_pool_under_stress() {
        let temp_dir = create_temp_dir_for_test("test_pool_stress");
        let fs = Arc::new(PassthroughFS::new(
            temp_dir.clone(),
            "mapping.pipe".to_string(),
        ));

        let temp_dir = Arc::new(temp_dir); // Make temp_dir shareable across threads

        let handles = spawn_concurrent_file_operations(fs.clone(), temp_dir.clone(), 20, 50);

        for handle in handles {
            handle.join().unwrap();
        }

        let metrics = fs.get_pool_metrics();
        assert!(metrics.total_checkouts.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn test_connection_recovery() {
        let temp_dir = create_temp_dir_for_test("test_recovery");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        // Simulate a failed connection
        let mut conn = fs.get_connection();
        conn.file_handles.clear();
        drop(conn);

        // Test pool recovery
        let new_conn = fs.get_connection();
        assert!(new_conn.file_handles.is_empty());

        let metrics = fs.get_pool_metrics();
        assert!(metrics.active_connections.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_connection_timeout_recovery() {
        let temp_dir = create_temp_dir_for_test("test_timeout_recovery");
        let fs = PassthroughFS::new(temp_dir.clone(), "mapping.pipe".to_string());

        let max_conns = (num_cpus::get() * 4) as u32;
        let mut connections = Vec::new();

        // In test_connection_timeout_recovery
        for _ in 0..max_conns {
            if let Ok(conn) = fs.connection_pool.get() {
                connections.push(conn);
            }
        }

        // Test pool exhaustion
        assert!(fs.connection_pool.get().is_err());

        // Release one connection
        connections.pop();

        // Should be able to get a connection now
        assert!(fs.connection_pool.get().is_ok());
    }
}
