/*
 * Copyright (C) 2024 Nos Doughty
 *
 * Licensed under:
 * 1. Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 * 2. GNU General Public License, Version 3 (https://www.gnu.org/licenses/gpl-3.0.html)
 *
 * Fallback:
 * If you choose the Apache License, Version 2.0, and any provision of that license is invalidated in a jurisdiction,
 * this software defaults to the GNU General Public License, Version 3 or later, for that jurisdiction.
 */
use clap::{Arg, Command};
use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request, ReplyCreate};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsStr, fs, io, os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt}, path::PathBuf, sync::RwLock, time::{Duration, SystemTime, UNIX_EPOCH}};
use std::fs::File;
use std::path::Path;
use std::time::Instant;
use nix::fcntl::{FlockArg};


const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 4096;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Mapping {
    path: String,
    target: String,
    permissions: Option<Permissions>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Permissions {
    owner: Option<u32>,
    group: Option<u32>,
    mode: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FileMapping {
    mappings: Vec<Mapping>,
}

#[derive(Clone)]
struct CachedAttr {
    attr: FileAttr,
    timestamp: Instant,
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
}

impl PassthroughFS {
    fn new(target_dir: PathBuf, mapping_file: String) -> Self {
        Self {
            target_dir,
            file_mapping: RwLock::new(HashMap::new()),
            file_cache: RwLock::new(HashMap::new()),
            mapping_file,
            last_modified: RwLock::new(None),
        }
    }

    fn reload_mappings(&self) {
        let metadata = match fs::metadata(&self.mapping_file) {
            Ok(metadata) => metadata,
            Err(err) => {
                eprintln!("Failed to get metadata for {}: {:?}", self.mapping_file, err);
                return; // Ignore if the file doesn't exist
            }
        };

        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(err) => {
                eprintln!("Failed to get modification time for {}: {:?}", self.mapping_file, err);
                return; // Ignore if the modification time can't be determined
            }
        };

        let mut last_modified = self.last_modified.write().unwrap();
        if let Some(last_time) = *last_modified {
            if last_time >= modified {
                eprintln!("No changes detected for {}", self.mapping_file);
                return; // Skip reload if the file hasn't changed
            }
        }

        eprintln!("Reloading mappings from {}", self.mapping_file);

        if let Ok(data) = fs::read_to_string(&self.mapping_file) {
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, Mapping>>(&data) {
                let mut mappings = self.file_mapping.write().unwrap();
                mappings.clear();
                mappings.extend(parsed);
                *last_modified = Some(modified); // Update last modified time
                eprintln!("Mappings successfully reloaded: {:?}", mappings.keys().collect::<Vec<_>>());
            } else {
                eprintln!("Failed to parse JSON in {}", self.mapping_file);
            }
        } else {
            eprintln!("Failed to read {}", self.mapping_file);
        }
    }

    fn resolve_path(&self, path: &str) -> io::Result<PathBuf> {
        let mappings = self.file_mapping.read().unwrap();
        if let Some(mapping) = mappings.get(path) {
            Ok(PathBuf::from(&mapping.target))
        } else {
            Ok(self.target_dir.join(path.trim_start_matches('/'))) // Default to passthrough
        }
    }

    fn get_inode(&self, path: &Path) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        hasher.finish()
    }

    fn get_cached_attr(&self, ino: u64) -> Option<FileAttr> {
        let cache = self.file_cache.read().unwrap();
        if let Some(cached) = cache.get(&ino) {
            if cached.timestamp.elapsed() < TTL {
                return Some(cached.attr.clone());
            }
        }
        None
    }

    fn set_cached_attr(&self, ino: u64, attr: FileAttr) {
        let mut cache = self.file_cache.write().unwrap();
        cache.insert(ino, CachedAttr { attr, timestamp: Instant::now() });
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

    fn lock_file(&self, file_path: &PathBuf) -> io::Result<()> {
        let file = File::open(file_path)?;
        match nix::fcntl::Flock::lock(file, FlockArg::LockExclusive) {
            Ok(_) => Ok(()),
            Err((_, err)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to lock file: {:?}", err),
            )),
        }
    }

    fn unlock_file(&self, file_path: &PathBuf) -> io::Result<()> {
        let file = File::open(file_path)?;
        match nix::fcntl::Flock::lock(file, FlockArg::Unlock) {
            Ok(_) => Ok(()),
            Err((_, err)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to unlock file: {:?}", err),
            )),
        }
    }

    fn log_operation(&self, operation: &str, path: &str) {
        log::info!("Operation: {}, Path: {}", operation, path);
    }
}

impl Filesystem for PassthroughFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // Log the operation
        self.log_operation("lookup", &format!("parent inode: {}, name: {:?}", parent, name));

        // Construct the path for the lookup
        let parent_path = if parent == 1 {
            PathBuf::new()
        } else {
            PathBuf::from(format!("inode-{}", parent))
        };

        let full_path = match self.resolve_path(&parent_path.join(name).to_string_lossy()) {
            Ok(path) => path,
            Err(_) => {
                reply.error(libc::ENOENT); // Logically no such entry
                return;
            }
        };

        // Check if the metadata is cached
        if let Ok(metadata) = fs::metadata(&full_path) {
            let ino = self.get_inode(&full_path); // Generate an inode number based on the path (if needed)
            let attr = self.to_file_attr(metadata, ino);

            // Cache the result
            self.set_cached_attr(ino, attr.clone());

            // Reply with the entry
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        self.log_operation("getattr", &format!("inode-{}", ino));

        if let Some(attr) = self.get_cached_attr(ino) {
            reply.attr(&TTL, &attr);
            return;
        }

        let path = format!("inode-{}", ino);
        match self.resolve_path(&path) {
            Ok(full_path) => match fs::metadata(full_path) {
                Ok(metadata) => {
                    let attr = self.to_file_attr(metadata, ino);
                    self.set_cached_attr(ino, attr.clone());
                    reply.attr(&TTL, &attr);
                }
                Err(_) => reply.error(libc::ENOENT),
            },
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
        // Log the operation
        self.log_operation("read", &format!("inode: {}, offset: {}, size: {}", ino, offset, size));

        // Resolve the path from the inode
        let path = format!("inode-{}", ino);
        let full_path = match self.resolve_path(&path) {
            Ok(path) => path,
            Err(_) => {
                reply.error(libc::ENOENT); // Path not found
                return;
            }
        };

        // Open the file and attempt to lock it for reading
        match fs::File::open(&full_path) {
            Ok(file) => {
                if let Err(err) = self.lock_file(&full_path) {
                    log::warn!("Failed to lock file for reading: {}, Error: {}", full_path.display(), err);
                    reply.error(libc::EACCES); // Permission denied
                    return;
                }

                // Read the file contents
                let mut buffer = vec![0; size as usize];
                match file.read_at(&mut buffer, offset as u64) {
                    Ok(bytes_read) => {
                        // Unlock the file
                        let _ = self.unlock_file(&full_path);
                        reply.data(&buffer[..bytes_read]);
                    }
                    Err(_) => {
                        // Unlock the file on error
                        let _ = self.unlock_file(&full_path);
                        reply.error(libc::EIO); // I/O error
                    }
                }
            }
            Err(_) => reply.error(libc::ENOENT), // File not found
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
        // Log the operation
        self.log_operation("write", &format!("inode: {}, offset: {}, size: {}", ino, offset, data.len()));

        // Resolve the path from the inode
        let path = format!("inode-{}", ino);
        let full_path = match self.resolve_path(&path) {
            Ok(path) => path,
            Err(_) => {
                reply.error(libc::ENOENT); // Path not found
                return;
            }
        };

        // Open the file and lock it for writing
        match fs::OpenOptions::new().write(true).open(&full_path) {
            Ok(file) => {
                if let Err(err) = self.lock_file(&full_path) {
                    log::warn!("Failed to lock file for writing: {}, Error: {}", full_path.display(), err);
                    reply.error(libc::EACCES); // Permission denied
                    return;
                }

                // Perform the write operation
                match file.write_at(data, offset as u64) {
                    Ok(bytes_written) => {
                        // Unlock the file after a successful write
                        let _ = self.unlock_file(&full_path);
                        reply.written(bytes_written as u32);
                    }
                    Err(err) => {
                        log::error!("Write operation failed: {}, Error: {}", full_path.display(), err);
                        // Unlock the file on error
                        let _ = self.unlock_file(&full_path);
                        reply.error(libc::EIO); // I/O error
                    }
                }
            }
            Err(_) => {
                log::error!("File not found for writing: {}", full_path.display());
                reply.error(libc::ENOENT); // File not found
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Log the release operation
        self.log_operation("release", &format!("inode: {}", ino));

        // Resolve the path from the inode
        let path = format!("inode-{}", ino);
        let full_path = match self.resolve_path(&path) {
            Ok(path) => path,
            Err(_) => {
                reply.error(libc::ENOENT); // Path not found
                return;
            }
        };

        // Attempt to unlock the file
        match self.unlock_file(&full_path) {
            Ok(_) => {
                log::info!("Successfully released lock for: {}", full_path.display());
                reply.ok();
            }
            Err(err) => {
                log::warn!(
                "Failed to release lock for file: {}, Error: {}",
                full_path.display(),
                err
            );
                reply.error(libc::EIO); // I/O error on unlocking
            }
        }
    }

    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        self.log_operation("readdir", &format!("inode-{}", ino));

        let path = format!("inode-{}", ino);
        let full_path = match self.resolve_path(&path) {
            Ok(path) => path,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if let Ok(entries) = fs::read_dir(full_path) {
            let mut index = 0;
            for entry in entries.skip(offset as usize) {
                if let Ok(entry) = entry {
                    let metadata = entry.metadata().unwrap();
                    let name = entry.file_name();
                    let filetype = if metadata.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    let _ = reply.add(ino + index, (index + 1) as i64, filetype, &name);
                    index += 1;
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
        // Log the operation
        self.log_operation(
            "create",
            &format!("parent inode: {}, name: {:?}, mode: {:o}", parent, name, mode),
        );

        // Resolve the parent directory path
        let parent_path = format!("inode-{}", parent);
        let full_path = match self.resolve_path(&parent_path) {
            Ok(path) => path.join(name),
            Err(_) => {
                reply.error(libc::ENOENT); // Parent directory not found
                return;
            }
        };

        // Attempt to create the file
        match fs::OpenOptions::new().write(true).create(true).mode(mode).open(&full_path) {
            Ok(_) => {
                // Lock the file after creation
                if let Err(err) = self.lock_file(&full_path) {
                    log::warn!(
                    "Failed to lock newly created file: {}, Error: {}",
                    full_path.display(),
                    err
                );
                    reply.error(libc::EACCES); // Permission denied
                    return;
                }

                // Fetch metadata and generate the file attributes
                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        let ino = self.get_inode(&full_path); // Generate an inode number
                        let attr = self.to_file_attr(metadata, ino);

                        // Cache the file attributes
                        self.set_cached_attr(ino, attr.clone());

                        // Reply with created file information
                        reply.created(&TTL, &attr, 0, 0, 0);
                    }
                    Err(err) => {
                        log::error!("Failed to retrieve metadata for created file: {}, Error: {}", full_path.display(), err);
                        reply.error(libc::EIO); // I/O error
                    }
                }

                // Unlock the file after metadata processing
                let _ = self.unlock_file(&full_path);
            }
            Err(err) => {
                log::error!(
                "Failed to create file: {}, Error: {}",
                full_path.display(),
                err
            );
                reply.error(libc::EIO); // I/O error during file creation
            }
        }
    }
}

fn main() {
    let matches = Command::new("PassthroughFS")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
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
                .help("The JSON file containing mappings")
                .required(false)
                .default_value("filemapping.json")
                .value_parser(clap::value_parser!(String)),
        )
        .get_matches();

    let mountpoint = matches.get_one::<String>("mountpoint").unwrap();
    let target = matches.get_one::<String>("target").unwrap();
    let mapping_file = matches.get_one::<String>("mapping_file").unwrap();

    let fs = PassthroughFS::new(PathBuf::from(target), mapping_file.clone());
    fs.reload_mappings();

    fuser::mount2(fs, mountpoint, &[]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self};
    use std::path::Path;

    fn create_temp_dir() -> PathBuf {
        let temp_dir = std::env::temp_dir().join("passthroughfs_test");
        let _ = fs::remove_dir_all(&temp_dir); // Clean up before starting
        fs::create_dir_all(&temp_dir).unwrap();
        temp_dir
    }

    #[test]
    fn test_resolve_path() {
        let temp_dir = create_temp_dir();
        let real_target = temp_dir.join("real_target");
        fs::create_dir_all(&real_target).unwrap();
        let mapping_file = temp_dir.join("filemapping.json");

        // Write test mappings
        let mappings = r#"
    {
        "/example.txt": {
            "path": "/example.txt",
            "target": "/real_target/example.txt",
            "permissions": null
        }
    }
    "#;
        fs::write(&mapping_file, mappings).unwrap();

        // Create the target file
        let target_file = real_target.join("example.txt");
        fs::write(&target_file, "Example content").unwrap();

        let fs = PassthroughFS::new(temp_dir.clone(), mapping_file.to_string_lossy().to_string());
        fs.reload_mappings();

        // Test resolve_path with mapping
        let resolved = fs.resolve_path("/example.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("/real_target/example.txt"));

        // Test resolve_path without mapping
        let resolved = fs.resolve_path("/unknown.txt").unwrap();
        assert_eq!(resolved, temp_dir.join("unknown.txt"));
    }

    #[test]
    fn test_reload_mappings() {
        let temp_dir = create_temp_dir();
        let mapping_file = temp_dir.join("filemapping.json");

        // Ensure the directory and file are created
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(&mapping_file, "").unwrap(); // Ensure the mapping file exists

        // Write initial mappings
        let initial_mappings = r#"
    {
        "/example.txt": {
            "path": "/example.txt",
            "target": "/real_target/example.txt",
            "permissions": null
        }
    }
    "#;
        fs::write(&mapping_file, initial_mappings).unwrap();

        let fs = PassthroughFS::new(temp_dir.clone(), mapping_file.to_string_lossy().to_string());
        fs.reload_mappings();

        {
            let mappings = fs.file_mapping.read().unwrap();
            assert!(mappings.contains_key("/example.txt"), "Initial mapping should exist");
        }

        // Introduce a short delay to ensure the modification timestamp updates
        std::thread::sleep(Duration::from_millis(100));
        
        // Update mappings
        let updated_mappings = r#"
    {
        "/newfile.txt": {
            "path": "/newfile.txt",
            "target": "/real_target/newfile.txt",
            "permissions": null
        },
        "/example.txt": {
            "path": "/example.txt",
            "target": "/real_target/example.txt",
            "permissions": null
        }
    }
    "#;
        fs::write(&mapping_file, updated_mappings).unwrap();
        fs.reload_mappings();

        {
            let mappings = fs.file_mapping.read().unwrap();
            assert!(mappings.contains_key("/newfile.txt"), "New mapping should exist");
            assert!(mappings.contains_key("/example.txt"), "Original mapping should still exist");
        }
    }

    #[test]
    fn test_get_inode() {
        let path = Path::new("/some/path");
        let fs = PassthroughFS::new(PathBuf::new(), String::new());

        let inode1 = fs.get_inode(path);
        let inode2 = fs.get_inode(path);

        assert_eq!(inode1, inode2);

        let different_inode = fs.get_inode(Path::new("/some/other/path"));
        assert_ne!(inode1, different_inode);
    }
}
