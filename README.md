# PassthroughFS

PassthroughFS is a FUSE-based filesystem written in Rust that allows users to mount a virtual filesystem over a target directory. It provides flexible mappings and optional permissions, making it ideal for virtual directory views and enforcing custom file access policies.

## Features

- **Passthrough Filesystem**: Mirrors a target directory while allowing configurable mappings.
- **JSON-based Configuration**: Define mappings and permissions in an easy-to-read JSON file.
- **Dynamic Reloading**: Automatically reloads mappings when the configuration file changes.
- **File Caching**: Optimized inode-level attribute caching for performance.
- **Permission Control**: Optionally enforce permissions for mapped files.
- **Logging**: Provides detailed operation logs for debugging and monitoring.

## Requirements

- **Rust**: Version 1.70 or later
- **Linux**: With FUSE support enabled
- **Dependencies**:
    - `fuser` crate for FUSE integration
    - `serde` and `serde_json` for JSON parsing

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/PassthroughFS.git
   cd PassthroughFS
   ```

2. Build the project:
   ```bash
    cargo build --release
   ```

3. (Optional) Install the binary globally:
   ```bash
   cargo install --path .
   ```

## Configuration
PassthroughFS uses a JSON configuration file to define mappings. Below is an example configuration (filemapping.json):
   ```json
   {
     "/example.txt": {
       "path": "/example.txt",
       "target": "/underlying_fs/real_example.txt"
     },
     "/example2.txt": {
       "path": "/example2.txt"
     },
     "/some/dir": {
       "path": "/some/dir",
       "target": "/underlying_fs/some/dir"
     }
   }
   ```
### Fields
* `path`: The virtual path in the mounted filesystem.
* `target`: The corresponding actual path in the target directory.

If an entry contains the 'path' field (required) but not the target field (optional), that is treated as if the target 
path has been removed (aka, deleted).

If the target is an absolute path, then that path is used as-is. If the target is a relative path, then that path is
converted to an absolute path by appending it to the path passed in as the `--target` param when starting the fs.  

### Regular file mode vs named pipe mode
PassthroughFS operates in a different mode when the passed filemapping.json file is a named pipe.

For regular mode, the entire file is processed in one chunk. This is triggered when an inotify event is sent, or as a 
fallback, polled for date and size changes every 100ms. Care must be taken to not write to this file when the fs is 
reading it, which means an approach based on an atomic renames or similar will be needed by the writing process. This 
mode is most useful for simple static mappings, perhaps exported from a more dynamic system, and allows the fs to 
operate without a server.

For named pipe mode, a 'protocol' of sorts is implemented by the called expecting a 4-byte length value, which is to be
calculated by the sender, and will trigger the fs to read that many bytes, in however many chunked reads it takes, 
before applying that as the update. After the 4-byte length is pushed, the contents of the file is the same is in the 
regular mode, i.e., a json payload with the structure as documented in the example above. 

### Synchronisation concerns when using named pipes
When using the named-pipe mode of operation, additional failure modes exist around the protocol that is in use (as 
simple as that is!).

If a reader kept reading from a named pipe and the writer sends a partial message, they can get out of sync if the 
pipe is treated as a continuous stream without resetting. However, in the code as currently structured, there are 
several factors that help prevent permanent desynchronisation:

1. **Single-Message Reads With Each Reload**:  
   Each time the filesystem reloads the mappings, it:
    - Opens the named pipe anew (using `OpenOptions::new().read(true).open(...)`).
    - Attempts to read exactly one length-prefixed JSON message.
    - If it fails to read a complete message, it returns without updating mappings.

   Because the pipe is opened fresh for each reload attempt, no partial data from a previous attempt lingers in memory. Once the read attempt finishes—successfully or not—the file descriptor is closed and discarded. If the writer failed mid-message, that half-read message is effectively abandoned.

2. **EOF and Incomplete Messages**:  
   If the writer writes a partial message and then closes the pipe:
    - The `read_exact_bytes` function will eventually hit EOF before finishing the message.
    - The code interprets this as "no complete message" and returns.
    - On the next reload attempt, the pipe is reopened from scratch. Because a named pipe’s contents do not persist once both writer and reader are closed, you start fresh. The next message from the writer will be read as if nothing happened before.

3. **One Writer, One Reader**:  
   With a single writer and a single reader, you don’t have to worry about interleaving messages from multiple sources. The primary failure mode is just that the writer sent an incomplete message and closed. If the writer restarts and sends a new, valid message the next time the filesystem tries to reload, it will succeed. If the writer never fixes its output, you simply never get a new valid mapping, but you won't be permanently stuck reading garbage data since each read attempt starts over.

4. **No Persistent State**:  
   The code doesn't buffer partial reads across reload attempts. Each reload attempt:
    - Opens the pipe.
    - Reads one length+payload message.
    - Closes the pipe.

   Without persistent state, there’s no opportunity for a half-read message to cause a permanent "offset" error. Every reload is a fresh start.

**What Failure Modes Remain?**

- **Writer Never Finishes a Message**:  
  If the writer consistently fails to send a complete message (e.g., always closes the pipe mid-stream), the filesystem will never successfully load updated mappings. It will log warnings and revert to previously loaded mappings (if any), or keep the old state.

- **Writer Sends Garbage Data**:  
  If the writer sends random data that doesn’t parse as valid JSON, the code logs a warning and skips updating mappings. The next reload attempt may succeed if the writer corrects its output.

- **Writer Doesn’t Write At All**:  
  If the writer never sends data or the pipe is empty, you get no updated mappings. The filesystem falls back on whatever it had before.

**In Summary**:

- The approach of opening the named pipe fresh each time prevents permanent desynchronisation.
- Each reload attempt either reads a complete message or fails and returns without changing state.
- If a partial write occurs, the next reload starts from scratch, waiting for a new message from the writer.

Thus, while a writer error can prevent successful updates, it won’t cause an irrecoverable state where the reader is permanently out of sync. The system always attempts to "reset" by re-opening the pipe for each reload attempt.

If such assurance was needed for the sender, one could be added by the writer applying a final entry in the payload of a special path (as a uuid perhaps) which resolves to a memory mapped file under the control of the writer that contains matching content for the uuid.
In cases where there is no match, then the last send can be considered to be lost and resent.

## Usage
1. Create a directory for the mount point:
   ```bash
    mkdir /mnt/passthrough
   ```
2. Run PassthroughFS:
   ```bash
    ./target/release/PassthroughFS --mountpoint /mnt/passthrough --target /real/target --mapping_file filemapping.json
   ```
* Replace `/mnt/passthrough` with your desired mount directory.
* Replace `/real/target` with the directory to mirror.
* Replace `filemapping.json` with your configuration file path.
3. Access your virtual filesystem:
   ```bash
    ls /mnt/passthrough
   ```
4. Unmount the filesystem:
   ```bash
    fusermount -u /mnt/passthrough
   ```

## Development

### Running Tests
Run the included test suite to verify functionality:
   ```bash
   cargo test
   ```
   
### Debugging
Enable debug-level logs for detailed output:
   ```bash
   RUST_LOG=debug ./target/debug/PassthroughFS --mountpoint /mnt/passthrough --target /real/target --mapping_file filemapping.json
   ```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch: git checkout -b feature-name.
3. Commit your changes: git commit -m "Description of changes".
4. Push to your fork: git push origin feature-name.
5. Open a pull request.

## License
This project is licensed under the following terms:
1. Apache License, Version 2.0
2. GNU General Public License, Version 3

## Acknowledgments
* FUSE: Foundation for the filesystem integration.
* The Rust community for their tools and libraries.
* OpenAI's ChatGPT
