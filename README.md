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
      "mappings": [
        {
          "path": "/example.txt",
          "target": "/real/target/example.txt",
          "permissions": {
            "owner": 1000,
            "group": 1000,
            "mode": 420
          }
        },
        {
          "path": "/readonly.txt",
          "target": "/real/target/readonly.txt",
          "permissions": {
            "owner": 1000,
            "group": 1000,
            "mode": 292
          }
        },
        {
          "path": "/unrestricted-folder",
          "target": "/real/target/unrestricted-folder"
        }
      ]
    }
```
### Fields
* `path`: The virtual path in the mounted filesystem.
* `target`: The corresponding actual path in the target directory.
* `permissions`: (Optional) Custom permissions for the virtual file.

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

Please Note: If you choose to use this software under the Apache License, Version 2.0, and any provision of that license is determined to be invalid or unenforceable in a jurisdiction (including but not limited to the patent clause), this software will instead be licensed under the terms of the GNU General Public License, Version 3 or later, for that jurisdiction.

## Acknowledgments
* FUSE: Foundation for the filesystem integration.
* The Rust community for their tools and libraries.
* OpenAI's ChatGPT
