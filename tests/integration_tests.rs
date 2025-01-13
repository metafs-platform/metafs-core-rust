use std::error::Error;
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{FileType, Mode, CWD};
use tempfile::tempdir;
use tokio::fs::File;
use tokio::sync::Barrier;
use tokio::{io, task};
use uuid::Uuid;

use metafs_core_rust::named_pipe::{
    // Adjust to your actual crate name and module structure
    PipeTransport,
    ProtocolHandler,
    TaskManager,
};

#[tokio::test]
async fn test_protocol_handler_with_real_fifo() -> Result<(), Box<dyn Error>> {
    // Create a temporary directory for test FIFOs
    let temp_dir = tempdir()?;
    let inbound_path = temp_dir.path().join("inbound_fifo");
    let outbound_path = temp_dir.path().join("outbound_fifo");

    // Create the FIFOs using rustix
    eprintln!("Creating inbound_fifo: {}", inbound_path.display());
    create_fifo(&inbound_path)?;
    eprintln!("Creating outbound_fifo: {}", outbound_path.display());
    create_fifo(&outbound_path)?;
    eprintln!("Creating fisos done");

    // Use a barrier to synchronize FIFO opening
    let barrier = Arc::new(Barrier::new(2));

    // Spawn task to open the reader
    let reader_barrier = barrier.clone();
    let reader_task = task::spawn(async move {
        reader_barrier.wait().await; // Wait until writer is ready
        eprintln!(
            "Opening inbound_fifo for reading: {}",
            inbound_path.display()
        );
        let inbound_file = File::open(&inbound_path).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound_file)
    });

    // Spawn task to open the writer
    let writer_barrier = barrier.clone();
    let writer_task = task::spawn(async move {
        writer_barrier.wait().await; // Wait until reader is ready
        eprintln!(
            "Opening outbound_fifo for writing: {}",
            outbound_path.display()
        );
        let outbound_file = File::create(&outbound_path).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(outbound_file)
    });

    // Wait for both tasks to complete
    let inbound_file = match reader_task.await {
        Ok(Ok(file)) => file,
        Ok(Err(e)) => {
            eprintln!("Reader task failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Reader task failed"));
        }
        Err(e) => {
            eprintln!("Reader task panicked: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Reader task panicked"));
        }
    };

    let outbound_file = match writer_task.await {
        Ok(Ok(file)) => file,
        Ok(Err(e)) => {
            eprintln!("Writer task failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Writer task failed"));
        }
        Err(e) => {
            eprintln!("Writer task panicked: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Writer task panicked"));
        }
    };
    eprintln!("Both FIFOs are open!");

    eprintln!("Getting PipeTransport");
    let transport = PipeTransport::new(
        inbound_path.to_string_lossy().to_string(),
        outbound_path.to_string_lossy().to_string(),
    );

    eprintln!("Getting ProtocolHandler");
    let mut handler = ProtocolHandler::new(transport);

    let send_payload = b"Hello, World!";
    eprintln!("Sending: {:?}", send_payload);
    handler.send(send_payload).await?;
    eprintln!("Sent");

    // Simulate reading from another process:
    // We'll open the inbound FIFO for reading from a separate "server" perspective
    // and the outbound FIFO for writing back a response.

    // Because this is a test in one process, we need non-blocking behavior.
    // Named pipes block until both ends are open. We have them open above.
    // We can just open them again from the "server" side.

    let outbound_for_read = File::open(&outbound_path).await?;
    let inbound_for_write = File::create(&inbound_path).await?;

    // Read from outbound_for_read the message
    let mut out_std = outbound_for_read.into_std().await;
    let mut length_buf = [0u8; 4];
    out_std.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf) as usize;
    let mut recv_payload = vec![0u8; length];
    out_std.read_exact(&mut recv_payload)?;
    assert_eq!(&recv_payload, send_payload);

    // Now write a response back
    let response = b"Hello Back!";
    let resp_len = response.len() as u32;
    let mut resp_message = resp_len.to_be_bytes().to_vec();
    resp_message.extend_from_slice(response);

    let mut in_std = inbound_for_write.into_std().await;
    in_std.write_all(&resp_message)?;
    in_std.flush()?;

    let received = handler.receive().await?;
    assert_eq!(received, response);

    Ok(())
}

//#[tokio::test]
async fn test_task_manager_with_real_fifo() -> Result<(), Box<dyn Error>> {
    let temp_dir = tempdir()?;
    let inbound_path = temp_dir.path().join("inbound_fifo_2");
    let outbound_path = temp_dir.path().join("outbound_fifo_2");

    create_fifo(&inbound_path)?;
    create_fifo(&outbound_path)?;

    // Now open them with async File
    eprintln!("Temp dir: {}", temp_dir.path().display());
    eprintln!("Opening inbound_fifo2");
    let inbound_file = File::open(&inbound_path).await?;
    eprintln!("Opening outbound_fifo2");
    let outbound_file = File::create(&outbound_path).await?;

    let transport = PipeTransport::new(
        inbound_path.to_string_lossy().to_string(),
        outbound_path.to_string_lossy().to_string(),
    );

    let mut handler = ProtocolHandler::new(transport);

    let (tm, tx) = TaskManager::new();
    let task_manager = tm.start().await;

    let request_payload = b"Test Request".to_vec();

    // Send request
    let response_future = task_manager.send_request(&mut handler, request_payload.clone());

    // Simulate the "server" side: open the FIFOs again for reading/writing
    let outbound_for_read = File::open(&outbound_path).await?;
    let inbound_for_write = File::create(&inbound_path).await?;

    let mut out_std = outbound_for_read.into_std().await;

    // Read the request: first 4 bytes for length
    let mut length_buf = [0u8; 4];
    out_std.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf) as usize;

    let mut req_buf = vec![0u8; length];
    out_std.read_exact(&mut req_buf)?;

    let (uuid_bytes, req_payload_read) = req_buf.split_at(16);
    let received_uuid = Uuid::from_slice(uuid_bytes)?;
    assert_eq!(req_payload_read, request_payload.as_slice());

    // Respond
    let response_payload = b"Test Response";
    let mut resp_data = received_uuid.as_bytes().to_vec();
    resp_data.extend(response_payload);

    let resp_len = resp_data.len() as u32;
    let mut resp_message = resp_len.to_be_bytes().to_vec();
    resp_message.extend_from_slice(&resp_data);

    let mut in_std = inbound_for_write.into_std().await;
    in_std.write_all(&resp_message)?;
    in_std.flush()?;

    let result = response_future.await?;
    assert_eq!(result, response_payload);

    task_manager.shutdown().await.expect("Wont shut down");

    Ok(())
}

// Helper function to create FIFO
fn create_fifo(path: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid path: {}", e),
        )
    })?;

    let mode = Mode::from_bits(0o644).unwrap_or(Mode::empty());
    rustix::fs::mknodat(CWD, &c_path, FileType::Fifo, mode, 0)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}
