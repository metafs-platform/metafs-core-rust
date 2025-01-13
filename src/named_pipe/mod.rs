use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::fs::FileType::Fifo;
use rustix::fs::{mknodat, Mode, CWD};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug)]
pub enum PipeTransportError {
    FatalReadError(String),
    ReadError(String),
    WriteError(String),
    IoError(std::io::Error),
}

impl Display for PipeTransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PipeTransportError::FatalReadError(s) => write!(f, "Fatal read error: {}", s),
            PipeTransportError::ReadError(s) => write!(f, "Read error: {}", s),
            PipeTransportError::WriteError(s) => write!(f, "Write error: {}", s),
            PipeTransportError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl Error for PipeTransportError {}

impl From<io::Error> for PipeTransportError {
    fn from(e: io::Error) -> Self {
        PipeTransportError::IoError(e)
    }
}

impl From<PipeTransportError> for std::io::Error {
    fn from(error: PipeTransportError) -> Self {
        match error {
            PipeTransportError::IoError(io_err) => io_err,
            PipeTransportError::FatalReadError(msg)
            | PipeTransportError::ReadError(msg)
            | PipeTransportError::WriteError(msg) => {
                std::io::Error::new(std::io::ErrorKind::Other, msg)
            }
        }
    }
}

const READ_PIPE_RETRY_COUNT: usize = 10;
const READ_PIPE_RETRY_DELAY_MS: u64 = 1000;
const WRITE_PIPE_RETRY_COUNT: usize = 5;
const WRITE_PIPE_RETRY_DELAY_MS: u64 = 1000;
const READ_CHUNK_SIZE: usize = 4096;

pub struct PipeTransport {
    inbound_path: String,
    outbound_path: String,
    inbound_file: Option<File>,
    outbound_file: Option<File>,
    read_buffer: Vec<u8>,
}

impl PipeTransport {
    pub fn new(inbound_path: String, outbound_path: String) -> Self {
        PipeTransport {
            inbound_path,
            outbound_path,
            inbound_file: None,
            outbound_file: None,
            read_buffer: Vec::new(),
        }
    }

    pub async fn initialize(&mut self) -> Result<(), PipeTransportError> {
        self.inbound_file = Some(self.open_read_pipe().await?);
        self.outbound_file = Some(self.open_write_pipe().await?);
        info!(message = "PipeTransport initialized", inbound_path=?self.inbound_path, outbound_path=?self.outbound_path);
        Ok(())
    }

    async fn ensure_fifo_exists(&self, path: &str) -> Result<(), PipeTransportError> {
        if !Path::new(path).exists() {
            info!(message="FIFO does not exist, creating", path=?path);
            tokio::fs::create_dir_all(Path::new(path).parent().unwrap_or_else(|| Path::new(".")))
                .await
                .map_err(PipeTransportError::IoError)?;

            let c_path = CString::new(path).map_err(|e| {
                PipeTransportError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid path string: {}", e),
                ))
            })?;

            // Since we are using `FileType::Fifo`, we only need permission bits for Mode
            let mode = Mode::from_bits(0o644).unwrap_or(Mode::empty());

            // Use rustix to create a FIFO
            if let Err(e) = mknodat(CWD, &c_path, Fifo, mode, 0) {
                let msg = format!("Failed to create named pipe at {}: {}", path, e);
                error!(message="mknodat failed", path=?path, error=?e);
                return Err(PipeTransportError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    msg,
                )));
            }
        }
        Ok(())
    }

    async fn open_read_pipe(&self) -> Result<File, PipeTransportError> {
        self.ensure_fifo_exists(&self.inbound_path).await?;
        let file = OpenOptions::new()
            .read(true)
            .open(&self.inbound_path)
            .await
            .map_err(|e| {
                error!(error=?e, message="Failed to open inbound pipe");
                PipeTransportError::IoError(e)
            })?;
        info!(message="Successfully opened inbound pipe", path=?self.inbound_path);
        Ok(file)
    }

    async fn open_write_pipe(&self) -> Result<File, PipeTransportError> {
        eprintln!("ensure_fifo_exists: {}", self.outbound_path);
        self.ensure_fifo_exists(&self.outbound_path).await?;
        eprintln!("ensure_fifo_exists: ok");
        let file = OpenOptions::new()
            .write(true)
            .open(&self.outbound_path)
            .await
            .map_err(|e| {
                eprintln!("error: {}", e);
                error!(error=?e, message="Failed to open outbound pipe");
                PipeTransportError::IoError(e)
            })?;
        eprintln!("all open");
        info!(message="Successfully opened outbound pipe", path=?self.outbound_path);
        Ok(file)
    }

    async fn reconnect_inbound(&mut self) -> Result<(), PipeTransportError> {
        for attempt in 1..=READ_PIPE_RETRY_COUNT {
            match self.open_read_pipe().await {
                Ok(file) => {
                    info!(
                        message = "Successfully reconnected inbound pipe",
                        attempts = attempt
                    );
                    self.inbound_file = Some(file);
                    return Ok(());
                }
                Err(e) => {
                    warn!(error=?e, attempt=attempt, message="Failed to reconnect inbound pipe");
                    sleep(Duration::from_millis(READ_PIPE_RETRY_DELAY_MS)).await;
                }
            }
        }

        error!(message = "Exhausted inbound pipe reconnection attempts");
        Err(PipeTransportError::FatalReadError(
            "Cannot reconnect inbound pipe".into(),
        ))
    }

    async fn reconnect_outbound(&mut self) -> Result<(), PipeTransportError> {
        for attempt in 1..=WRITE_PIPE_RETRY_COUNT {
            eprintln!(
                "Attempting to reconnect outbound pipe (attempt {})",
                attempt
            );
            match self.open_write_pipe().await {
                Ok(file) => {
                    eprintln!("Successfully reconnected outbound pipe");
                    info!(
                        message = "Successfully reconnected outbound pipe",
                        attempts = attempt
                    );
                    self.outbound_file = Some(file);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("Unsuccessfully reconnected outbound pipe");
                    warn!(error=?e, attempt=attempt, message="Failed to reconnect outbound pipe");
                    sleep(Duration::from_millis(WRITE_PIPE_RETRY_DELAY_MS)).await;
                }
            }
        }

        error!(message = "Exhausted outbound pipe reconnection attempts");
        Err(PipeTransportError::WriteError(
            "Cannot reconnect outbound pipe".into(),
        ))
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>, PipeTransportError> {
        if self.read_buffer.is_empty() {
            self.fill_read_buffer().await?;
        }
        let data = self.read_buffer.split_off(0);
        Ok(data)
    }

    async fn fill_read_buffer(&mut self) -> Result<(), PipeTransportError> {
        if self.inbound_file.is_none() {
            self.reconnect_inbound().await?;
        }

        let file = self.inbound_file.as_mut().unwrap();
        let mut tmp_buf = vec![0u8; READ_CHUNK_SIZE];

        match file.read(&mut tmp_buf).await {
            Ok(0) => {
                warn!(message = "Inbound pipe EOF, attempting reconnect");
                self.reconnect_inbound().await?;
                let file = self.inbound_file.as_mut().unwrap();
                let read_bytes = file.read(&mut tmp_buf).await.map_err(|e| {
                    error!(error=?e, message="Error after inbound reconnection");
                    PipeTransportError::ReadError(format!("Error after reconnection: {}", e))
                })?;
                tmp_buf.truncate(read_bytes);
                self.read_buffer.extend(tmp_buf);
            }
            Ok(n) => {
                tmp_buf.truncate(n);
                self.read_buffer.extend(tmp_buf);
            }
            Err(e) => {
                error!(error=?e, message="Inbound read error");
                self.reconnect_inbound().await?;
                return Err(PipeTransportError::ReadError(format!(
                    "Inbound read error: {}",
                    e
                )));
            }
        }
        Ok(())
    }

    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<usize, PipeTransportError> {
        if self.outbound_file.is_none() {
            eprintln!("Outbound file is none");
            self.reconnect_outbound().await?;
            eprintln!("Reconnected to outbound file");
        }

        eprintln!("outbound file write_all");
        let result = self.outbound_file.as_mut().unwrap().write_all(data).await;
        if let Err(e) = result {
            warn!(error=?e, message="Outbound write failed, attempting reconnect");
            self.reconnect_outbound().await?;
            if let Err(e2) = self.outbound_file.as_mut().unwrap().write_all(data).await {
                error!(error=?e2, message="Outbound write still failing after reconnect");
                return Err(PipeTransportError::WriteError(format!(
                    "Failed to write after reconnect: {}",
                    e2
                )));
            }
        }
        Ok(data.len())
    }
}

pub struct ProtocolHandler {
    transport: PipeTransport,
}

impl ProtocolHandler {
    pub fn new(transport: PipeTransport) -> Self {
        Self { transport }
    }

    pub async fn initialize(&mut self) -> Result<(), PipeTransportError> {
        self.transport.initialize().await
    }

    pub async fn send(&mut self, payload: &[u8]) -> Result<(), PipeTransportError> {
        let size = payload.len() as u32;
        let mut message = Vec::with_capacity(4 + payload.len());
        message.extend_from_slice(&size.to_be_bytes());
        message.extend_from_slice(payload);
        eprintln!("write_chunk of size: {}", size);
        self.transport.write_chunk(&message).await?;
        eprintln!("write_chunk done");
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, PipeTransportError> {
        let mut buffer = Vec::new();
        while buffer.len() < 4 {
            let chunk = self.transport.read_chunk().await?;
            if chunk.is_empty() {
                return Err(PipeTransportError::ReadError(
                    "No data received when expecting message length".into(),
                ));
            }
            buffer.extend_from_slice(&chunk);
        }

        let mut size_bytes = [0u8; 4];
        size_bytes.copy_from_slice(&buffer[..4]);
        let payload_size = u32::from_be_bytes(size_bytes) as usize;
        buffer.drain(..4);

        while buffer.len() < payload_size {
            let chunk = self.transport.read_chunk().await?;
            if chunk.is_empty() {
                return Err(PipeTransportError::ReadError(
                    "EOF while reading message payload".into(),
                ));
            }
            buffer.extend_from_slice(&chunk);
        }

        let payload = buffer.split_off(0);
        Ok(payload)
    }
}

/// A simple trait for sending/receiving to abstract over ProtocolHandler
pub trait ProtocolSendReceive {
    fn send_payload<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    fn receive_payload<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>;
}

impl ProtocolSendReceive for ProtocolHandler {
    fn send_payload<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.send(payload)
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
        })
    }

    fn receive_payload<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            self.receive()
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
        })
    }
}

/// The TaskManager sets up request/response handling.
pub struct TaskManager {
    pending_tasks: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>>,
    receiver: mpsc::Receiver<(Uuid, Vec<u8>)>,
    // We keep the sender separate so we can return it to the caller
}

impl TaskManager {
    pub fn new() -> (Self, mpsc::Sender<(Uuid, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(100);
        (
            TaskManager {
                pending_tasks: Arc::new(Mutex::new(HashMap::new())),
                receiver: rx,
            },
            tx,
        )
    }

    /// Starts the background task that processes incoming responses.
    /// Consumes the TaskManager and returns a handle that can be used to send requests.
    pub async fn start(self) -> TaskManagerHandle {
        let pending = self.pending_tasks.clone();
        let mut rx = self.receiver;

        // Spawn the background task
        let handle = tokio::spawn(async move {
            while let Some((id, response)) = rx.recv().await {
                if let Some(sender) = pending.lock().unwrap().remove(&id) {
                    let _ = sender.send(response);
                }
            }
        });

        TaskManagerHandle {
            pending_tasks: self.pending_tasks,
            task_handle: handle,
        }
    }
}

/// After starting the TaskManager, we get this handle.
/// It provides a stable API for sending requests and managing the background task.
pub struct TaskManagerHandle {
    pending_tasks: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>>,
    task_handle: JoinHandle<()>,
}

impl TaskManagerHandle {
    /// Sends a request and awaits a response.
    /// `protocol` must implement `ProtocolSendReceive`.
    pub async fn send_request<P: ProtocolSendReceive + Send>(
        &self,
        protocol: &mut P,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();

        self.pending_tasks.lock().unwrap().insert(id, tx);

        // Prefix the payload with the correlation ID
        let mut message = id.as_bytes().to_vec();
        message.extend(payload);

        protocol.send_payload(&message).await?;

        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.pending_tasks.lock().unwrap().remove(&id);
                Err(Box::new(std::io::Error::new(
                    io::ErrorKind::Other,
                    "Response channel error",
                )))
            }
            Err(_) => {
                self.pending_tasks.lock().unwrap().remove(&id);
                Err(Box::new(std::io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Request timed out",
                )))
            }
        }
    }

    /// Optionally, you could provide a shutdown method if you modify the background task accordingly.
    /// For now, just dropping this handle doesn't stop the background task. If you'd like to stop it:
    /// - You could send a special message to terminate, or
    /// - Cancel the join handle.
    pub async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        self.task_handle.abort();
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
//     use uuid::Uuid;
//
//     // ----------------------------------
//     // Test for ProtocolHandler
//     // ----------------------------------
//     #[tokio::test]
//     async fn test_protocol_handler_send_receive() {
//         // Create a duplex pair
//         let (mut client_side, mut server_side) = duplex(64);
//
//         // Create a ProtocolHandler that uses the client_side as its transport
//         let transport = PipeTransport {
//             inbound_path: "inbound_mock".into(),
//             outbound_path: "outbound_mock".into(),
//             inbound_file: Some(tokio::fs::File::from_std(server_side.into_std().unwrap())),
//             outbound_file: None,
//             read_buffer: Vec::new(),
//         };
//
//         // For testing protocol handler alone, we can cheat:
//         // We want both inbound and outbound in the same transport.
//         // Let's just store the duplex again. In a real scenario,
//         // you'd have separate inbound and outbound files, but here we simulate full-duplex.
//         let (mut client2, mut server2) = duplex(64);
//         let mut handler = ProtocolHandler::new(PipeTransport {
//             inbound_path: "inbound_mock2".into(),
//             outbound_path: "outbound_mock2".into(),
//             inbound_file: Some(tokio::fs::File::from_std(client2.into_std().unwrap())),
//             outbound_file: Some(tokio::fs::File::from_std(server2.into_std().unwrap())),
//             read_buffer: Vec::new(),
//         });
//
//         // No need to call initialize since we manually assigned files.
//
//         // Send a message from the ProtocolHandler
//         let payload = b"Hello Protocol";
//         handler.send(payload).await.unwrap();
//
//         // Now read from the "server" side of the duplex to verify the message structure
//         // The message format is: [4-byte length][payload]
//         let mut length_buf = [0u8; 4];
//         let n = client_side.read_exact(&mut length_buf).await.unwrap();
//         assert_eq!(n, 4);
//         let length = u32::from_be_bytes(length_buf) as usize;
//
//         let mut recv_payload = vec![0u8; length];
//         client_side.read_exact(&mut recv_payload).await.unwrap();
//         assert_eq!(&recv_payload, payload);
//
//         // Now test receive:
//         // Write a response back on client_side
//         let response = b"Hello Back!";
//         let resp_len = response.len() as u32;
//         let mut resp_message = resp_len.to_be_bytes().to_vec();
//         resp_message.extend_from_slice(response);
//         client_side.write_all(&resp_message).await.unwrap();
//
//         let received = handler.receive().await.unwrap();
//         assert_eq!(received, response);
//     }
//
//     // ----------------------------------
//     // Test for TaskManager
//     // ----------------------------------
//     #[tokio::test]
//     async fn test_task_manager_request_response() {
//         let (mut client_side, mut server_side) = duplex(128);
//
//         // Create a ProtocolHandler for the client (TaskManager side)
//         let mut handler = ProtocolHandler::new(PipeTransport {
//             inbound_path: "inbound_mock".into(),
//             outbound_path: "outbound_mock".into(),
//             inbound_file: Some(tokio::fs::File::from_std(client_side.into_std().unwrap())),
//             outbound_file: Some(tokio::fs::File::from_std(server_side.into_std().unwrap())),
//             read_buffer: Vec::new(),
//         });
//
//         // Create the TaskManager
//         let (mut task_manager, response_sender) = TaskManager::new();
//
//         // Start the TaskManager in background
//         let mut task_manager_handle = tokio::spawn(async move {
//             task_manager.start().await;
//         });
//
//         // Create a fake "server" duplex to respond
//         let (mut client_side_req, mut server_side_req) = duplex(128);
//
//         // For simplicity, let's re-initialize handler with a fresh duplex:
//         // In a real test, you'd unify these streams carefully or abstract over them.
//         let mut handler = ProtocolHandler::new(PipeTransport {
//             inbound_path: "inbound_mock2".into(),
//             outbound_path: "outbound_mock2".into(),
//             inbound_file: Some(tokio::fs::File::from_std(client_side_req.into_std().unwrap())),
//             outbound_file: Some(tokio::fs::File::from_std(server_side_req.into_std().unwrap())),
//             read_buffer: Vec::new(),
//         });
//
//         // We'll simulate a request/response:
//         let request_payload = b"Test Request".to_vec();
//
//         // Send the request via TaskManager
//         // This will send a message with a UUID + payload via the ProtocolHandler
//         let response_future = task_manager.send_request(&mut handler, request_payload.clone());
//
//         // On the "server" side, we expect to receive: [16-byte UUID][payload]
//         // The server_side_req is the inbound side for the server.
//         let mut server_in = vec![0u8; 4 + 16 + request_payload.len()];
//
//         // First read size prefix (4 bytes)
//         let mut length_buf = [0u8; 4];
//         server_side_req.read_exact(&mut length_buf).await.unwrap();
//         let length = u32::from_be_bytes(length_buf) as usize;
//
//         // Now read the payload (UUID + request_payload)
//         let mut req_buf = vec![0u8; length];
//         server_side_req.read_exact(&mut req_buf).await.unwrap();
//
//         let (uuid_bytes, req_payload_read) = req_buf.split_at(16);
//         let received_uuid = Uuid::from_slice(uuid_bytes).unwrap();
//         assert_eq!(req_payload_read, request_payload.as_slice());
//
//         // Now respond:
//         // The server writes back a message with the same UUID as correlation
//         let response_payload = b"Test Response";
//         let mut resp_data = received_uuid.as_bytes().to_vec();
//         resp_data.extend(response_payload);
//
//         // Send the response
//         let resp_len = resp_data.len() as u32;
//         let mut resp_message = resp_len.to_be_bytes().to_vec();
//         resp_message.extend_from_slice(&resp_data);
//         server_side_req.write_all(&resp_message).await.unwrap();
//
//         // Await the response future on the client side
//         let result = response_future.await.unwrap();
//         assert_eq!(result, response_payload);
//
//         // Clean up the TaskManager background task
//         task_manager_handle.abort();
//     }
//
//
//     #[tokio::test]
//     async fn test_protocol_handler() {
//         init_tracing();
//
//         let (client, server) = duplex(64);
//
//         let mut transport = PipeTransport {
//             inbound_path: "inbound_fifo".into(),
//             outbound_path: "outbound_fifo".into(),
//             inbound_file: None,
//             outbound_file: None,
//             read_buffer: Vec::new(),
//         };
//
//         // For this test, just directly assign files from duplex streams for demonstration.
//         transport.inbound_file = Some(File::from_std(server.into_std().unwrap()));
//         transport.outbound_file = Some(File::from_std(client.into_std().unwrap()));
//
//         let mut handler = ProtocolHandler::new(transport);
//
//         let send_payload = b"Hello, World!";
//         handler.send(send_payload).await.unwrap();
//         let received = handler.receive().await.unwrap();
//         assert_eq!(received, send_payload);
//     }
// }
