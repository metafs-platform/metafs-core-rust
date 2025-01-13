use crate::proto_bridge::generated::ReplyLink;

use prost::Message;

#[allow(dead_code)]
pub async fn send_reply_link(link: String) -> Result<(), Box<dyn std::error::Error>> {
    let reply = ReplyLink { link };
    let mut buf = Vec::new();
    Message::encode(&reply, &mut buf)?;

    // Example: Send `buf` over a named pipe or socket
    tokio::fs::write("/path/to/named_pipe", buf).await?;

    Ok(())
}
