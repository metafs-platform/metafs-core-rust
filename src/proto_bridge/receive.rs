use crate::proto_bridge::generated::LinkResponse;

use prost::Message;

#[allow(dead_code)]
pub async fn receive_reply_link() -> Result<LinkResponse, Box<dyn std::error::Error>> {
    let buf = tokio::fs::read("/path/to/named_pipe").await?;
    let reply = LinkResponse::decode(&*buf)?;

    Ok(reply)
}
