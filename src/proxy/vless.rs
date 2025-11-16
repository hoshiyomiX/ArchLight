use super::ProxyStream;
use crate::common::{parse_addr, parse_port};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_vless(&mut self) -> Result<()> {
        // Read and validate version
        let version = self.read_u8().await?;
        if version != 0 {
            return Err(Error::RustError(format!("Invalid VLESS version: {}", version)));
        }
        
        // Read and validate UUID
        let mut user_id = [0u8; 16];
        self.read_exact(&mut user_id).await?;
        let received_uuid = Uuid::from_bytes(user_id);
        
        if received_uuid != self.config.uuid {
            return Err(Error::RustError("Invalid UUID".to_string()));
        }
        
        // Read protobuf (metadata) - currently unused but required by protocol
        let m_len = self.read_u8().await? as usize;
        if m_len > 0 {
            let mut protobuf = vec![0u8; m_len];
            self.read_exact(&mut protobuf).await?;
            // TODO: Parse protobuf if needed for advanced features
        }

        // Read instruction
        let network_type = self.read_u8().await?;
        let is_tcp = network_type == 1;

        // Read port and address
        let remote_port = parse_port(self).await?;
        let remote_addr = parse_addr(self).await?;

        console_log!("VLESS connection: {}:{} (TCP: {})", remote_addr, remote_port, is_tcp);

        if is_tcp {
            // Handle TCP connection
            self.handle_tcp_connection(remote_addr, remote_port).await?;
        } else {
            // Handle UDP connection
            self.handle_udp_connection(remote_addr, remote_port).await?;
        }

        Ok(())
    }

    async fn handle_tcp_connection(&mut self, addr: String, port: u16) -> Result<()> {
        console_log!("Establishing TCP connection to {}:{}", addr, port);
        
        // Send VLESS response header (2 zero bytes as per protocol)
        self.write(&[0u8; 2]).await?;
        self.flush().await?;

        // Handle the outbound TCP connection
        if let Err(e) = self.handle_tcp_outbound(addr, port).await {
            console_error!("TCP connection failed to {}:{} - {}", addr, port, e);
            return Err(e);
        }

        console_log!("TCP connection established to {}:{}", addr, port);
        Ok(())
    }

    async fn handle_udp_connection(&mut self, addr: String, port: u16) -> Result<()> {
        console_log!("Establishing UDP connection to {}:{}", addr, port);
        
        // Handle the outbound UDP connection
        if let Err(e) = self.handle_udp_outbound().await {
            console_error!("UDP connection failed to {}:{} - {}", addr, port, e);
            return Err(e);
        }

        console_log!("UDP connection established to {}:{}", addr, port);
        Ok(())
    }
}
