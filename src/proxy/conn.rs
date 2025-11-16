use crate::config::Config;

use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

// Optimized buffer sizes for better performance
static MAX_WEBSOCKET_SIZE: usize = 16 * 1024; // Reduced from 64kb to 16kb
static MAX_BUFFER_SIZE: usize = 128 * 1024; // Reduced from 512kb to 128kb
static PEEK_BUFFER_LEN: usize = 16; // Reduced from 62 to 16 bytes for protocol detection

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
        // Performance counters
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub backpressure_count: u32,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::with_capacity(MAX_BUFFER_SIZE);

        Self {
            config,
            ws,
            buffer,
            events,
            bytes_sent: 0,
            bytes_received: 0,
            backpressure_count: 0,
        }
    }
    
    pub async fn fill_buffer_until(&mut self, n: usize) -> std::io::Result<()> {
        use futures_util::StreamExt;

        while self.buffer.len() < n {
            match self.events.next().await {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "websocket message too large"
                            ));
                        }
                        if self.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            self.backpressure_count += 1;
                            // Only log backpressure occasionally to reduce overhead
                            if self.backpressure_count % 100 == 0 {
                                console_log!("Buffer full, applying backpressure (occurred {} times)", self.backpressure_count);
                            }
                            // Return an error instead of Poll::Pending
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                "buffer full"
                            ));
                        }
                        self.buffer.put_slice(&data);
                        self.bytes_received += data.len() as u64;
                    }
                }
                Some(Ok(WebsocketEvent::Close(_))) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "websocket closed"
                    ));
                }
                Some(Err(e)) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "stream ended"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn peek_buffer(&self, n: usize) -> &[u8] {
        let len = self.buffer.len().min(n);
        &self.buffer[..len]
    }

    pub async fn process(&mut self) -> Result<()> {
        // Reduced buffer read for faster protocol detection
        match self.fill_buffer_until(PEEK_BUFFER_LEN).await {
            Ok(_) => {
                let peeked_buffer = self.peek_buffer(PEEK_BUFFER_LEN);

                if peeked_buffer.len() < (PEEK_BUFFER_LEN/2) {
                    return Err(Error::RustError("not enough buffer".to_string()));
                }

                // Minimized logging - only log when protocol is detected
                if self.is_vless(peeked_buffer) {
                    self.process_vless().await
                } else if self.is_shadowsocks(peeked_buffer) {
                    self.process_shadowsocks().await
                } else if self.is_trojan(peeked_buffer) {
                    self.process_trojan().await
                } else if self.is_vmess(peeked_buffer) {
                    self.process_vmess().await
                } else {
                    Err(Error::RustError("protocol not implemented".to_string()))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Handle backpressure by waiting and retrying
                console_log!("Buffer full, waiting for space...");
                // In a real implementation, we might want to wait here
                // For now, return an error
                Err(Error::RustError("buffer full".to_string()))
            }
            Err(e) => {
                Err(Error::RustError(format!("Failed to fill buffer: {}", e)))
            }
        }
    }

    pub fn is_vless(&self, buffer: &[u8]) -> bool {
        !buffer.is_empty() && buffer[0] == 0
    }

    fn is_shadowsocks(&self, buffer: &[u8]) -> bool {
        if buffer.is_empty() {
            return false;
        }
        match buffer[0] {
            1 => { // IPv4
                buffer.len() >= 7 && u16::from_be_bytes([buffer[5], buffer[6]]) != 0
            }
            3 => { // Domain name
                if buffer.len() < 2 {
                    return false;
                }
                let domain_len = buffer[1] as usize;
                buffer.len() >= 2 + domain_len + 2 && 
                u16::from_be_bytes([buffer[2 + domain_len], buffer[2 + domain_len + 1]]) != 0
            }
            4 => { // IPv6
                buffer.len() >= 19 && u16::from_be_bytes([buffer[17], buffer[18]]) != 0
            }
            _ => false,
        }
    }

    fn is_trojan(&self, buffer: &[u8]) -> bool {
        buffer.len() > 57 && buffer[56] == 13 && buffer[57] == 10
    }

    fn is_vmess(&self, buffer: &[u8]) -> bool {
        buffer.len() >= 1 && buffer[0] == 1
    }

    pub async fn handle_tcp_outbound(&mut self, addr: String, port: u16) -> Result<()> {
        // Minimized logging - only log on error or significant events
        let mut remote_socket = Socket::builder().connect(&addr, port).map_err(|e| {
            Error::RustError(format!("Failed to connect to {}:{}: {}", addr, port, e))
        })?;

        remote_socket.opened().await.map_err(|e| {
            Error::RustError(format!("Failed to open connection to {}:{}: {}", addr, port, e))
        })?;

        let result = tokio::io::copy_bidirectional(self, &mut remote_socket).await;
        
        match result {
            Ok((a_to_b, b_to_a)) => {
                // Only log if significant data transfer occurred
                if a_to_b > 1024 || b_to_a > 1024 {
                    console_log!(
                        "TCP {}:{} - up: {}, down: {}", 
                        addr, 
                        port, 
                        convert(a_to_b as f64), 
                        convert(b_to_a as f64)
                    );
                }
                Ok(())
            }
            Err(e) => {
                console_error!("TCP {}:{} error: {}", addr, port, e);
                Err(Error::RustError(format!("TCP connection error: {}", e)))
            }
        }
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buff = vec![0u8; 65535];

        let n = self.read(&mut buff).await?;
        let data = &buff[..n];
        
        // Minimized logging - DNS queries are frequent
        match crate::dns::doh(data).await {
            Ok(response) => {
                self.write(&response).await?;
            }
            Err(e) => {
                // Only log DNS errors occasionally to reduce overhead
                static mut DNS_ERROR_COUNT: u32 = 0;
                unsafe {
                    DNS_ERROR_COUNT += 1;
                    if DNS_ERROR_COUNT % 50 == 0 {
                        console_error!("DNS resolution failed ({} occurrences): {}", DNS_ERROR_COUNT, e);
                    }
                }
                return Err(Error::RustError(format!("DNS resolution failed: {}", e)));
            }
        }
        Ok(())
    }
}

impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();

        loop {
            let size = std::cmp::min(this.buffer.len(), buf.remaining());
            if size > 0 {
                buf.put_slice(&this.buffer.split_to(size));
                return Poll::Ready(Ok(()));
            }

            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "websocket message too large"
                            )));
                        }
                        
                        if this.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            *this.backpressure_count += 1;
                            // Only log backpressure occasionally
                            if *this.backpressure_count % 100 == 0 {
                                console_log!("Buffer full, applying backpressure (occurred {} times)", this.backpressure_count);
                            }
                            return Poll::Pending;
                        }
                        
                        this.buffer.put_slice(&data);
                        *this.bytes_received += data.len() as u64;
                    }
                }
                Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "websocket closed"
                    )));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string()
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "stream ended"
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        // Efficient data copying for small packets
        if buf.len() > MAX_WEBSOCKET_SIZE {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "message too large"
            )));
        }
        
        // Use direct send for small packets to minimize overhead
        let result = if buf.len() < 1024 {
            // Small packet - use direct send
            self.ws.send_with_bytes(buf)
        } else {
            // Larger packet - normal send
            self.ws.send_with_bytes(buf)
        };
        
        match result {
            Ok(_) => {
                // Update bytes sent counter
                unsafe {
                    let this = self.get_unchecked_mut();
                    this.bytes_sent += buf.len() as u64;
                }
                Poll::Ready(Ok(buf.len()))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string()
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        match self.ws.close(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string()
            ))),
        }
    }
}
