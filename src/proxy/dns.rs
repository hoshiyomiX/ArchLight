use anyhow::Result;
use worker::*;

/// Perform DNS over HTTPS (DoH) query
/// 
/// # Arguments
/// * `req_wireformat` - DNS query in wire format
/// 
/// # Returns
/// * `Result<Vec<u8>>` - DNS response in wire format
pub async fn doh(req_wireformat: &[u8]) -> Result<Vec<u8>> {
    let doh_url = "https://1.1.1.1/dns-query";
    
    console_log!("Making DoH request to {}", doh_url);
    
    let mut headers = Headers::new();
    headers.set("Content-Type", "application/dns-message")?;
    headers.set("Accept", "application/dns-message")?;
    
    let request = Request::new_with_init(
        doh_url,
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(req_wireformat.to_vec().into()))
    )?;
    
    let mut response = Fetch::Request(request).send().await?;
    
    if response.status_code() != 200 {
        return Err(anyhow::anyhow!(
            "DoH request failed with status: {}",
            response.status_code()
        ));
    }
    
    let response_bytes = response.bytes().await?;
    
    console_log!("DoH response received: {} bytes", response_bytes.len());
    
    Ok(response_bytes.to_vec())
}

/// Alternative DoH function with configurable DNS server
pub async fn doh_with_server(req_wireformat: &[u8], server_url: &str) -> Result<Vec<u8>> {
    console_log!("Making DoH request to {}", server_url);
    
    let mut headers = Headers::new();
    headers.set("Content-Type", "application/dns-message")?;
    headers.set("Accept", "application/dns-message")?;
    
    let request = Request::new_with_init(
        server_url,
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(req_wireformat.to_vec().into()))
    )?;
    
    let mut response = Fetch::Request(request).send().await?;
    
    if response.status_code() != 200 {
        return Err(anyhow::anyhow!(
            "DoH request to {} failed with status: {}",
            server_url,
            response.status_code()
        ));
    }
    
    let response_bytes = response.bytes().await?;
    
    console_log!("DoH response from {}: {} bytes", server_url, response_bytes.len());
    
    Ok(response_bytes.to_vec())
}

/// Fallback DoH function that tries multiple DNS servers
pub async fn doh_with_fallback(req_wireformat: &[u8]) -> Result<Vec<u8>> {
    let servers = [
        "https://1.1.1.1/dns-query",      // Cloudflare
        "https://8.8.8.8/dns-query",      // Google
        "https://9.9.9.9/dns-query",      // Quad9
    ];
    
    for (index, server) in servers.iter().enumerate() {
        match doh_with_server(req_wireformat, server).await {
            Ok(response) => {
                console_log!("DoH request succeeded using server: {}", server);
                return Ok(response);
            }
            Err(e) => {
                console_error!("DoH request to {} failed: {}", server, e);
                if index == servers.len() - 1 {
                    return Err(anyhow::anyhow!("All DoH servers failed"));
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("No DoH servers available"))
}
