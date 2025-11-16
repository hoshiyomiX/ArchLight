fn validate_dns_response(response: &[u8]) -> Result<()> {
    if response.len() < 12 {
        return Err(anyhow::anyhow!("DNS response too short"));
    }
    
    // Check if it's a valid DNS response (QR bit should be set)
    if (response[2] & 0x80) == 0 {
        return Err(anyhow::anyhow!("Invalid DNS response: QR bit not set"));
    }
    
    // Check if response code is NOERROR (0)
    let response_code = response[3] & 0x0F;
    if response_code != 0 {
        return Err(anyhow::anyhow!("DNS error: response code {}", response_code));
    }
    
    Ok(())
}

// Then in doh function:
let response_bytes = response.bytes().await?;
validate_dns_response(&response_bytes)?;
