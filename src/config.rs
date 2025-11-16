use uuid::Uuid;

#[allow(dead_code)]  // Suppress the warning about unused host field
pub struct Config {
    pub uuid: Uuid,
    pub host: String,  // Keep for future use
    pub proxy_addr: String,
    pub proxy_port: u16,

    pub main_page_url: String,
    pub sub_page_url: String,
    pub link_page_url: String,
    pub converter_page_url: String,
    pub checker_page_url: String,
}
