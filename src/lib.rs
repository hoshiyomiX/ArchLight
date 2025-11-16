mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^.+-\d+$").expect("Invalid PROXYIP_PATTERN regex")
});
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Z]{2})").expect("Invalid PROXYKV_PATTERN regex")
});

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .and_then(|x| Uuid::parse_str(&x.to_string()).map_err(|_| Error::RustError("Invalid UUID".to_string())))?;
    
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x| x.to_string()).unwrap_or_default();
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x| x.to_string()).unwrap_or_default();
    let link_page_url = env.var("LINK_PAGE_URL").map(|x| x.to_string()).unwrap_or_default();
    let converter_page_url = env.var("CONVERTER_PAGE_URL").map(|x| x.to_string()).unwrap_or_default();
    let checker_page_url = env.var("CHECKER_PAGE_URL").map(|x| x.to_string()).unwrap_or_default();

    let config = Config { 
        uuid, 
        host: host.clone(), 
        proxy_addr: host, 
        proxy_port: 443, 
        main_page_url, 
        sub_page_url,
        link_page_url,
        converter_page_url,
        checker_page_url
    };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on_async("/link", link)
        .on_async("/converter", converter)
        .on_async("/checker", checker)
        .on_async("/:proxyip", tunnel)
        .on_async("/Geo-Project/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let url = Url::parse(&url).map_err(|e| Error::RustError(format!("Invalid URL: {}", e)))?;
    let req = Fetch::Url(url);
    let mut res = req.send().await?;
    let text = res.text().await?;
    Response::from_html(text)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url.clone()).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url.clone()).await
}

async fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.link_page_url.clone()).await
}

async fn converter(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.converter_page_url.clone()).await
}

async fn checker(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.checker_page_url.clone()).await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap().to_string();
    
    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        
        let mut rand_buf = [0u8; 2];
        getrandom::getrandom(&mut rand_buf)
            .map_err(|e| Error::RustError(format!("Random generation failed: {}", e)))?;

        if proxy_kv_str.is_empty() {
            console_log!("getting proxy kv from github...");
            let github_url = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
            let req = Fetch::Url(Url::parse(github_url)?);
            let mut res = req.send().await?;
            
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?.to_string();
                kv.put("proxy_kv", &proxy_kv_str)?
                    .expiration_ttl(60 * 60 * 24)
                    .execute()
                    .await?;
            } else {
                return Err(Error::RustError(format!("Failed to fetch proxy KV: HTTP {}", res.status_code())));
            }
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)
            .map_err(|e| Error::RustError(format!("Failed to parse proxy KV JSON: {}", e)))?;

        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        let proxy_key = &kvid_list[kv_index];
        
        if let Some(proxy_list) = proxy_kv.get(proxy_key) {
            let proxyip_index = (rand_buf[0] as usize) % proxy_list.len();
            proxyip = proxy_list[proxyip_index].clone().replace(":", "-");
        }
    }

    if PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse::<u16>() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_log!("[tunnel]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }
}
