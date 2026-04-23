//! Resolve `--listen` / `--port` the same way the hand-rolled pong CLIs did.

use std::net::{Ipv4Addr, SocketAddr};

/// Build the UDP bind address from optional `--listen ADDR:PORT` and `--port PORT`.
pub fn bind_addr(listen: Option<String>, port: Option<u16>) -> Result<SocketAddr, String> {
    match (listen, port) {
        (Some(l), _) => {
            if let Some((host, p_str)) = l.rsplit_once(':') {
                let port: u16 = p_str
                    .parse()
                    .map_err(|_| format!("invalid port in --listen: {p_str}"))?;
                format!("{host}:{port}")
                    .parse()
                    .map_err(|e| format!("invalid --listen: {e}"))
            } else {
                let pr: u16 = l
                    .parse()
                    .map_err(|_| format!("invalid port in --listen: {l}"))?;
                Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, pr)))
            }
        }
        (None, Some(p)) => Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, p))),
        (None, None) => "0.0.0.0:4433"
            .parse()
            .map_err(|e| format!("default bind: {e}")),
    }
}
