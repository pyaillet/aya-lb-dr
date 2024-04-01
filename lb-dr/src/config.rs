use std::net::Ipv4Addr;
use mac_address::MacAddress;
use serde::Deserialize;

/// This is what we're going to decode into. Each field is optional, meaning
/// that it doesn't have to be present in TOML.
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct Config {
    pub servers: Option<Vec<ServerConfig>>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct ServerConfig {
    pub ip: Ipv4Addr,
    pub backends: Vec<MacAddress>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_loads() {

        let expected = Config {
            servers: Some(vec![
                ServerConfig {
                    ip: Ipv4Addr::new(192, 168, 31, 50),
                    backends: vec![
                        MacAddress::new([0x30, 0x33, 0x11, 0x11, 0x11, 0x11]),
                        MacAddress::new([0x30, 0x33, 0x22, 0x22, 0x22, 0x22]),
                    ],
                }
            ])
        };
        let toml_str = r#"
        [[servers]]
        ip = "192.168.31.50"
        backends = ["30:33:11:11:11:11", "30:33:22:22:22:22"]
    "#;

    let actual: Config = toml::from_str(toml_str).unwrap();

    assert_eq!(expected, actual);
    println!("{:#?}", actual);
    }
}
