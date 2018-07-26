# RADIUS client

This aims to be a full Rust RADIUS client<br />
Any contribution is appreciated

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
radius_client = { git = "https://github.com/athonet-open/rust-radius-client.git" }
```

Next, add this to your crate root (`src/lib.rs` or `src/main.rs`):

```rust
extern crate radius_client;
```

## Example

```rust
use radius_client::client::Client;
use radius_client::client::dictionary::{Dictionary, DEFAULT_DICTIONARY};
use radius_client::radius::RadiusCode;
use std::str::FromStr;

fn authentication() {
    // use with https://hub.docker.com/r/marcelmaatkamp/freeradius/
    let dictionary = Dictionary::from_str(DEFAULT_DICTIONARY).unwrap();
    let client = Client::new("172.25.0.100", 1812, 1813, 3799, "SECRET", dictionary).unwrap();
    let packet = client.get_auth_packet("testing", "password", None, None, Some(vec![
        client.create_attribute_by_name("NAS-IP-Address", vec![172, 25, 0, 1]).unwrap(),
        client.create_attribute_by_name("NAS-Port", vec![0]).unwrap(),
    ])).unwrap();
    let response = client.send_packet(packet).unwrap();
    assert!(response.get_code() == &RadiusCode::AccessAccept);
}
```
