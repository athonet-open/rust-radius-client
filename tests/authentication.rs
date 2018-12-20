
use radius_client::client::Client;
use radius_client::client::dictionary::{Dictionary, DEFAULT_DICTIONARY};
use radius_client::radius::RadiusCode;
use std::str::FromStr;

#[test]
fn authentication() {
    // test with https://hub.docker.com/r/marcelmaatkamp/freeradius/
    let d = Dictionary::from_str(DEFAULT_DICTIONARY).unwrap();
    let c = Client::factory("172.25.0.100", 1812, 1813, 3799, "SECRET", d).unwrap();
    let p = c.get_auth_packet("testing", "password", None, None, Some(vec![
        c.create_attribute_by_name("NAS-IP-Address", vec![172, 25, 0, 2]).unwrap(),
        c.create_attribute_by_name("NAS-Port", vec![0]).unwrap(),
    ])).unwrap();
    let r = c.send_packet(&p).unwrap();
    assert!(r.get_code() == &RadiusCode::AccessAccept);
}
