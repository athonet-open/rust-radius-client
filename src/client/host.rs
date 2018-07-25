use super::{Dictionary, RadiusCode, RadiusAttribute, RadiusData};

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::mac::Mac;
use crypto::hmac::Hmac;

/// Host management
pub struct Host {
    dict: Dictionary,
    authport: usize,
    accport: usize,
    // TODO: find out which operations goes on coaport
    _coaport: usize,
}

impl Host {
    pub fn new(authport: usize, accport: usize, coaport: usize, dict: Dictionary) -> Result<Host, String> {
        Ok(Host {
            dict: dict,
            authport: authport,
            accport: accport,
            _coaport: coaport,
        })
    }

    pub fn get_port(&self, code: &RadiusCode) -> usize {
        match code {
            &RadiusCode::AccessRequest => self.authport,
            //&RadiusCode::Co => self.coaport,
            _ => self.accport,
        }
    }

    pub fn create_attribute_by_name(&self, name: &str, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        self.dict.create_attribute_by_name(name, value)
    }

    pub fn create_attribute_by_code(&self, code: u8, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        self.dict.create_attribute_by_code(code, value)
    }

    /// generates an authentication request packet
    pub fn get_auth_packet(&self, username: &str, password: &str, secret: &[u8], identifier: Option<u8>, authenticator: Option<Vec<u8>>, attributes: Option<Vec<RadiusAttribute>>) -> Result<RadiusData, String> {
        let mut data = RadiusData::new(RadiusCode::AccessRequest, identifier, authenticator, attributes);

        data.add_attribute(self.dict.create_attribute_by_name("User-Name", username.as_bytes().to_vec())?);

        let pwd = self.crypt_password(password, data.get_authenticator(), secret);
        data.add_attribute(self.dict.create_attribute_by_name("User-Password", pwd)?);

        let temp = self.generate_hash(&data, secret)?;
        let add = match data.get_attribute_by_name_mut("Message-Authenticator") {
            Some(v) => {
                v.set_value(temp);
                None
            },
            None => Some(temp),
        };
        if add.is_some() {
            data.add_attribute(self.dict.create_attribute_by_name("Message-Authenticator", add.unwrap())?);
        }

        Ok(data)
    }

    fn crypt_password(&self, password: &str, authenticator: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut buf = password.as_bytes().to_vec();
        let l = buf.len() % 16;
        if l != 0 {
            buf.append(&mut vec![0u8; 16 - l]);
        }

        let mut result = Vec::new();
        let mut last = authenticator.to_vec();

        while buf.len() > 0 {
            let mut temp = secret.to_vec();
            temp.append(&mut last.to_vec());

            let mut md5 = Md5::new();
            md5.input(&temp);
            let mut hash = [0; 16];
            md5.result(&mut hash);

            for i in 0..16 {
                result.push(hash[i] ^ buf[i]);
            }

            last = result[(result.len() - 16)..].to_vec();
            buf = buf[16..].to_vec();
        }

        result
    }

    pub fn generate_hash(&self, data: &RadiusData, secret: &[u8]) -> Result<Vec<u8>, String> {
        //clone to avoid data modification
        let mut temp = data.clone();
        let add = match temp.get_attribute_by_name_mut("Message-Authenticator") {
            Some(a) => {
                a.set_value([0u8; 16].to_vec());
                false
            },
            None => true,
        };
        if add {
            temp.add_attribute(self.dict.create_attribute_by_name("Message-Authenticator", [0u8; 16].to_vec())?);
        }

        let mut hmac = Hmac::new(Md5::new(), secret);
        hmac.input(&temp.get_bytes());
        Ok(hmac.result().code().to_vec())
    }

    pub fn from_bytes(&self, data: &[u8]) -> Result<RadiusData, String> {
        self.dict.from_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::{Host, Dictionary};
    use client::dictionary::DEFAULT_DICTIONARY;
    use std::str::FromStr;

    #[test]
    fn to_bytes() {
        let example = [
            0x01, 0x68, 0x00, 0x4d, 0x8a, 0xa8, 0x1f, 0xc1,
            0x74, 0xc8, 0x63, 0x10, 0x21, 0x13, 0xf2, 0xe7,
            0x5b, 0xf4, 0x69, 0x61, 0x01, 0x09, 0x74, 0x65,
            0x73, 0x74, 0x69, 0x6e, 0x67, 0x02, 0x12, 0xdb,
            0x45, 0x98, 0x63, 0x4f, 0x11, 0x03, 0x24, 0x4a,
            0x4f, 0x9d, 0x8f, 0xa6, 0x02, 0x16, 0x46, 0x04,
            0x06, 0xac, 0x19, 0x00, 0x65, 0x05, 0x06, 0x00,
            0x00, 0x00, 0x00, 0x50, 0x12, 0x6f, 0x58, 0x0b,
            0x1f, 0x89, 0x5a, 0xec, 0xb9, 0x9b, 0x12, 0x46,
            0x11, 0xc5, 0x4c, 0xe3, 0x26
        ];

        let h = Host::new(1812, 1813, 3799, Dictionary::from_str(DEFAULT_DICTIONARY).unwrap()).unwrap();

        let data = h.from_bytes(&example).unwrap();
        assert_eq!(example.to_vec(), data.get_bytes());

        match data.get_attribute_by_name("Message-Authenticator") {
            Some(v) => assert_eq!(v.get_value().to_vec(), h.generate_hash(&data, "SECRET".as_bytes()).unwrap()),
            None => panic!("Message-Authenticator not found in message"),
        }
    }
}
