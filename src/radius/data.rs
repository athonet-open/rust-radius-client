use super::{RadiusCode, RadiusAttribute};

use rand::{thread_rng, Rng};

/// RADIUS packet
#[derive(Clone)]
pub struct RadiusData {
    code: RadiusCode,
    identifier: u8,
    authenticator: Vec<u8>,
    attributes: Vec<RadiusAttribute>,
}

impl RadiusData {
    /// constructor
    pub fn new(code: RadiusCode, identifier: Option<u8>, authenticator: Option<Vec<u8>>, attributes: Option<Vec<RadiusAttribute>>) -> RadiusData {
        RadiusData {
            code,
            identifier: identifier.or_else(|| Some(Self::create_id())).unwrap(),
            authenticator: authenticator.or_else(|| Some(Self::create_authenticator())).unwrap(),
            attributes: attributes.or_else(|| Some(Vec::new())).unwrap(),
        }
    }

    /// retrieves packet type
    pub fn get_code(&self) -> &RadiusCode {
        &self.code
    }

    /// retrieves packet identifier
    pub fn get_identifier(&self) -> u8 {
        self.identifier
    }

    /// retrieves packet authenticator
    pub fn get_authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    /// adds a RADIUS attribute
    pub fn add_attribute(&mut self, attr: RadiusAttribute) {
        self.attributes.push(attr);
    }

    /// retrieves a RADIUS attribute by name
    pub fn get_attribute_by_name(&self, name: &str) -> Option<&RadiusAttribute> {
        for i in 0..self.attributes.len() {
            if self.attributes[i].get_definition().get_name() == name {
                return self.attributes.get(i);
            }
        }
        None
    }

    /// retrieves a mutable reference to a RADIUS attribute by name
    pub fn get_attribute_by_name_mut(&mut self, name: &str) -> Option<&mut RadiusAttribute> {
        for i in 0..self.attributes.len() {
            if self.attributes[i].get_definition().get_name() == name {
                return self.attributes.get_mut(i);
            }
        }
        None
    }

    /// retrieves a RADIUS attribute by code
    pub fn get_attribute_by_code(&self, code: u8) -> Option<&RadiusAttribute> {
        for i in 0..self.attributes.len() {
            if self.attributes[i].get_definition().get_code() == code {
                return self.attributes.get(i);
            }
        }
        None
    }

    /// retrieves a mutable reference to a RADIUS attribute by code
    pub fn get_attribute_by_code_mut(&mut self, code: u8) -> Option<&mut RadiusAttribute> {
        for i in 0..self.attributes.len() {
            if self.attributes[i].get_definition().get_code() == code {
                return self.attributes.get_mut(i);
            }
        }
        None
    }

    fn create_id() -> u8 {
        thread_rng().gen_range(0u8, 255u8)
    }

    fn create_authenticator() -> Vec<u8> {
        let mut rng = thread_rng();
        let mut v = Vec::new();
        for _ in 0..16 {
            v.push(rng.gen_range(0u8, 255u8));
        }
        v
    }

    /// RADIUS packet byte array representation
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();

        let mut attributes = Vec::new();
        self.attributes.iter().for_each(|a| attributes.append(&mut a.get_bytes()));

        res.push(self.code.to_u8());
        res.push(self.identifier);

        res.append(&mut Self::from_u16_to_u8(((20 + attributes.len()) as u16).to_be()).to_vec());//big endian
        res.append(&mut self.authenticator.as_slice().to_vec());//clone
        res.append(&mut attributes);

        res
    }

    fn from_u16_to_u8(a: u16) -> [u8; 2] {
        [a as u8, (a >> 8) as u8]
    }
}
