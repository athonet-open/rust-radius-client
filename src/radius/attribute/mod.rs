pub mod def;
pub mod atype;

use self::def::RadiusAttributeDef;

/// A simple association between a RADIUS attribute definition and byte array value
/// TODO: return typed value based on definition
#[derive(Clone)]
pub struct RadiusAttribute {
    definition: RadiusAttributeDef,
    value: Vec<u8>,
}

impl RadiusAttribute {
    /// constructor
    pub fn new(definition: RadiusAttributeDef, value: Vec<u8>) -> RadiusAttribute {
        RadiusAttribute {
            definition,
            value,
        }
    }

    /// retrieve attribute definition
    pub fn get_definition(&self) -> &RadiusAttributeDef {
        &self.definition
    }

    /// retrieve attribute value
    pub fn get_value(&self) -> &[u8] {
        &self.value
    }

    /// set attribute value
    pub fn set_value(&mut self, data: Vec<u8>) {
        self.value = data;
    }

    /// RADIUS attribute byte array representation
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.push(self.definition.get_code());
        res.push((2 + self.value.len()) as u8);
        res.append(&mut self.value.clone());
        res
    }
}
