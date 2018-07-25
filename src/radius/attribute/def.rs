use std::str::FromStr;

use super::atype::RadiusAttributeType;

/// RADIUS attribute definition
#[derive(Clone)]
pub struct RadiusAttributeDef {
    name: String,
    code: u8,
    atype: RadiusAttributeType,
}

impl RadiusAttributeDef {
    /// retrieve attribute name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// retrieve attribute code
    pub fn get_code(&self) -> u8 {
        self.code
    }
}

impl FromStr for RadiusAttributeDef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 4 {
            return Err(format!("Malformed attribute row: {}", s));
        }
        if parts[0] != "ATTRIBUTE" {
            return Err(format!("Not an attribute row: {}", s));
        }

        Ok(RadiusAttributeDef {
            name: parts[1].to_owned(),
            code: parts[2].parse::<u8>().map_err(|e| format!("Malformed attriute code: {:?}", e))?,
            atype: RadiusAttributeType::from_str(parts[3])?,
        })
    }
}
