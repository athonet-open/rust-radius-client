use std::str::FromStr;

#[derive(Clone)]
pub enum RadiusAttributeType {
    String,
    Integer,
    Octets,
    IpAddr,
    Date,
}

impl FromStr for RadiusAttributeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let temp: &str = &s.to_lowercase();
        match temp {
            "string" => Ok(RadiusAttributeType::String),
            "integer" => Ok(RadiusAttributeType::Integer),
            "octets" => Ok(RadiusAttributeType::Octets),
            "ipaddr" => Ok(RadiusAttributeType::IpAddr),
            "date" => Ok(RadiusAttributeType::Date),
            _ => Err(format!("Unrecognized Attribute type: {}", s)),
        }
    }
}
