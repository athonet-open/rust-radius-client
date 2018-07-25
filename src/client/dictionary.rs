use std::str::FromStr;

use super::{RadiusCode, RadiusAttribute, RadiusAttributeDef, RadiusData};

#[allow(dead_code)]
pub const DEFAULT_DICTIONARY: &'static str = r"
ATTRIBUTE   User-Name       1   string
ATTRIBUTE   User-Password       2   string
ATTRIBUTE   CHAP-Password       3   octets
ATTRIBUTE   NAS-IP-Address      4   ipaddr
ATTRIBUTE   NAS-Port        5   integer
ATTRIBUTE   Service-Type        6   integer
ATTRIBUTE   Framed-Protocol     7   integer
ATTRIBUTE   Framed-IP-Address   8   ipaddr
ATTRIBUTE   Framed-IP-Netmask   9   ipaddr
ATTRIBUTE   Framed-Routing      10  integer
ATTRIBUTE   Filter-Id       11  string
ATTRIBUTE   Framed-MTU      12  integer
ATTRIBUTE   Framed-Compression  13  integer
ATTRIBUTE   Login-IP-Host       14  ipaddr
ATTRIBUTE   Login-Service       15  integer
ATTRIBUTE   Login-TCP-Port      16  integer
ATTRIBUTE   Reply-Message       18  string
ATTRIBUTE   Callback-Number     19  string
ATTRIBUTE   Callback-Id     20  string
ATTRIBUTE   Framed-Route        22  string
ATTRIBUTE   Framed-IPX-Network  23  ipaddr
ATTRIBUTE   State           24  octets
ATTRIBUTE   Class           25  octets
ATTRIBUTE   Vendor-Specific     26  octets
ATTRIBUTE   Session-Timeout     27  integer
ATTRIBUTE   Idle-Timeout        28  integer
ATTRIBUTE   Termination-Action  29  integer
ATTRIBUTE   Called-Station-Id   30  string
ATTRIBUTE   Calling-Station-Id  31  string
ATTRIBUTE   NAS-Identifier      32  string
ATTRIBUTE   Proxy-State     33  octets
ATTRIBUTE   Login-LAT-Service   34  string
ATTRIBUTE   Login-LAT-Node      35  string
ATTRIBUTE   Login-LAT-Group     36  octets
ATTRIBUTE   Framed-AppleTalk-Link   37  integer
ATTRIBUTE   Framed-AppleTalk-Network 38 integer
ATTRIBUTE   Framed-AppleTalk-Zone   39  string

ATTRIBUTE    Acct-Status-Type       40    integer
ATTRIBUTE    Acct-Delay-Time        41    integer
ATTRIBUTE    Acct-Input-Octets      42    integer
ATTRIBUTE    Acct-Output-Octets     43    integer
ATTRIBUTE    Acct-Session-Id        44    string
ATTRIBUTE    Acct-Authentic         45    integer
ATTRIBUTE    Acct-Session-Time      46    integer
ATTRIBUTE    Acct-Input-Packets     47    integer
ATTRIBUTE    Acct-Output-Packets    48    integer
ATTRIBUTE    Acct-Terminate-Cause   49    integer
ATTRIBUTE    Acct-Multi-Session-Id  50    string
ATTRIBUTE    Acct-Link-Count        51    integer
ATTRIBUTE    Acct-Input-Gigawords   52    integer
ATTRIBUTE    Acct-Output-Gigawords  53    integer
ATTRIBUTE    Event-Timestamp        55    date

ATTRIBUTE    CHAP-Challenge          60   string
ATTRIBUTE    NAS-Port-Type           61   integer
ATTRIBUTE    Port-Limit              62   integer
ATTRIBUTE    Login-LAT-Port          63   integer

ATTRIBUTE    Acct-Tunnel-Connection  68   string

ATTRIBUTE    ARAP-Password           70   string
ATTRIBUTE    ARAP-Features           71   string
ATTRIBUTE    ARAP-Zone-Access        72   integer
ATTRIBUTE    ARAP-Security           73   integer
ATTRIBUTE    ARAP-Security-Data      74   string
ATTRIBUTE    Password-Retry          75   integer
ATTRIBUTE    Prompt                  76   integer
ATTRIBUTE    Connect-Info            77   string
ATTRIBUTE    Configuration-Token     78   string
ATTRIBUTE    EAP-Message             79   string
ATTRIBUTE    Message-Authenticator   80   octets
ATTRIBUTE    ARAP-Challenge-Response 84   string
ATTRIBUTE    Acct-Interim-Interval   85   integer
ATTRIBUTE    NAS-Port-Id             87   string
ATTRIBUTE    Framed-Pool             88   string
ATTRIBUTE    NAS-IPv6-Address        95   octets
ATTRIBUTE    Framed-Interface-Id     96   octets
ATTRIBUTE    Framed-IPv6-Prefix      97   octets
ATTRIBUTE    Login-IPv6-Host         98   octets
ATTRIBUTE    Framed-IPv6-Route       99   string
ATTRIBUTE    Framed-IPv6-Pool        100  string

ATTRIBUTE    Digest-Response        206   string
ATTRIBUTE    Digest-Attributes      207   octets
";

/// Dictionary struct
/// Actually manager only attributes rows, limited to 255
pub struct Dictionary {
    attributes: Vec<RadiusAttributeDef>
}

impl Dictionary {
    /// Creates a RadiusAttribute element starting from Dictionary's attribute name
    pub fn create_attribute_by_name(&self, name: &str, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        for def in self.attributes.iter() {
            if def.get_name() == name {
                return Ok(RadiusAttribute::new(def.clone(), value));
            }
        }

        Err(format!("Unrecognized attribute name: {}", name))
    }

    /// Creates a RadiusAttribute element starting from Dictionary's attribute code
    pub fn create_attribute_by_code(&self, code: u8, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        for def in self.attributes.iter() {
            if def.get_code() == code {
                return Ok(RadiusAttribute::new(def.clone(), value));
            }
        }

        Err(format!("Unrecognized attribute code: {}", code))
    }

    /// converts a byte array into a RadiusData element
    pub fn from_bytes(&self, data: &[u8]) -> Result<RadiusData, String> {
        let mut attributes = Vec::new();
        let mut i = 20;
        while i < data.len() {
            let size = data[i + 1] as usize;
            attributes.push(self.create_attribute_by_code(data[i], data[(i + 2)..(i + size)].to_vec())?);
            i += size;
        }

        Ok(RadiusData::new(RadiusCode::from_u8(data[0])?, Some(data[1]), Some(data[4..20].to_vec()), Some(attributes)))
    }
}

impl FromStr for Dictionary {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Dictionary {
            attributes: Vec::new(),
        };

        for l in s.lines() {
            if l.starts_with("ATTRIBUTE") {
                res.attributes.push(RadiusAttributeDef::from_str(l)?);
            }
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{Dictionary, DEFAULT_DICTIONARY};
    use std::str::FromStr;

    #[test]
    fn to_bytes() {
        let d = Dictionary::from_str(DEFAULT_DICTIONARY).unwrap();

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

        let data = d.from_bytes(&example).unwrap();
        assert_eq!(example.to_vec(), data.get_bytes());
    }
}
