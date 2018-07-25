/// RADIUS message types
#[derive(Clone, PartialEq)]
pub enum RadiusCode {
    /// 1 = Access-Request
    AccessRequest,
    /// 2 = Access-Accept
    AccessAccept,
    /// 3 = Access-Reject
    AccessReject,
    /// 4 = Accounting-Request
    AccountingRequest,
    /// 5 = Accounting-Response
    AccountingResponse,
    /// 11 = Access-Challenge
    AccessChallenge,
    /// 12 = Status-Server (experimental)
    StatusServer,
    /// 13 = Status-Client (experimental)
    StatusClient,
    /// 255 = reserved
    Reserved,
}

impl RadiusCode {
    /// converts from byte representation
    pub fn from_u8(i: u8) -> Result<RadiusCode, String> {
        match i {
            1u8 => Ok(RadiusCode::AccessRequest),
            2u8 => Ok(RadiusCode::AccessAccept),
            3u8 => Ok(RadiusCode::AccessReject),
            4u8 => Ok(RadiusCode::AccountingRequest),
            5u8 => Ok(RadiusCode::AccountingResponse),
            11u8 => Ok(RadiusCode::AccessChallenge),
            12u8 => Ok(RadiusCode::StatusServer),
            13u8 => Ok(RadiusCode::StatusClient),
            255u8 => Ok(RadiusCode::Reserved),
            _ => Err(format!("Unknown RadiusCode {}", i)),
        }
    }

    /// converts into byte representation
    pub fn to_u8(&self) -> u8 {
        match self {
            RadiusCode::AccessRequest => 1u8,
            RadiusCode::AccessAccept => 2u8,
            RadiusCode::AccessReject => 3u8,
            RadiusCode::AccountingRequest => 4u8,
            RadiusCode::AccountingResponse => 5u8,
            RadiusCode::AccessChallenge => 11u8,
            RadiusCode::StatusServer => 12u8,
            RadiusCode::StatusClient => 13u8,
            RadiusCode::Reserved => 255u8,
        }
    }
}
