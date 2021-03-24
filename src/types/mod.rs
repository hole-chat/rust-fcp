pub mod traits;
mod key;
use regex::Regex;
use traits::*;
pub use key::*;

#[derive(Debug, PartialEq)]
pub struct SSKKeypair {
    pub insert_uri: SSK,
    pub request_uri: SSK,
    pub identifier: String,
}

impl FcpParser<SSKKeypair> for SSKKeypair {
    fn parse(plain: &str) -> Option<SSKKeypair> {
        let reg = Regex::new(
            r"^SSKKeypair\nIdentifier=(.*)\nInsertURI=(.*)\nRequestURI=(.*)\nEndMessage",
        )
        .unwrap();
        println!("{:?}", reg);
        let res = reg.captures(plain).unwrap();
        let identifier = res[1].to_string();
        let insert_uri = SSK::parse(&res[2]).unwrap();
        let request_uri = SSK::parse(&res[3]).unwrap();
        return Some(SSKKeypair {
            insert_uri: insert_uri,
            request_uri: request_uri,
            identifier: identifier,
        });
    }
}

pub enum ReturnType {
    /// return the data directly to the client via an AllData message, once we have all of it. (For persistent requests, the client will get a DataFound message but must send a GetRequestStatus to ask for the AllData).
    Direct,
    ///  write the data to disk. If you download to disk, you have to do a TestDDARequest.
    None,
    /// don't return the data at all, just fetch it to the node and tell the client when we have finished.
    Disk,
}

impl FcpRequest for ReturnType {
    fn convert(&self) -> String {
        match self {
            ReturnType::Direct => "direct".to_string(),
            ReturnType::Disk => "disk".to_string(),
            ReturnType::None => "none".to_string(),
        }
    }
}
