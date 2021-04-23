use crate::types::traits::FcpParser;
use regex::Regex;
use std::str::FromStr;
/*
  AllData
  Identifier=Request Number One
  DataLength=37261 // length of data
  StartupTime=1189683889
  CompletionTime=1189683889
  Metadata.ContentType=text/plain;charset=utf-8
  Data
  <37261 bytes of data>




AllData\n
Identifier=get1\n
CompletionTime=1619156374827\n
StartupTime=1619156374743\n
DataLength=33\n
Global=false\n
Metadata.ContentType=application/octet-stream\n
Data\n
hello\n Yeah kek ruururun\n\n\nKE^[u

 */

#[derive(Debug, PartialEq)]
pub struct AllData {
    pub identifier: String,
    pub startup_time: String,
    pub completion_time: String,
    pub data_length: usize,
    pub global: bool,
    pub metadata_content_type: String,
    pub data: String,
}

impl FcpParser<AllData> for AllData {
    fn parse(plain: &str) -> Option<AllData> {
        let reg = Regex::new(
            r"^AllData\nIdentifier=(.*)\nCompletionTime=(.*)\nStartupTime=(.*)\nDataLength=(.*)\nGlobal=(.*)\nMetadata\.ContentType=(.*)\nData\n((\n?.*)*)"
        )
        .unwrap();
        println!("{:?}", reg);
        let res = reg.captures(plain).unwrap();
        let identifier = res[1].to_string();
        // let completion_time = u32::from_str_radix(&res[2], 10).unwrap();
        // let startup_time = u32::from_str_radix(&res[3], 10).unwrap();
        let completion_time = res[2].to_string();
        let startup_time = res[3].to_string();
        let data_length = usize::from_str_radix(&res[4], 10).unwrap();
        let global = bool::from_str(&res[5]).unwrap();
        let metadata = res[6].to_string();
        let data = res[7].to_string();
        return Some(AllData {
            identifier: identifier,
            startup_time: startup_time,
            completion_time: completion_time,
            data_length: data_length,
            global: global,
            metadata_content_type: metadata,
            data: data,
        });
    }
}

#[test]
fn is_all_data_parsing() {
    assert_eq!(
        AllData::parse(
            "AllData\n\
         Identifier=get1\n\
         CompletionTime=1619156374827\n\
         StartupTime=1619156374743\n\
         DataLength=33\n\
         Global=false\n\
         Metadata.ContentType=application/octet-stream\n\
         Data\n\
         hello\n Yeah kek ruururun\n\n\nKE",
        )
        .unwrap(),
        AllData {
            identifier: "get1".to_string(),
            startup_time: "1619156374743".to_string(),
            completion_time: "1619156374827".to_string(),
            data_length: 33,
            global: false,
            metadata_content_type: "application/octet-stream".to_string(),
            data:"hello\n Yeah kek ruururun\n\n\nKE".to_string()
        }
    )
}
