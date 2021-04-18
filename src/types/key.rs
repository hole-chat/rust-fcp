use super::traits::{FcpParser, FcpRequest};
use rusqlite::types::ToSqlOutput;
use rusqlite::{
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
    Result, ToSql,
};
extern crate serde;

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor, Error};
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
#[derive(Debug, PartialEq)]
pub struct SSK {
    pub sign_key: String,
    pub decrypt_key: String,
    pub settings: Option<String>,
}
/// converting SSK to rusqlite type
impl ToSql for SSK {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.convert()))
    }
}

/// converting from rusqlite type to SSK
impl FromSql for SSK {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match SSK::parse(value.as_str()?) {
            Some(res) => Ok(res),
            None => Err(FromSqlError::InvalidType),
        }
    }
}

impl serde::ser::Serialize for SSK {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        serializer.serialize_str(&self.convert()[..])
    }
}

impl<'de> Deserialize<'de> for SSK {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SSKVisitor;

        impl<'de> Visitor<'de> for SSKVisitor {
            type Value = SSK;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SSK")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                //return Ok(SSK{sign_key: "lol".to_string(), decrypt_key: "kik".to_string(),settings: Some("kek".to_string())});
                match SSK::parse(v) {
                    Some(ssk) => {
                        Ok(ssk)
                    },
                    None => {
                        Err(de::Error::unknown_variant(v, &["expected key with structure like SSK@../../?"]))
                    }
                }

            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                where
                    E: de::Error,
            {
                //return Ok(SSK{sign_key: "lol".to_string(), decrypt_key: "kik".to_string(),settings: Some("kek".to_string())});
                match SSK::parse(v) {
                    Some(ssk) => {
                        Ok(ssk)
                    },
                    None => {
                        Err(de::Error::unknown_variant(v, &["expected key with structure like SSK@../../?"]))
                    }
                }

            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                where
                    E: de::Error,
            {
                return Ok(SSK{sign_key: "lol".to_string(), decrypt_key: "kik".to_string(),settings: Some("kek".to_string())});
                match SSK::parse(&v[..]) {
                    Some(ssk) => {
                        Ok(ssk)
                    },
                    None => {
                        Err(de::Error::unknown_variant(&v[..], &["expected key with structure like SSK@../../?"]))
                    }
                }
            }
        }
        println!("tset");
        return deserializer.deserialize_any(SSKVisitor)
    }
}

#[derive(Debug, PartialEq)]
pub struct USK {
    pub ssk: SSK,
    pub path: String,
}

#[cfg(test)]
mod tests {
    use types::traits::FcpRequest;

    use crate::types::SSK;
    use crate::*;
    #[test]
    fn is_ssk_serializing() {
        let ssk: SSK = SSK {
            sign_key: "AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: None,
        };
        let json = serde_json::json!(&ssk);

        assert_eq!("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM", json);
        assert_eq!("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM", &ssk.convert());
    }
    #[test]
    fn is_ssk_deserializing() {
        let ssk: SSK = SSK {
            sign_key: "AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: None,
        };
        let res: SSK = serde_json::from_str("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM").unwrap();
        assert_eq!(res, ssk)
    }
}
