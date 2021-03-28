use super::traits::{FcpParser, FcpRequest};
use rusqlite::types::ToSqlOutput;
use rusqlite::{
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
    Result, ToSql,
};
extern crate serde;

use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize ;
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
#[derive(Debug, PartialEq)]
pub struct USK {
    pub ssk: SSK,
    pub index: i32,
}

#[cfg(test)]
mod tests {
    use types::traits::FcpRequest;

    use crate::types::SSK;
    use crate::*;
    #[test]
    fn is_serializing() {
        let ssk:SSK = SSK {
            sign_key: "AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: None
        };
        let json = serde_json::json!(&ssk);



        assert_eq!("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM", json);
        assert_eq!("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM", &ssk.convert());



    }
}
