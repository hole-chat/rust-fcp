use super::traits::{FcpParser, FcpRequest};
use rusqlite::types::ToSqlOutput;
use rusqlite::{Result, ToSql, types::{FromSql, ValueRef, FromSqlResult, FromSqlError}};

#[derive(Debug, PartialEq)]
pub struct SSK {
    pub sign_key: String,
    pub decrypt_key: String,
    pub settings: Option<String>,
}

impl ToSql for SSK {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.convert()))
    }
}

impl FromSql for SSK{
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self>{
        match SSK::parse(value.as_str()?) {
            Some(res) => Ok(res),
            None => Err(FromSqlError::InvalidType)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct USK {
    pub ssk: SSK,
    pub index: i32,
}


