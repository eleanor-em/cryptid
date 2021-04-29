pub trait AsBase64
where
    Self: Sized,
{
    type Error;

    fn as_base64(&self) -> String;
    fn try_from_base64(encoded: &str) -> Result<Self, Self::Error>;
}

pub const K: u32 = 12;
pub const SCALAR_MAX_BYTES: usize = ((252 - K) / 8) as usize;

#[macro_export]
macro_rules! base64_serde {
    ($name:ty) => {
        mod base64_serde_inner {
            use super::AsBase64;
            use serde::de;
            use std::fmt;

            pub struct Base64Visitor;

            impl<'de> de::Visitor<'de> for Base64Visitor {
                type Value = $name;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("binary data encoded as base64")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    <$name>::try_from_base64(value)
                        .map_err(|_| de::Error::custom("not a valid encoding"))
                }
            }
        }
        impl serde::Serialize for $name {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.as_base64())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(
                deserializer: D,
            ) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_str(base64_serde_inner::Base64Visitor)
            }
        }
    };
}
