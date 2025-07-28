//! Top-level Varsig envelope.

use serde::{
    de::{self, Deserializer, IntoDeserializer, MapAccess, Visitor},
    {ser::SerializeMap, Deserialize, Serialize},
};
use serde_ipld_dagcbor::codec::DagCborCodec;
use signature::SignatureEncoding;
use std::{collections::BTreeMap, fmt, marker::PhantomData};
use varsig::{header::Varsig, verify::Verify};

/// Top-level Varsig envelope type.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)] // NOTE: important!
pub struct Envelope<
    V: Verify<Signature = S>,
    T: Serialize + for<'de> Deserialize<'de>,
    S: SignatureEncoding,
>(
    /// Envelope signature.
    pub S,
    /// Varsig envelope
    pub EnvelopePayload<V, T>,
);

/// Inner Varsig envelope payload type.
#[derive(Debug, Clone)]
pub struct EnvelopePayload<V: Verify, T: Serialize + for<'de> Deserialize<'de>> {
    /// Varsig header.
    pub header: Varsig<V, DagCborCodec, T>,

    /// Payload data.
    pub payload: T,
}

impl<V: Verify, T: Serialize + for<'de> Deserialize<'de>> Serialize for EnvelopePayload<V, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload = serde_value::to_value(&self.payload).map_err(serde::ser::Error::custom)?;

        let payload_map = match payload {
            serde_value::Value::Map(map) => map,
            _ => return Err(serde::ser::Error::custom("payload must serialize to a map")),
        };

        // Total length = header (1) + payload (n)
        let mut map = serializer.serialize_map(Some(1 + payload_map.len()))?;
        map.serialize_entry("h", &self.header)?;

        // Flatten payload
        for (k, v) in payload_map {
            // TODO enforce that no keys conflict with "h"
            map.serialize_entry(&k, &v)?;
        }

        map.end()
    }
}

impl<'de, V, T: Serialize + for<'ze> Deserialize<'ze>> Deserialize<'de> for EnvelopePayload<V, T>
where
    V: Verify,
    Varsig<V, DagCborCodec, T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "kebab-case")]
        enum Field {
            Header,
            Payload(serde_value::Value),
        }

        struct EnvelopeVisitor<V: Verify, T: Serialize + for<'ze> Deserialize<'ze>> {
            marker: PhantomData<fn() -> EnvelopePayload<V, T>>,
        }

        impl<'de, V, T> Visitor<'de> for EnvelopeVisitor<V, T>
        where
            V: Verify,
            Varsig<V, DagCborCodec, T>: Deserialize<'de>,
            T: Serialize + for<'ee> Deserialize<'ee>,
        {
            type Value = EnvelopePayload<V, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with field `h` and flattened payload fields")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut header: Option<Varsig<V, DagCborCodec, T>> = None;
                let mut payload_map = BTreeMap::new();

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Header => {
                            if header.is_some() {
                                return Err(de::Error::duplicate_field("h"));
                            }
                            header = Some(map.next_value()?);
                        }
                        Field::Payload(key) => {
                            let value: serde_value::Value = map.next_value()?;
                            payload_map.insert(key, value);
                        }
                    }
                }

                let header = header.ok_or_else(|| de::Error::missing_field("h"))?;

                let payload_deserializer = serde_value::Value::Map(payload_map).into_deserializer();
                let payload = T::deserialize(payload_deserializer).map_err(de::Error::custom)?;

                Ok(EnvelopePayload { header, payload })
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor {
            marker: PhantomData,
        })
    }
}
