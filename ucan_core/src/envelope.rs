//! Top-level Varsig envelope.

use ipld_core::ipld::Ipld;
use serde::{
    de::{
        self, value::BorrowedBytesDeserializer, Deserializer, IntoDeserializer, MapAccess,
        SeqAccess, Visitor,
    },
    ser::SerializeMap,
    Deserialize, Serialize,
};
use serde_ipld_dagcbor::codec::DagCborCodec;
use signature::SignatureEncoding;
use std::{collections::BTreeMap, fmt, marker::PhantomData};
use varsig::{header::Varsig, verify::Verify};

/// Top-level Varsig envelope type.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Envelope<
    V: Verify<Signature = S>,
    T: Serialize + for<'ze> Deserialize<'ze>,
    S: SignatureEncoding,
>(
    /// Envelope signature.
    pub S,
    /// Varsig envelope
    pub EnvelopePayload<V, T>,
);

impl<
        'de,
        V: Verify<Signature = S>,
        T: Serialize + for<'ze> Deserialize<'ze>,
        S: SignatureEncoding + for<'ze> Deserialize<'ze>,
    > Deserialize<'de> for Envelope<V, T, S>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor<V, T, S>
        where
            V: Verify<Signature = S>,
            T: Serialize + for<'ze> Deserialize<'ze>,
            S: SignatureEncoding,
        {
            marker: std::marker::PhantomData<(V, T, S)>,
        }

        impl<'de, V, T, S> Visitor<'de> for EnvelopeVisitor<V, T, S>
        where
            V: Verify<Signature = S>,
            T: Serialize + for<'ze> Deserialize<'ze>,
            S: SignatureEncoding + Deserialize<'de>,
        {
            type Value = Envelope<V, T, S>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 2-element sequence [signature, payload]")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                dbg!(">>>>>>>>>>>> GOT 0");
                let sig_ipld: Ipld = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let sig_bytes = if let Ipld::Bytes(bytes) = sig_ipld {
                    bytes
                } else {
                    return Err(de::Error::custom("expected signature to be bytes"));
                };

                let signature = S::try_from(sig_bytes.as_slice())
                    .map_err(|_| de::Error::custom("invalid signature bytes"))?;
                dbg!(">>>>>>>>>>>> GOT 1");

                let payload: EnvelopePayload<V, T> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                dbg!(">>>>>>>>>>> GOT 2");

                // FIXME prevent extra fields

                Ok(Envelope(signature, payload))
            }
        }

        deserializer.deserialize_tuple(
            2,
            EnvelopeVisitor {
                marker: std::marker::PhantomData,
            },
        )
    }
}

/// Inner Varsig envelope payload type.
#[derive(Debug, Clone, PartialEq)]
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

impl<'de, V, T> Deserialize<'de> for EnvelopePayload<V, T>
where
    V: Verify,
    T: Serialize + for<'any> Deserialize<'any>,
    Varsig<V, DagCborCodec, T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnvelopeVisitor<V, T>(PhantomData<(V, T)>);

        // Note the different lifetime parameter on the Visitor:
        impl<'vde, V, T> Visitor<'vde> for EnvelopeVisitor<V, T>
        where
            V: Verify,
            T: Serialize + for<'any> Deserialize<'any>,
            Varsig<V, DagCborCodec, T>: Deserialize<'vde>,
        {
            type Value = EnvelopePayload<V, T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"a map with "h" and exactly one dynamic payload key"#)
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'vde>,
            {
                let mut header: Option<Varsig<V, DagCborCodec, T>> = None;
                let mut payload: Option<T> = None;
                let mut seen_payload = false;

                dbg!(">>>>>>>>>> ENV PAYLOAD 0");

                while let Some(key) = map.next_key::<&str>()? {
                    if key == "h" {
                        dbg!(">>>>>>>>>> ENV PAYLOAD: H");
                        if header.is_some() {
                            return Err(de::Error::duplicate_field("h"));
                        }
                        let varsig_header_ipld: Ipld = map.next_value()?;
                        let varsig_header_bytes: Vec<u8> = if let Ipld::Bytes(bytes) =
                            varsig_header_ipld
                        {
                            bytes
                        } else {
                            return Err(de::Error::custom("expected varsig header to be bytes"));
                        };
                        let bytes_de = serde::de::value::BytesDeserializer::<M::Error>::new(
                            &varsig_header_bytes,
                        );

                        let varsig_header: Varsig<V, DagCborCodec, T> =
                            Varsig::<V, DagCborCodec, T>::deserialize(bytes_de)?;

                        header = Some(varsig_header);
                    } else {
                        dbg!(">>>>>>>>>> ENV PAYLOAD: REST");
                        if seen_payload {
                            return Err(de::Error::custom(
                                "expected exactly one dynamic payload entry",
                            ));
                        }
                        dbg!(">>>> ABOUT TO TRY NEXT");
                        dbg!(format!("KEY: {key}"));
                        // let ipld = map.next_value::<Ipld>()?;
                        // dbg!(format!("IPLD: {ipld:?}"));
                        payload = Some(map.next_value::<T>()?);
                        dbg!(">>> NEXT DONE");
                        seen_payload = true;
                    }
                }

                dbg!("========== ENV PAYLOAD DONE");

                let header = header.ok_or_else(|| de::Error::missing_field("h"))?;
                let payload =
                    payload.ok_or_else(|| de::Error::custom("missing dynamic payload entry"))?;

                Ok(EnvelopePayload { header, payload })
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor(PhantomData))
    }
}
// impl<'de, V, T: Serialize + for<'ze> Deserialize<'ze>> Deserialize<'de> for EnvelopePayload<V, T>
// where
//     V: Verify,
//     Varsig<V, DagCborCodec, T>: Deserialize<'de>,
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         #[derive(Debug, Deserialize)]
//         #[serde(field_identifier)]
//         enum Field {
//             Header,
//             Payload(serde_value::Value),
//         }
//
//         struct EnvelopeVisitor<V: Verify, T: Serialize + for<'ze> Deserialize<'ze>> {
//             marker: PhantomData<fn() -> EnvelopePayload<V, T>>,
//         }
//
//         impl<'de, V, T> Visitor<'de> for EnvelopeVisitor<V, T>
//         where
//             V: Verify,
//             Varsig<V, DagCborCodec, T>: Deserialize<'de>,
//             T: Serialize + for<'ee> Deserialize<'ee>,
//         {
//             type Value = EnvelopePayload<V, T>;
//
//             fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
//                 formatter.write_str("a map with field `h` and flattened payload fields")
//             }
//
//             fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
//             where
//                 M: MapAccess<'de>,
//             {
//                 let mut header: Option<Varsig<V, DagCborCodec, T>> = None;
//                 let mut payload_map = BTreeMap::new();
//
//                 dbg!("0");
//
//                 while let Some(field) = map.next_key::<Field>()? {
//                     dbg!("0.5 {:?}", &field);
//                     match field {
//                         Field::Header => {
//                             dbg!("1");
//                             if header.is_some() {
//                                 return Err(de::Error::duplicate_field("h"));
//                             }
//                             header = Some(map.next_value()?);
//                         }
//                         Field::Payload(key) => {
//                             dbg!("2");
//                             let value: serde_value::Value = map.next_value()?;
//                             payload_map.insert(key, value);
//                         }
//                     }
//                 }
//
//                 dbg!("3");
//
//                 let header = header.ok_or_else(|| de::Error::missing_field("h"))?;
//
//                 dbg!(">>>>>>>>>> HERE");
//
//                 let payload_deserializer = serde_value::Value::Map(payload_map).into_deserializer();
//                 let payload = T::deserialize(payload_deserializer).map_err(de::Error::custom)?;
//
//                 Ok(EnvelopePayload { header, payload })
//             }
//         }
//
//         deserializer.deserialize_map(EnvelopeVisitor {
//             marker: PhantomData,
//         })
//     }
// }
