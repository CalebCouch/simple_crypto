use super::Error;

use schemars::schema::{Schema, SchemaObject, StringValidation};
use schemars::gen::SchemaGenerator;
use schemars::JsonSchema;

use bitcoin_hashes::sha256t::Hash as HashT;

use bitcoin_hashes::Hash as _;
use bitcoin_hashes::sha256::Midstate;
use bitcoin_hashes::sha256::HashEngine;
use bitcoin_hashes::sha256t::Tag as TagTrait;

const MIDSTATE: Midstate = Midstate::hash_tag(env!("CARGO_CRATE_NAME").as_bytes());

pub struct Tag {}
impl TagTrait for Tag {
    fn engine() -> HashEngine {HashEngine::from_midstate(MIDSTATE, 0)}
}

pub type BHash = HashT<Tag>;


#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Hash {
    inner: BHash
}

impl Hash {
    pub fn to_arr(self) -> [u8; 32] {*self.inner.as_ref()}
    pub fn all_zeros() -> Self {Hash{inner: BHash::all_zeros()}}
    pub fn new(inner: BHash) -> Self {Hash{inner}}
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.as_byte_array().to_vec()
    }
    pub fn as_bytes(&self) -> &[u8] {self.inner.as_byte_array()}
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(Hash{inner: BHash::from_slice(slice)?})
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl std::str::FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_slice(&hex::decode(s)?)
    }
}

impl JsonSchema for Hash {
    fn schema_name() -> String {"Hash".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{64}$".to_string())
    }
}

pub struct Schemas {}
impl Schemas {
    pub fn regex(regex: String) -> Schema {
        Schema::Object(SchemaObject{
            string: Some(Box::new(StringValidation {
                max_length: None,
                min_length: None,
                pattern: Some(regex)
            })),
            ..Default::default()
        })
    }
}
