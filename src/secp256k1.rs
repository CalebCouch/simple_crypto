use super::Error;

use super::bip324::{PacketHandler, Handshake, Role};
use super::structs::{Schemas, Hash};
use super::traits::Hashable;

use bitcoin_hashes::{Hash as BHash, hash160};
use serde::{Serialize, Deserialize};
use schemars::gen::SchemaGenerator;
use secp256k1::schnorr::Signature;
use secp256k1::{Message, Keypair};
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use bitcoin::NetworkKind;
use bitcoin::bip32::{
    ChildNumber,
    Xpriv,
};
use schemars::schema::Schema;
use schemars::JsonSchema;
use either::Either;
use bitcoin::Network;

fn message(payload: &[u8]) -> Message {
    Message::from_digest(payload.hash().to_arr())
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    inner: Either<PublicKey, SecretKey>
}

impl Key {
    pub fn new_public(key: PublicKey) -> Self {Key{inner: Either::Left(key)}}
    pub fn new_secret(key: SecretKey) -> Self {Key{inner: Either::Right(key)}}

    pub fn public_key(&self) -> PublicKey {
        self.inner.clone().left_or_else(|r| r.public_key())
    }
    pub fn secret_key(&self) -> Option<SecretKey> {self.inner.clone().right()}

    pub fn secret_or(self, key: Key) -> Key {if self.inner.is_right() {self} else {key}}
    pub fn to_public(self) -> Self {Self::new_public(self.public_key())}
    pub fn is_public(&self) -> bool {self.inner.is_left()}
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey {
    key: secp256k1::PublicKey
}


impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey{key: secp256k1::PublicKey::from_slice(b)?})
    }
    pub fn thumbprint(&self) -> String {
        hex::encode(hash160::Hash::hash(&self.key.serialize()))
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        Ok(Signature::from_slice(signature)?.verify(
            &message(payload),
            &self.key.x_only_public_key().0
        )?)
    }

    pub fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let their_ell_swift = ElligatorSwift::from_pubkey(self.key);
        let my_sec_key = SecretKey::new();
        let my_ell_swift = ElligatorSwift::from_pubkey(my_sec_key.public_key().key);
        let session_keys = Handshake::get_shared_secrets(
            my_ell_swift,
            their_ell_swift,
            my_sec_key.key,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )?;
        let mut packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        Ok([
            my_ell_swift.to_array().to_vec(),
            packet_handler.writer().encrypt_packet(payload, None)?
        ].concat())
    }
}

impl JsonSchema for PublicKey {
    fn schema_name() -> String {"PublicKey".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{32}$".to_string())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

#[derive(Clone, PartialEq, Eq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct SecretKey {
    key: secp256k1::SecretKey
}

impl SecretKey {
    pub fn new() -> Self {
        SecretKey{
            key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng())
        }
    }
    pub fn encrypt_self(&self, public_key: &PublicKey) -> Result<Vec<u8>, Error> {
        public_key.encrypt(&serde_json::to_vec(&self.key)?)
    }
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        Keypair::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &self.key
        ).sign_schnorr(message(payload)).serialize().to_vec()
    }
    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() < 65 {return Err(Error::err("SecretKey.decrypt", "Payload was too small"));}
        let their_ell_swift = ElligatorSwift::from_array(payload[0..64].try_into().unwrap());
        let my_sec_key = self;
        let my_ell_swift = ElligatorSwift::from_pubkey(my_sec_key.public_key().key);
        let session_keys = Handshake::get_shared_secrets(
            their_ell_swift,
            my_ell_swift,
            my_sec_key.key,
            ElligatorSwiftParty::B,
            Network::Bitcoin,
        )?;
        let mut packet_handler = PacketHandler::new(session_keys, Role::Responder);
        Ok(packet_handler.reader().decrypt_payload(&payload[64+3..], None)?[1..].to_vec())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey{key: self.key.public_key(&secp256k1::Secp256k1::new())}
    }

    pub fn derive_usize(&self, index: usize) -> Result<Self, Error> {
        self.get_child(Derivation::from_usize(index)?)
    }

    pub fn derive_hash(&self, hash: &Hash) -> Result<Self, Error> {
        self.get_child(Derivation::from_hash(hash)?)
    }

    pub fn derive_bytes(&self, bytes: &[u8]) -> Result<Self, Error> {
        self.get_child(Derivation::from_bytes(bytes)?)
    }

    pub fn get_child(&self, derivation_path: Vec<ChildNumber>) -> Result<Self, Error> {
        let x_priv = Xpriv::new_master(
            NetworkKind::Main,
            &self.key.secret_bytes()
        )?;
        Ok(SecretKey{
            key: x_priv.derive_priv(
                &secp256k1::Secp256k1::new(),
                &derivation_path,
            )?.to_priv().inner
        })
    }
}

impl Default for SecretKey {
    fn default() -> Self {Self::new()}
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.secret_bytes().cmp(&other.key.secret_bytes())
    }
}


impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
        .field("key", &&self.to_string()[0..10])
        .field("kp", &&self.public_key().to_string()[0..10])
        .finish()
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.key.secret_bytes()))
    }
}

impl std::str::FromStr for SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecretKey{key: secp256k1::SecretKey::from_slice(&hex::decode(s)?)?})
    }
}

impl JsonSchema for SecretKey {
    fn schema_name() -> String {"SecretKey".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{64}$".to_string())
    }
}

struct Derivation {}
impl Derivation {
    pub fn from_bytes(bytes: &[u8]) -> Result<Vec<ChildNumber>, Error> {
        let mut results = vec![];
        for i in 0..(bytes.len()/3)+1 {
            let index = u32::from_le_bytes([
                bytes.get(i).copied().unwrap_or_default(),
                bytes.get(i+1).copied().unwrap_or_default(),
                bytes.get(i+2).copied().unwrap_or_default(),
                0
            ]);
            results.push(ChildNumber::from_hardened_idx(index)?);
        }
        Ok(results)
    }
    pub fn from_usize(index: usize) -> Result<Vec<ChildNumber>, Error> {
        Self::from_bytes(&index.to_le_bytes())
    }
    pub fn from_hash(hash: &Hash) -> Result<Vec<ChildNumber>, Error> {
        Self::from_bytes(hash.as_bytes())
    }
}
