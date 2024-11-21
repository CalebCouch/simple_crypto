// SPDX-License-Identifier: MIT OR Apache-2.0

//! BIP324 encrypted transport for exchanging bitcoin P2P *messages*. Much like TLS, a connection begins by exchanging ephemeral
//! elliptic curve public keys and performing a Diffie-Hellman handshake. Thereafter, each participant derives shared session secrets, and may
//! freely exchange encrypted packets.
//!
//! ## Packets
//!
//! A *packet* has the following layout:
//!   * *Length*   - 3-byte encoding of the length of the *contents* (note this does not include the header byte).
//!   * *Header*   - 1-byte for transport layer protocol flags, currently only used to flag decoy packets.
//!   * *Contents* - Variable length payload.
//!   * *Tag*      - 16-byte authentication tag.
//!
//! ## Application Messages
//!
//! Under the new V2 specification, P2P messages are encoded differently than V1.
//! Read more about the [specification](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki).

mod chacha20poly1305;
mod fschacha20poly1305;
mod hkdf;

use core::fmt;

pub use bitcoin::Network;

use bitcoin::{
    hashes::sha256,
    secp256k1::{
        self,
        ellswift::{ElligatorSwift, ElligatorSwiftParty},
        SecretKey,
    },
};
use fschacha20poly1305::{FSChaCha20, FSChaCha20Poly1305};
use hkdf::Hkdf;

/// Number of bytes for the header holding protocol flags.
pub const NUM_HEADER_BYTES: usize = 1;
/// Number of bytes for the length encoding prefix of a packet.
pub const NUM_LENGTH_BYTES: usize = 3;

// Number of bytes for the authentication tag of a packet.
const NUM_TAG_BYTES: usize = 16;
// Number of bytes per packet for static layout, everything not including contents.
const NUM_PACKET_OVERHEAD_BYTES: usize = NUM_LENGTH_BYTES + NUM_HEADER_BYTES + NUM_TAG_BYTES;

/// Errors encountered throughout the lifetime of a V2 connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encrypted text does not contain enough information to decrypt.
    CiphertextTooSmall,
    /// Allocated memory is too small for packet, returns
    /// total required bytes for the failed packet so the
    /// caller can re-allocate and re-attempt.
    BufferTooSmall { required_bytes: usize },
    /// The maximum amount of garbage bytes was exceeded in the handshake.
    MaxGarbageLength,
    /// A handshake step was not completed in the proper order.
    HandshakeOutOfOrder,
    /// Not able to generate secret material.
    SecretGeneration(SecretGenerationError),
    /// General decryption error, channel could be out of sync.
    Decryption(fschacha20poly1305::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CiphertextTooSmall => {
                write!(
                    f,
                    "Ciphertext does not contain enough information, should be further extended."
                )
            }
            Error::BufferTooSmall { required_bytes } => write!(
                f,
                "Buffer memory allocation too small, need at least {} bytes.",
                required_bytes
            ),
            Error::MaxGarbageLength => {
                write!(f, "More than 4095 bytes of garbage in the handshake.")
            }
            Error::HandshakeOutOfOrder => write!(f, "Handshake flow out of sequence."),
            Error::SecretGeneration(e) => write!(f, "Cannot generate secrets: {:?}.", e),
            Error::Decryption(e) => write!(f, "Decrytion error: {:?}.", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<fschacha20poly1305::Error> for Error {
    fn from(e: fschacha20poly1305::Error) -> Self {
        Error::Decryption(e)
    }
}

/// Secret generation specific errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecretGenerationError {
    /// Undable to generate a secret.
    MaterialsGeneration(secp256k1::Error),
    /// Unable to expand the key.
    Expansion(hkdf::MaxLengthError),
}

impl fmt::Display for SecretGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretGenerationError::MaterialsGeneration(e) => {
                write!(f, "Cannot generate materials: {}.", e)
            }
            SecretGenerationError::Expansion(e) => write!(f, "Cannot expand key: {}.", e),
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::SecretGeneration(SecretGenerationError::MaterialsGeneration(e))
    }
}

impl From<hkdf::MaxLengthError> for Error {
    fn from(e: hkdf::MaxLengthError) -> Self {
        Error::SecretGeneration(SecretGenerationError::Expansion(e))
    }
}

/// All keys derived from the ECDH.
#[derive(Clone)]
pub struct SessionKeyMaterial {
    initiator_length_key: [u8; 32],
    initiator_packet_key: [u8; 32],
    responder_length_key: [u8; 32],
    responder_packet_key: [u8; 32],
}

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Started the handshake with a peer.
    Initiator,
    /// Responding to a handshake.
    Responder,
}

/// Read packets over established encrypted channel from a peer.
#[derive(Clone)]
pub struct PacketReader {
    packet_decoding_aead: FSChaCha20Poly1305,
}

impl PacketReader {
    /// Decrypt the packet header byte and contents.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///                  the header, contents, and authentication tag.
    /// * `contents`   - Mutable buffer to write plaintext. Note that the first byte is the header byte
    ///                  containing protocol flags.
    /// * `aad`        - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(PacketType)`: A flag indicating if the decoded packet is a decoy or not.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    /// * `BufferTooSmall `    - Contents buffer argument is not large enough for plaintext.
    /// * Decryption errors for any failures such as a tag mismatch.
    pub fn decrypt_payload_no_alloc(
        &mut self,
        ciphertext: &[u8],
        contents: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        let auth = aad.unwrap_or_default();
        // Check minimum size of ciphertext.
        if ciphertext.len() < NUM_TAG_BYTES {
            return Err(Error::CiphertextTooSmall);
        }
        let (msg, tag) = ciphertext.split_at(ciphertext.len() - NUM_TAG_BYTES);
        // Check that the contents buffer is large enough.
        if contents.len() < msg.len() {
            return Err(Error::BufferTooSmall {
                required_bytes: msg.len(),
            });
        }
        contents[0..msg.len()].copy_from_slice(msg);
        self.packet_decoding_aead.decrypt(
            auth,
            &mut contents[0..msg.len()],
            tag.try_into().expect("16 byte tag"),
        )?;

        Ok(())
    }

    /// Decrypt the packet header byte and contents.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///                  the header, contents, and authentication tag.
    /// * `aad`        - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Payload)`: The plaintext header and contents.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    pub fn decrypt_payload(
        &mut self,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut payload = vec![0u8; ciphertext.len() - NUM_TAG_BYTES];
        self.decrypt_payload_no_alloc(ciphertext, &mut payload, aad)?;
        Ok(payload)
    }
}

/// Prepare packets to be sent over encrypted channel to a peer.
#[derive(Clone)]
pub struct PacketWriter {
    length_encoding_cipher: FSChaCha20,
    packet_encoding_aead: FSChaCha20Poly1305,
}

impl PacketWriter {
    /// Encrypt plaintext bytes and serialize into a packet to be sent over the wire.
    ///
    /// # Arguments
    ///
    /// * `plaintext`   - Plaintext contents to be encrypted.
    /// * `aad`         - Optional associated authenticated data.
    /// * `packet`      - Buffer to write backet bytes too which must have enough capacity
    ///                   for the plaintext length in bytes + 20 (length, header, and tag bytes).
    ///
    /// # Errors
    ///
    /// * `Error::BufferTooSmall` - Buffer does not have enough allocated memory for the
    ///                             ciphertext plus the 20 bytes needed for the length, header, and tag bytes.
    pub fn encrypt_packet_no_alloc(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        packet: &mut [u8],
    ) -> Result<(), Error> {
        // Validate buffer capacity.
        if packet.len() < plaintext.len() + NUM_PACKET_OVERHEAD_BYTES {
            return Err(Error::BufferTooSmall {
                required_bytes: plaintext.len() + NUM_PACKET_OVERHEAD_BYTES,
            });
        }

        let plaintext_length = plaintext.len();
        let header_index = NUM_LENGTH_BYTES + NUM_HEADER_BYTES - 1;
        let plaintext_start_index = header_index + 1;
        let plaintext_end_index = plaintext_start_index + plaintext_length;

        // Set header byte.
        packet[header_index] = 0;
        packet[plaintext_start_index..plaintext_end_index].copy_from_slice(plaintext);

        // Encrypt header byte and plaintext in place and produce authentication tag.
        let auth = aad.unwrap_or_default();
        let tag = self
            .packet_encoding_aead
            .encrypt(auth, &mut packet[header_index..plaintext_end_index]);

        // Encrypt plaintext length.
        let mut content_len = [0u8; 3];
        content_len.copy_from_slice(&(plaintext_length as u32).to_le_bytes()[0..NUM_LENGTH_BYTES]);
        self.length_encoding_cipher.crypt(&mut content_len);

        // Copy over encrypted length and the tag to the final packet (plaintext already encrypted).
        packet[0..NUM_LENGTH_BYTES].copy_from_slice(&content_len);
        packet[plaintext_end_index..(plaintext_end_index + NUM_TAG_BYTES)].copy_from_slice(&tag);

        Ok(())
    }

    /// Encrypt plaintext bytes and serialize into a packet to be sent over the wire
    /// and handle necessary memory allocation.
    ///
    /// * `plaintext`   - Plaintext content to be encrypted.
    /// * `aad`         - Optional associated authenticated data.
    pub fn encrypt_packet(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0u8; plaintext.len() + NUM_PACKET_OVERHEAD_BYTES];
        self.encrypt_packet_no_alloc(plaintext, aad, &mut packet)?;
        Ok(packet)
    }
}

/// Encrypt and decrypt packets with a peer.
#[derive(Clone)]
pub struct PacketHandler {
    /// Decrypt packets.
    packet_reader: PacketReader,
    /// Encrypt packets.
    packet_writer: PacketWriter,
}

impl PacketHandler {
    pub fn new(materials: SessionKeyMaterial, role: Role) -> Self {
        match role {
            Role::Initiator => {
                let length_encoding_cipher = FSChaCha20::new(materials.initiator_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                PacketHandler {
                    packet_reader: PacketReader {
                        packet_decoding_aead: packet_decoding_cipher,
                    },
                    packet_writer: PacketWriter {
                        length_encoding_cipher,
                        packet_encoding_aead: packet_encoding_cipher,
                    },
                }
            }
            Role::Responder => {
                let length_encoding_cipher = FSChaCha20::new(materials.responder_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                PacketHandler {
                    packet_reader: PacketReader {
                        packet_decoding_aead: packet_decoding_cipher,
                    },
                    packet_writer: PacketWriter {
                        length_encoding_cipher,
                        packet_encoding_aead: packet_encoding_cipher,
                    },
                }
            }
        }
    }

    /// Read reference for packet decryption.
    pub fn reader(&mut self) -> &mut PacketReader {
        &mut self.packet_reader
    }

    /// Write reference for packet encryption.
    pub fn writer(&mut self) -> &mut PacketWriter {
        &mut self.packet_writer
    }
}

pub struct Handshake {}
impl Handshake {
    pub fn get_shared_secrets(
        a: ElligatorSwift,
        b: ElligatorSwift,
        secret: SecretKey,
        party: ElligatorSwiftParty,
        network: Network,
    ) -> Result<SessionKeyMaterial, Error> {
        let data = "bip324_ellswift_xonly_ecdh".as_bytes();
        let ecdh_sk = ElligatorSwift::shared_secret(a, b, secret, party, Some(data));

        let ikm_salt = "bitcoin_v2_shared_secret".as_bytes();
        let magic = network.magic().to_bytes();
        let salt = [ikm_salt, &magic].concat();
        let hk = Hkdf::<sha256::Hash>::new(salt.as_slice(), ecdh_sk.as_secret_bytes());
        let mut session_id = [0u8; 32];
        let session_info = "session_id".as_bytes();
        hk.expand(session_info, &mut session_id)?;
        let mut initiator_length_key = [0u8; 32];
        let intiiator_l_info = "initiator_L".as_bytes();
        hk.expand(intiiator_l_info, &mut initiator_length_key)?;
        let mut initiator_packet_key = [0u8; 32];
        let intiiator_p_info = "initiator_P".as_bytes();
        hk.expand(intiiator_p_info, &mut initiator_packet_key)?;
        let mut responder_length_key = [0u8; 32];
        let responder_l_info = "responder_L".as_bytes();
        hk.expand(responder_l_info, &mut responder_length_key)?;
        let mut responder_packet_key = [0u8; 32];
        let responder_p_info = "responder_P".as_bytes();
        hk.expand(responder_p_info, &mut responder_packet_key)?;
        Ok(SessionKeyMaterial {
            initiator_length_key,
            initiator_packet_key,
            responder_length_key,
            responder_packet_key,
        })
    }
}
