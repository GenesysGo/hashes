use crate::{consts, sha256::compress256, sha512::compress512};
use core::{fmt, slice::from_ref};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser,
        SerializableHasher, TruncSide, UpdateCore, VariableOutputCore,
    },
    typenum::{Unsigned, U128, U32, U64},
    HashMarker, InvalidOutputSize, Output,
};

/// Core block-level SHA-256 hasher with variable output size.
///
/// Supports initialization only for 28 and 32 byte output sizes,
/// i.e. 224 and 256 bits respectively.
#[derive(Clone)]
pub struct Sha256VarCore {
    state: consts::State256,
    block_len: u64,
}

impl HashMarker for Sha256VarCore {}

impl BlockSizeUser for Sha256VarCore {
    type BlockSize = U64;
}

impl BufferKindUser for Sha256VarCore {
    type BufferKind = Eager;
}

impl UpdateCore for Sha256VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        compress256(&mut self.state, blocks);
    }
}

impl OutputSizeUser for Sha256VarCore {
    type OutputSize = U32;
}

impl VariableOutputCore for Sha256VarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state = match output_size {
            28 => consts::H256_224,
            32 => consts::H256_256,
            _ => return Err(InvalidOutputSize),
        };
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        buffer.len64_padding_be(bit_len, |b| compress256(&mut self.state, from_ref(b)));

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sha256VarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}

impl fmt::Debug for Sha256VarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256VarCore { ... }")
    }
}

/// Core block-level SHA-512 hasher with variable output size.
///
/// Supports initialization only for 28, 32, 48, and 64 byte output sizes,
/// i.e. 224, 256, 384, and 512 bits respectively.
#[derive(Clone)]
pub struct Sha512VarCore {
    state: consts::State512,
    block_len: u128,
}

impl HashMarker for Sha512VarCore {}

impl BlockSizeUser for Sha512VarCore {
    type BlockSize = U128;
}

impl BufferKindUser for Sha512VarCore {
    type BufferKind = Eager;
}

impl UpdateCore for Sha512VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u128;
        compress512(&mut self.state, blocks);
    }
}

impl OutputSizeUser for Sha512VarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for Sha512VarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state = match output_size {
            28 => consts::H512_224,
            32 => consts::H512_256,
            48 => consts::H512_384,
            64 => consts::H512_512,
            _ => return Err(InvalidOutputSize),
        };
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64 as u128;
        let bit_len = 8 * (buffer.get_pos() as u128 + bs * self.block_len);
        buffer.len128_padding_be(bit_len, |b| compress512(&mut self.state, from_ref(b)));

        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sha512VarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512")
    }
}

impl fmt::Debug for Sha512VarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512VarCore { ... }")
    }
}

impl SerializableHasher for Sha256VarCore {
    type HasherType = Self;
    type SerializedForm = [u8; 40];
    /// Serializes a [Sha256VarCore] into the following format
    ///    
    /// | ----------------- 40 bytes ----------------- |
    /// [ ----- 32 bytes of state ----- | u64 le_bytes |
    fn to_bytes(&self) -> [u8; 40] {
        // Initialize return value with zeros
        let mut bytes = [0; 40];

        // Copy state and block length
        bytes[..32]
            .copy_from_slice(&unsafe { core::mem::transmute::<[u32; 8], [u8; 32]>(self.state) });
        bytes[32..40].copy_from_slice(&self.block_len.to_le_bytes());

        bytes
    }

    /// Given 40 bytes serialized as
    ///    
    /// | ----------------- 40 bytes ----------------- |
    /// [ ----- 32 bytes of state ----- | u64 le_bytes |
    ///
    /// constructs a [Sha256VarCore].
    fn from_bytes(bytes: [u8; 40]) -> Sha256VarCore {
        // Initialize and copy state
        let mut state = [0; 32];
        state.copy_from_slice(&bytes[..32]);
        let state = unsafe { core::mem::transmute::<[u8; 32], [u32; 8]>(state) };

        // Convert le len bytes
        use core::convert::TryInto;
        let block_len = u64::from_le_bytes(bytes[32..].try_into().unwrap());

        Sha256VarCore { state, block_len }
    }
}

impl SerializableHasher for Sha512VarCore {
    type HasherType = Self;
    type SerializedForm = [u8; 80];

    /// Serializes a [Sha512VarCore] into the following format
    ///    
    /// | ----------------- 80 bytes ----------------- |
    /// [ ----- 64 bytes of state ----- | u128 lebytes |
    fn to_bytes(&self) -> [u8; 80] {
        // Initialize return value with zeros
        let mut bytes = [0; 80];

        // Copy state and block length
        bytes[..64]
            .copy_from_slice(&unsafe { core::mem::transmute::<[u64; 8], [u8; 64]>(self.state) });
        bytes[64..].copy_from_slice(&self.block_len.to_le_bytes());

        bytes
    }

    /// Given 80 bytes serialized as
    ///    
    /// | ----------------- 80 bytes ----------------- |
    /// [ ----- 64 bytes of state ----- | u128 lebytes |
    ///
    /// constructs a [Sha512VarCore].
    fn from_bytes(bytes: [u8; 80]) -> Sha512VarCore {
        // Initialize and copy state
        let mut state = [0; 64];
        state.copy_from_slice(&bytes[..64]);
        let state = unsafe { core::mem::transmute::<[u8; 64], [u64; 8]>(state) };

        // Convert le len bytes
        use core::convert::TryInto;
        let block_len = u128::from_le_bytes(bytes[64..].try_into().unwrap());

        Sha512VarCore { state, block_len }
    }
}

#[test]
fn test_sha256_serialize_deserialize() {
    use digest::generic_array::GenericArray;
    let mut sha256 = Sha256VarCore::new(32).unwrap();
    let block: Block<Sha256VarCore> = GenericArray::clone_from_slice(
        b"caveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwashere",
    );
    sha256.update_blocks(&[block]);

    let mut round_trip = Sha256VarCore::from_bytes(sha256.to_bytes());
    assert_eq!(sha256.state, round_trip.state);
    assert_eq!(sha256.block_len, round_trip.block_len);

    let mut hash_bytes = [0; 32];
    let hash = GenericArray::from_mut_slice(&mut hash_bytes);
    let mut buffer: Buffer<Sha256VarCore> = Buffer::<Sha256VarCore>::default();
    sha256.finalize_variable_core(&mut buffer, hash);

    let mut round_trip_hash_bytes = [0; 32];
    let round_trip_hash = GenericArray::from_mut_slice(&mut round_trip_hash_bytes);
    let mut buffer: Buffer<Sha256VarCore> = Buffer::<Sha256VarCore>::default();
    round_trip.finalize_variable_core(&mut buffer, round_trip_hash);

    assert_eq!(hash_bytes, round_trip_hash_bytes)
}

#[test]
fn test_sha512_serialize_deserialize() {
    use digest::generic_array::GenericArray;
    let mut sha512 = Sha512VarCore::new(32).unwrap();
    let block: Block<Sha512VarCore> = GenericArray::clone_from_slice(
        b"caveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwasherecaveycoolwashere",
    );
    sha512.update_blocks(&[block]);

    let round_trip = Sha512VarCore::from_bytes(sha512.to_bytes());

    assert_eq!(sha512.state, round_trip.state);
    assert_eq!(sha512.block_len, round_trip.block_len);
}
