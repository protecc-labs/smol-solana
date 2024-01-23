//! The utility structs and functions for writing byte blocks for the
//! accounts db tiered storage.

use {
    crate::tiered_storage::{footer::AccountBlockFormat, meta::AccountMetaOptionalFields},
    std::{
        io::{Cursor, Read, Result as IoResult, Write},
        mem,
    },
};

/// The encoder for the byte-block.
#[derive(Debug)]
pub enum ByteBlockEncoder {
    Raw(Cursor<Vec<u8>>),
    Lz4(lz4::Encoder<Vec<u8>>),
}

/// The byte block writer.
///
/// All writes (`write_type` and `write`) will be buffered in the internal
/// buffer of the ByteBlockWriter using the specified encoding.
///
/// To finalize all the writes, invoke `finish` to obtain the encoded byte
/// block.
#[derive(Debug)]
pub struct ByteBlockWriter {
    /// the encoder for the byte-block
    encoder: ByteBlockEncoder,
    /// the length of the raw data
    len: usize,
}

impl ByteBlockWriter {
    /// Create a ByteBlockWriter from the specified AccountBlockFormat.
    pub fn new(encoding: AccountBlockFormat) -> Self {
        Self {
            encoder: match encoding {
                AccountBlockFormat::AlignedRaw => ByteBlockEncoder::Raw(Cursor::new(Vec::new())),
                AccountBlockFormat::Lz4 => ByteBlockEncoder::Lz4(
                    lz4::EncoderBuilder::new()
                        .level(0)
                        .build(Vec::new())
                        .unwrap(),
                ),
            },
            len: 0,
        }
    }

    /// Return the length of the raw data (i.e. after decoding).
    pub fn raw_len(&self) -> usize {
        self.len
    }

    /// Write plain ol' data to the internal buffer of the ByteBlockWriter instance
    ///
    /// Prefer this over `write_type()`, as it prevents some undefined behavior.
    pub fn write_pod<T: bytemuck::NoUninit>(&mut self, value: &T) -> IoResult<usize> {
        // SAFETY: Since T is NoUninit, it does not contain any uninitialized bytes.
        unsafe { self.write_type(value) }
    }

    /// Write the specified typed instance to the internal buffer of
    /// the ByteBlockWriter instance.
    ///
    /// Prefer `write_pod()` when possible, because `write_type()` may cause
    /// undefined behavior if `value` contains uninitialized bytes.
    ///
    /// # Safety
    ///
    /// Caller must ensure casting T to bytes is safe.
    /// Refer to the Safety sections in std::slice::from_raw_parts()
    /// and bytemuck's Pod and NoUninit for more information.
    pub unsafe fn write_type<T>(&mut self, value: &T) -> IoResult<usize> {
        let size = mem::size_of::<T>();
        let ptr = value as *const _ as *const u8;
        // SAFETY: The caller ensures that `value` contains no uninitialized bytes,
        // we ensure the size is safe by querying T directly,
        // and Rust ensures all values are at least byte-aligned.
        let slice = unsafe { std::slice::from_raw_parts(ptr, size) };
        self.write(slice)?;
        Ok(size)
    }

    /// Write all the Some fields of the specified AccountMetaOptionalFields.
    ///
    /// Note that the existence of each optional field is stored separately in
    /// AccountMetaFlags.
    pub fn write_optional_fields(
        &mut self,
        opt_fields: &AccountMetaOptionalFields,
    ) -> IoResult<usize> {
        let mut size = 0;
        if let Some(rent_epoch) = opt_fields.rent_epoch {
            size += self.write_pod(&rent_epoch)?;
        }
        if let Some(hash) = opt_fields.account_hash {
            size += self.write_pod(&hash)?;
        }

        debug_assert_eq!(size, opt_fields.size());

        Ok(size)
    }

    /// Write the specified typed bytes to the internal buffer of the
    /// ByteBlockWriter instance.
    pub fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        match &mut self.encoder {
            ByteBlockEncoder::Raw(cursor) => cursor.write_all(buf)?,
            ByteBlockEncoder::Lz4(lz4_encoder) => lz4_encoder.write_all(buf)?,
        };
        self.len += buf.len();
        Ok(())
    }

    /// Flush the internal byte buffer that collects all the previous writes
    /// into an encoded byte array.
    pub fn finish(self) -> IoResult<Vec<u8>> {
        match self.encoder {
            ByteBlockEncoder::Raw(cursor) => Ok(cursor.into_inner()),
            ByteBlockEncoder::Lz4(lz4_encoder) => {
                let (compressed_block, result) = lz4_encoder.finish();
                result?;
                Ok(compressed_block)
            }
        }
    }
}

/// The util struct for reading byte blocks.
pub struct ByteBlockReader;

/// Reads the raw part of the input byte_block, at the specified offset, as type T.
///
/// Returns None if `offset` + size_of::<T>() exceeds the size of the input byte_block.
///
/// Type T must be plain ol' data to ensure no undefined behavior.
pub fn read_pod<T: bytemuck::AnyBitPattern>(byte_block: &[u8], offset: usize) -> Option<&T> {
    // SAFETY: Since T is AnyBitPattern, it is safe to cast bytes to T.
    unsafe { read_type(byte_block, offset) }
}

/// Reads the raw part of the input byte_block at the specified offset
/// as type T.
///
/// If `offset` + size_of::<T>() exceeds the size of the input byte_block,
/// then None will be returned.
///
/// Prefer `read_pod()` when possible, because `read_type()` may cause
/// undefined behavior.
///
/// # Safety
///
/// Caller must ensure casting bytes to T is safe.
/// Refer to the Safety sections in std::slice::from_raw_parts()
/// and bytemuck's Pod and AnyBitPattern for more information.
pub unsafe fn read_type<T>(byte_block: &[u8], offset: usize) -> Option<&T> {
    let (next, overflow) = offset.overflowing_add(std::mem::size_of::<T>());
    if overflow || next > byte_block.len() {
        return None;
    }
    let ptr = byte_block[offset..].as_ptr() as *const T;
    debug_assert!(ptr as usize % std::mem::align_of::<T>() == 0);
    // SAFETY: The caller ensures it is safe to cast bytes to T,
    // we ensure the size is safe by querying T directly,
    // and we just checked above to ensure the ptr is aligned for T.
    Some(unsafe { &*ptr })
}

impl ByteBlockReader {
    /// Decode the input byte array using the specified format.
    ///
    /// Typically, the input byte array is the output of ByteBlockWriter::finish().
    ///
    /// Note that calling this function with AccountBlockFormat::AlignedRaw encoding
    /// will result in panic as the input is already decoded.
    pub fn decode(encoding: AccountBlockFormat, input: &[u8]) -> IoResult<Vec<u8>> {
        match encoding {
            AccountBlockFormat::Lz4 => {
                let mut decoder = lz4::Decoder::new(input).unwrap();
                let mut output = vec![];
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
            AccountBlockFormat::AlignedRaw => panic!("the input buffer is already decoded"),
        }
    }
}
