use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

static BE16: FuncDef = func!(
    /// Encode a 16bit integer into 2 big-endian bytes
    resynth fn be16(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

static BE32: FuncDef = func!(
    /// Encode a 32bit integer into 4 big-endian bytes
    resynth fn be32(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

static BE64: FuncDef = func!(
    /// Encode a 64bit integer into 8 big-endian bytes
    resynth fn be64(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

static LE16: FuncDef = func!(
    /// Encode a 16bit integer into 2 little-endian bytes
    resynth fn le16(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

static LE32: FuncDef = func!(
    /// Encode a 32bit integer into 4 little-endian bytes
    resynth fn le32(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

static LE64: FuncDef = func!(
    /// Encode a 64bit integer into 8 little-endian bytes
    resynth fn le64(
        /// Integer value to encode
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

static U8: FuncDef = func!(
    /// Convert an integer into a one-byte string
    resynth fn u8(
        /// Integer value to encode as a single byte
        val: U8,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u8 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

static LEN_BE64: FuncDef = func! (
    /// Prefix a buffer with a 64-bit big-endian length field
    ///
    /// Prepends an 8-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_be64(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U64 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u64 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u64).wrapping_add(adjust).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_BE32: FuncDef = func! (
    /// Prefix a buffer with a 32-bit big-endian length field
    ///
    /// Prepends a 4-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_be32(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U32 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u32 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u32).wrapping_add(adjust).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_BE16: FuncDef = func! (
    /// Prefix a buffer with a 16-bit big-endian length field
    ///
    /// Prepends a 2-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_be16(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U16 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u16 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u16).wrapping_add(adjust).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_LE64: FuncDef = func! (
    /// Prefix a buffer with a 64-bit little-endian length field
    ///
    /// Prepends an 8-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_le64(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U64 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u64 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 9);

        msg.extend((bytes.len() as u64).wrapping_add(adjust).to_le_bytes());
        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_LE32: FuncDef = func! (
    /// Prefix a buffer with a 32-bit little-endian length field
    ///
    /// Prepends a 4-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_le32(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U32 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u32 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u32).wrapping_add(adjust).to_le_bytes());
        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_LE16: FuncDef = func! (
    /// Prefix a buffer with a 16-bit little-endian length field
    ///
    /// Prepends a 2-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_le16(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U16 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u16 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 3);

        msg.extend((bytes.len() as u16).wrapping_add(adjust).to_le_bytes());
        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

static LEN_U8: FuncDef = func! (
    /// Prefix a buffer with an 8-bit byte length field
    ///
    /// Prepends a single byte encoding of `len(payload) + adjust` to the payload bytes.
    ///
    /// The length wraps around if it doesn\'t fit in the field.
    resynth fn len_u8(
        =>
        /// Adjustment value added to the computed length before encoding
        adjust: U8 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let adjust: u8 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.push((bytes.len() as u8).wrapping_add(adjust));

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

pub const MODULE: Module = module! {
    /// # Standard types
    ///
    /// Core type conversion and utility functions available in every resynth program.
    resynth mod std {
        be16 => Symbol::Func(&BE16),
        be32 => Symbol::Func(&BE32),
        be64 => Symbol::Func(&BE64),
        le16 => Symbol::Func(&LE16),
        le32 => Symbol::Func(&LE32),
        le64 => Symbol::Func(&LE64),
        u8 => Symbol::Func(&U8),

        len_be64 => Symbol::Func(&LEN_BE64),
        len_be32 => Symbol::Func(&LEN_BE32),
        len_be16 => Symbol::Func(&LEN_BE16),
        len_u8   => Symbol::Func(&LEN_U8),

        len_le64 => Symbol::Func(&LEN_LE64),
        len_le32 => Symbol::Func(&LEN_LE32),
        len_le16 => Symbol::Func(&LEN_LE16),
    }
};
