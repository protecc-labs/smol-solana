use {
    crate::{
        abi_example::{normalize_type_name, AbiEnumVisitor},
        hash::{Hash, Hasher},
    },
    log::*,
    serde::{
        ser::{Error as SerdeError, *},
        Serialize, Serializer,
    },
    std::{any::type_name, io::Write},
    thiserror::Error,
};

#[derive(Debug)]
pub struct AbiDigester {
    data_types: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    depth: usize,
    for_enum: bool,
    opaque_type_matcher: Option<String>,
}

pub type DigestResult = Result<AbiDigester, DigestError>;
type Sstr = &'static str;

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("Option::None is serialized; no ABI digest for Option::Some")]
    NoneIsSerialized,
    #[error("nested error")]
    Node(Sstr, Box<DigestError>),
    #[error("leaf error")]
    Leaf(Sstr, Sstr, Box<DigestError>),
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl SerdeError for DigestError {
    fn custom<T: std::fmt::Display>(msg: T) -> DigestError {
        panic!("Unexpected SerdeError: {msg}");
    }
}

impl DigestError {
    pub(crate) fn wrap_by_type<T: ?Sized>(e: DigestError) -> DigestError {
        DigestError::Node(type_name::<T>(), Box::new(e))
    }

    pub(crate) fn wrap_by_str(e: DigestError, s: Sstr) -> DigestError {
        DigestError::Node(s, Box::new(e))
    }
}

const INDENT_WIDTH: usize = 4;

pub(crate) fn shorten_serialize_with(type_name: &str) -> &str {
    // Fully qualified type names for the generated `__SerializeWith` types are very
    // long and do not add extra value to the digest. They also cause the digest
    // to change when a struct is moved to an inner module.
    if type_name.ends_with("__SerializeWith") {
        "__SerializeWith"
    } else {
        type_name
    }
}

impl AbiDigester {
    pub fn create() -> Self {
        AbiDigester {
            data_types: std::rc::Rc::new(std::cell::RefCell::new(vec![])),
            for_enum: false,
            depth: 0,
            opaque_type_matcher: None,
        }
    }

    // must create separate instances because we can't pass the single instance to
    // `.serialize()` multiple times
    pub fn create_new(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth,
            for_enum: false,
            opaque_type_matcher: self.opaque_type_matcher.clone(),
        }
    }

    pub fn create_new_opaque(&self, type_matcher: &str) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth,
            for_enum: false,
            opaque_type_matcher: Some(type_matcher.to_owned()),
        }
    }

    pub fn create_child(&self) -> Result<Self, DigestError> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(DigestError::ArithmeticOverflow)?;
        Ok(Self {
            data_types: self.data_types.clone(),
            depth,
            for_enum: false,
            opaque_type_matcher: self.opaque_type_matcher.clone(),
        })
    }

    pub fn create_enum_child(&self) -> Result<Self, DigestError> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(DigestError::ArithmeticOverflow)?;
        Ok(Self {
            data_types: self.data_types.clone(),
            depth,
            for_enum: true,
            opaque_type_matcher: self.opaque_type_matcher.clone(),
        })
    }

    pub fn digest_data<T: ?Sized + Serialize>(&mut self, value: &T) -> DigestResult {
        let type_name = normalize_type_name(type_name::<T>());
        if type_name.ends_with("__SerializeWith")
            || (self.opaque_type_matcher.is_some()
                && type_name.contains(self.opaque_type_matcher.as_ref().unwrap()))
        {
            // we can't use the AbiEnumVisitor trait for these cases.
            value.serialize(self.create_new())
        } else {
            // Don't call value.visit_for_abi(...) to prefer autoref specialization
            // resolution for IgnoreAsHelper
            <&T>::visit_for_abi(&value, &mut self.create_new())
        }
    }

    pub fn update(&mut self, strs: &[&str]) {
        let mut buf = strs
            .iter()
            .map(|s| {
                // this is a bit crude, but just normalize all strings as if they're
                // `type_name`s!
                normalize_type_name(s)
            })
            .collect::<Vec<_>>()
            .join(" ");
        buf = format!(
            "{:0width$}{}\n",
            "",
            buf,
            width = self.depth.saturating_mul(INDENT_WIDTH)
        );
        info!("updating with: {}", buf.trim_end());
        (*self.data_types.borrow_mut()).push(buf);
    }

    pub fn update_with_type<T: ?Sized>(&mut self, label: &str) {
        self.update(&[label, type_name::<T>()]);
    }

    pub fn update_with_string(&mut self, label: String) {
        self.update(&[&label]);
    }

    #[allow(clippy::unnecessary_wraps)]
    fn digest_primitive<T: Serialize>(mut self) -> Result<AbiDigester, DigestError> {
        self.update_with_type::<T>("primitive");
        Ok(self)
    }

    fn digest_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DigestError> {
        self.update_with_type::<T>("element");
        self.create_child()?.digest_data(v).map(|_| ())
    }

    fn digest_named_field<T: ?Sized + Serialize>(
        &mut self,
        key: Sstr,
        v: &T,
    ) -> Result<(), DigestError> {
        let field_type_name = shorten_serialize_with(type_name::<T>());
        self.update_with_string(format!("field {key}: {field_type_name}"));
        self.create_child()?
            .digest_data(v)
            .map(|_| ())
            .map_err(|e| DigestError::wrap_by_str(e, key))
    }

    fn digest_unnamed_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DigestError> {
        self.update_with_type::<T>("field");
        self.create_child()?.digest_data(v).map(|_| ())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn check_for_enum(
        &mut self,
        label: &'static str,
        variant: &'static str,
    ) -> Result<(), DigestError> {
        assert!(self.for_enum, "derive AbiEnumVisitor or implement it for the enum, which contains a variant ({label}) named {variant}");
        Ok(())
    }

    pub fn finalize(self) -> Hash {
        let mut hasher = Hasher::default();

        for buf in (*self.data_types.borrow()).iter() {
            hasher.hash(buf.as_bytes());
        }

        let hash = hasher.result();

        if let Ok(dir) = std::env::var("SOLANA_ABI_DUMP_DIR") {
            let thread_name = std::thread::current()
                .name()
                .unwrap_or("unknown-test-thread")
                .replace(':', "_");
            if thread_name == "main" {
                error!("Bad thread name detected for dumping; Maybe, --test-threads=1? Sorry, SOLANA_ABI_DUMP_DIR doesn't work under 1; increase it");
            }

            let path = format!("{dir}/{thread_name}_{hash}",);
            let mut file = std::fs::File::create(path).unwrap();
            for buf in (*self.data_types.borrow()).iter() {
                file.write_all(buf.as_bytes()).unwrap();
            }
            file.sync_data().unwrap();
        }

        hash
    }
}

impl Serializer for AbiDigester {
    type Ok = Self;
    type Error = DigestError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _data: bool) -> DigestResult {
        self.digest_primitive::<bool>()
    }

    fn serialize_i8(self, _data: i8) -> DigestResult {
        self.digest_primitive::<i8>()
    }

    fn serialize_i16(self, _data: i16) -> DigestResult {
        self.digest_primitive::<i16>()
    }

    fn serialize_i32(self, _data: i32) -> DigestResult {
        self.digest_primitive::<i32>()
    }

    fn serialize_i64(self, _data: i64) -> DigestResult {
        self.digest_primitive::<i64>()
    }

    fn serialize_i128(self, _data: i128) -> DigestResult {
        self.digest_primitive::<i128>()
    }

    fn serialize_u8(self, _data: u8) -> DigestResult {
        self.digest_primitive::<u8>()
    }

    fn serialize_u16(self, _data: u16) -> DigestResult {
        self.digest_primitive::<u16>()
    }

    fn serialize_u32(self, _data: u32) -> DigestResult {
        self.digest_primitive::<u32>()
    }

    fn serialize_u64(self, _data: u64) -> DigestResult {
        self.digest_primitive::<u64>()
    }

    fn serialize_u128(self, _data: u128) -> DigestResult {
        self.digest_primitive::<u128>()
    }

    fn serialize_f32(self, _data: f32) -> DigestResult {
        self.digest_primitive::<f32>()
    }

    fn serialize_f64(self, _data: f64) -> DigestResult {
        self.digest_primitive::<f64>()
    }

    fn serialize_char(self, _data: char) -> DigestResult {
        self.digest_primitive::<char>()
    }

    fn serialize_str(self, _data: &str) -> DigestResult {
        self.digest_primitive::<&str>()
    }

    fn serialize_unit(self) -> DigestResult {
        self.digest_primitive::<()>()
    }

    fn serialize_bytes(mut self, v: &[u8]) -> DigestResult {
        self.update_with_string(format!("bytes [u8] (len = {})", v.len()));
        Ok(self)
    }

    fn serialize_none(self) -> DigestResult {
        Err(DigestError::NoneIsSerialized)
    }

    fn serialize_some<T>(mut self, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        // emulate the ABI digest for the Option enum; see TestMyOption
        self.update(&["enum Option (variants = 2)"]);
        let mut variant_digester = self.create_child()?;

        variant_digester.update_with_string("variant(0) None (unit)".to_owned());
        variant_digester
            .update_with_string(format!("variant(1) Some({}) (newtype)", type_name::<T>()));
        variant_digester.create_child()?.digest_data(v)
    }

    fn serialize_unit_struct(mut self, name: Sstr) -> DigestResult {
        self.update(&["struct", name, "(unit)"]);
        Ok(self)
    }

    fn serialize_unit_variant(mut self, _name: Sstr, index: u32, variant: Sstr) -> DigestResult {
        self.check_for_enum("unit_variant", variant)?;
        self.update_with_string(format!("variant({index}) {variant} (unit)"));
        Ok(self)
    }

    fn serialize_newtype_struct<T>(mut self, name: Sstr, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update_with_string(format!("struct {}({}) (newtype)", name, type_name::<T>()));
        self.create_child()?
            .digest_data(v)
            .map_err(|e| DigestError::wrap_by_str(e, "newtype_struct"))
    }

    fn serialize_newtype_variant<T>(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        v: &T,
    ) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.check_for_enum("newtype_variant", variant)?;
        self.update_with_string(format!(
            "variant({}) {}({}) (newtype)",
            i,
            variant,
            type_name::<T>()
        ));
        self.create_child()?
            .digest_data(v)
            .map_err(|e| DigestError::wrap_by_str(e, "newtype_variant"))
    }

    fn serialize_seq(mut self, len: Option<usize>) -> DigestResult {
        let len = len.unwrap();
        assert_eq!(
            len, 1,
            "Exactly 1 seq element is needed to generate the ABI digest precisely"
        );
        self.update_with_string(format!("seq (elements = {len})"));
        self.create_child()
    }

    fn serialize_tuple(mut self, len: usize) -> DigestResult {
        self.update_with_string(format!("tuple (elements = {len})"));
        self.create_child()
    }

    fn serialize_tuple_struct(mut self, name: Sstr, len: usize) -> DigestResult {
        self.update_with_string(format!("struct {name} (fields = {len}) (tuple)"));
        self.create_child()
    }

    fn serialize_tuple_variant(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        len: usize,
    ) -> DigestResult {
        self.check_for_enum("tuple_variant", variant)?;
        self.update_with_string(format!("variant({i}) {variant} (fields = {len})"));
        self.create_child()
    }

    fn serialize_map(mut self, len: Option<usize>) -> DigestResult {
        let len = len.unwrap();
        assert_eq!(
            len, 1,
            "Exactly 1 map entry is needed to generate the ABI digest precisely"
        );
        self.update_with_string(format!("map (entries = {len})"));
        self.create_child()
    }

    fn serialize_struct(mut self, name: Sstr, len: usize) -> DigestResult {
        self.update_with_string(format!("struct {name} (fields = {len})"));
        self.create_child()
    }

    fn serialize_struct_variant(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        len: usize,
    ) -> DigestResult {
        self.check_for_enum("struct_variant", variant)?;
        self.update_with_string(format!("variant({i}) struct {variant} (fields = {len})"));
        self.create_child()
    }
}

impl SerializeSeq for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, data: &T) -> Result<(), DigestError> {
        self.digest_element(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeTuple for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, data: &T) -> Result<(), DigestError> {
        self.digest_element(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl SerializeTupleStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, data: &T) -> Result<(), DigestError> {
        self.digest_unnamed_field(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeTupleVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, data: &T) -> Result<(), DigestError> {
        self.digest_unnamed_field(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeMap for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), DigestError> {
        self.update_with_type::<T>("key");
        self.create_child()?.digest_data(key).map(|_| ())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), DigestError> {
        self.update_with_type::<T>("value");
        self.create_child()?.digest_data(value).map(|_| ())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: Sstr,
        data: &T,
    ) -> Result<(), DigestError> {
        self.digest_named_field(key, data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStructVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: Sstr,
        data: &T,
    ) -> Result<(), DigestError> {
        self.digest_named_field(key, data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
