use std::cmp::{max, min};
use std::ffi::{c_char, CStr};
use std::fmt;
use std::mem::size_of;

use object::{Object, ObjectSection};
use scroll::Pread;
use scroll_derive::{IOread, IOwrite, Pread as DerivePread, Pwrite, SizeWith};

use crate::{btf_error, BtfError, BtfResult};

pub const BTF_ELF_SEC: &str = ".BTF";
pub const BTF_EXT_ELF_SEC: &str = ".BTF.ext";

pub const BTF_MAGIC: u16 = 0xeB9F;
pub const BTF_VERSION: u8 = 1;

pub const BTF_KIND_UNKN: u32 = 0;
pub const BTF_KIND_INT: u32 = 1;
pub const BTF_KIND_PTR: u32 = 2;
pub const BTF_KIND_ARRAY: u32 = 3;
pub const BTF_KIND_STRUCT: u32 = 4;
pub const BTF_KIND_UNION: u32 = 5;
pub const BTF_KIND_ENUM: u32 = 6;
pub const BTF_KIND_FWD: u32 = 7;
pub const BTF_KIND_TYPEDEF: u32 = 8;
pub const BTF_KIND_VOLATILE: u32 = 9;
pub const BTF_KIND_CONST: u32 = 10;
pub const BTF_KIND_RESTRICT: u32 = 11;
pub const BTF_KIND_FUNC: u32 = 12;
pub const BTF_KIND_FUNC_PROTO: u32 = 13;
pub const BTF_KIND_VAR: u32 = 14;
pub const BTF_KIND_DATASEC: u32 = 15;
pub const BTF_KIND_FLOAT: u32 = 16;
pub const BTF_KIND_DECL_TAG: u32 = 17;
pub const BTF_KIND_TYPE_TAG: u32 = 18;
pub const BTF_KIND_ENUM64: u32 = 19;
pub const BTF_KIND_MAX: u32 = 19;
pub const NR_BTF_KINDS: u32 = BTF_KIND_MAX + 1;

pub const BTF_INT_SIGNED: u32 = 0b001;
pub const BTF_INT_CHAR: u32 = 0b010;
pub const BTF_INT_BOOL: u32 = 0b100;

pub const BTF_VAR_STATIC: u32 = 0;
pub const BTF_VAR_GLOBAL_ALLOCATED: u32 = 1;
pub const BTF_VAR_GLOBAL_EXTERNAL: u32 = 2;

pub const BTF_FUNC_STATIC: u32 = 0;
pub const BTF_FUNC_GLOBAL: u32 = 1;
pub const BTF_FUNC_EXTERN: u32 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_header {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_type {
    pub name_off: u32,
    pub info: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_enum {
    pub name_off: u32,
    pub val: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_array {
    pub val_type_id: u32,
    pub idx_type_id: u32,
    pub nelems: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_member {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_param {
    pub name_off: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_datasec_var {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_enum64 {
    pub name_off: u32,
    pub val_lo32: u32,
    pub val_hi32: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_min_header {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_header_v1 {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub func_info_off: u32,
    pub func_info_len: u32,
    pub line_info_off: u32,
    pub line_info_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_header_v2 {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub func_info_off: u32,
    pub func_info_len: u32,
    pub line_info_off: u32,
    pub line_info_len: u32,
    pub core_reloc_off: u32,
    pub core_reloc_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_info_sec {
    pub sec_name_off: u32,
    pub num_info: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_func_info {
    pub insn_off: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_line_info {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

pub const BTF_FIELD_BYTE_OFFSET: u32 = 0;
pub const BTF_FIELD_BYTE_SIZE: u32 = 1;
pub const BTF_FIELD_EXISTS: u32 = 2;
pub const BTF_FIELD_SIGNED: u32 = 3;
pub const BTF_FIELD_LSHIFT_U64: u32 = 4;
pub const BTF_FIELD_RSHIFT_U64: u32 = 5;
pub const BTF_TYPE_LOCAL_ID: u32 = 6;
pub const BTF_TYPE_TARGET_ID: u32 = 7;
pub const BTF_TYPE_EXISTS: u32 = 8;
pub const BTF_TYPE_SIZE: u32 = 9;
pub const BTF_ENUMVAL_EXISTS: u32 = 10;
pub const BTF_ENUMVAL_VALUE: u32 = 11;
pub const BTF_TYPE_MATCHES: u32 = 12;

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct btf_ext_core_reloc {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_spec_off: u32,
    pub kind: u32,
}

const EMPTY: &'static str = "";
const ANON_NAME: &'static str = "<anon>";

fn disp_name(s: &str) -> &str {
    if s == "" {
        ANON_NAME
    } else {
        s
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BtfIntEncoding {
    None,
    Signed,
    Char,
    Bool,
}

impl fmt::Display for BtfIntEncoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfIntEncoding::None => write!(f, "none"),
            BtfIntEncoding::Signed => write!(f, "signed"),
            BtfIntEncoding::Char => write!(f, "char"),
            BtfIntEncoding::Bool => write!(f, "bool"),
        }
    }
}

#[derive(Debug)]
pub struct BtfInt<'a> {
    pub name: &'a str,
    pub bits: u32,
    pub offset: u32,
    pub encoding: BtfIntEncoding,
}

impl<'a> fmt::Display for BtfInt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' bits:{} off:{}",
            "INT",
            disp_name(self.name),
            self.bits,
            self.offset
        )?;
        match self.encoding {
            BtfIntEncoding::None => (),
            _ => write!(f, " enc:{}", self.encoding)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BtfPtr {
    pub type_id: u32,
}

impl fmt::Display for BtfPtr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}> --> [{}]", "PTR", self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfArray {
    pub nelems: u32,
    pub idx_type_id: u32,
    pub val_type_id: u32,
}

impl fmt::Display for BtfArray {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> n:{} idx-->[{}] val-->[{}]",
            "ARRAY", self.nelems, self.idx_type_id, self.val_type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfMember<'a> {
    pub name: &'a str,
    pub type_id: u32,
    pub bit_offset: u32,
    pub bit_size: u8,
}

impl<'a> fmt::Display for BtfMember<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "'{}' off:{}", disp_name(self.name), self.bit_offset)?;
        if self.bit_size != 0 {
            write!(f, " sz:{}", self.bit_size)?;
        }
        write!(f, " --> [{}]", self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfComposite<'a> {
    pub is_struct: bool,
    pub name: &'a str,
    pub sz: u32,
    pub members: Vec<BtfMember<'a>>,
}

impl<'a> fmt::Display for BtfComposite<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' sz:{} n:{}",
            if self.is_struct { "STRUCT" } else { "UNION" },
            disp_name(self.name),
            self.sz,
            self.members.len()
        )?;
        for i in 0..self.members.len() {
            write!(f, "\n\t#{:02} {}", i, self.members[i])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BtfEnumValue<'a> {
    pub name: &'a str,
    pub value: i32,
}

impl<'a> fmt::Display for BtfEnumValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", disp_name(self.name), self.value)
    }
}

#[derive(Debug)]
pub struct BtfEnum<'a> {
    pub name: &'a str,
    pub sz: u32,
    pub values: Vec<BtfEnumValue<'a>>,
}

impl<'a> fmt::Display for BtfEnum<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' sz:{} n:{}",
            "ENUM",
            disp_name(self.name),
            self.sz,
            self.values.len()
        )?;
        for i in 0..self.values.len() {
            write!(f, "\n\t#{:02} {}", i, self.values[i])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BtfEnum64Value<'a> {
    pub name: &'a str,
    pub value: i64,
}

impl<'a> fmt::Display for BtfEnum64Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", disp_name(self.name), self.value)
    }
}

#[derive(Debug)]
pub struct BtfEnum64<'a> {
    pub name: &'a str,
    pub sz: u32,
    pub values: Vec<BtfEnum64Value<'a>>,
}

impl<'a> fmt::Display for BtfEnum64<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' sz:{} n:{}",
            "ENUM64",
            disp_name(self.name),
            self.sz,
            self.values.len()
        )?;
        for i in 0..self.values.len() {
            write!(f, "\n\t#{:02} {}", i, self.values[i])?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BtfFwdKind {
    Struct,
    Union,
}

impl fmt::Display for BtfFwdKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfFwdKind::Struct => write!(f, "struct"),
            BtfFwdKind::Union => write!(f, "union"),
        }
    }
}

#[derive(Debug)]
pub struct BtfFwd<'a> {
    pub name: &'a str,
    pub kind: BtfFwdKind,
}

impl<'a> fmt::Display for BtfFwd<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' kind:{}",
            "FWD",
            disp_name(self.name),
            self.kind
        )
    }
}

#[derive(Debug)]
pub struct BtfTypedef<'a> {
    pub name: &'a str,
    pub type_id: u32,
}

impl<'a> fmt::Display for BtfTypedef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' --> [{}]",
            "TYPEDEF",
            disp_name(self.name),
            self.type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfVolatile {
    pub type_id: u32,
}

impl fmt::Display for BtfVolatile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}> --> [{}]", "VOLATILE", self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfConst {
    pub type_id: u32,
}

impl fmt::Display for BtfConst {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}> --> [{}]", "CONST", self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfRestrict {
    pub type_id: u32,
}

impl fmt::Display for BtfRestrict {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}> --> [{}]", "RESTRICT", self.type_id)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BtfFuncKind {
    Unknown,
    Static,
    Global,
    Extern,
}

impl fmt::Display for BtfFuncKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfFuncKind::Unknown => write!(f, "<unknown>"),
            BtfFuncKind::Static => write!(f, "static"),
            BtfFuncKind::Global => write!(f, "global"),
            BtfFuncKind::Extern => write!(f, "extern"),
        }
    }
}

#[derive(Debug)]
pub struct BtfFunc<'a> {
    pub name: &'a str,
    pub proto_type_id: u32,
    pub kind: BtfFuncKind,
}

impl<'a> fmt::Display for BtfFunc<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' --> {} [{}]",
            "FUNC",
            disp_name(self.name),
            self.kind,
            self.proto_type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfFuncParam<'a> {
    pub name: &'a str,
    pub type_id: u32,
}

impl<'a> fmt::Display for BtfFuncParam<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "'{}' --> [{}]", disp_name(self.name), self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfFuncProto<'a> {
    pub res_type_id: u32,
    pub params: Vec<BtfFuncParam<'a>>,
}

impl<'a> fmt::Display for BtfFuncProto<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> r-->[{}] n:{}",
            "FUNC_PROTO",
            self.res_type_id,
            self.params.len()
        )?;
        for i in 0..self.params.len() {
            write!(f, "\n\t#{:02} {}", i, self.params[i])?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BtfVarKind {
    Static,
    GlobalAlloc,
    GlobalExtern,
}

impl fmt::Display for BtfVarKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfVarKind::Static => write!(f, "static"),
            BtfVarKind::GlobalAlloc => write!(f, "global-alloc"),
            BtfVarKind::GlobalExtern => write!(f, "global-extern"),
        }
    }
}

#[derive(Debug)]
pub struct BtfVar<'a> {
    pub name: &'a str,
    pub type_id: u32,
    pub kind: BtfVarKind,
}

impl<'a> fmt::Display for BtfVar<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' kind:{} --> [{}]",
            "VAR",
            disp_name(self.name),
            self.kind,
            self.type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfDatasecVar {
    pub type_id: u32,
    pub offset: u32,
    pub sz: u32,
}

impl fmt::Display for BtfDatasecVar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "off:{} sz:{} --> [{}]",
            self.offset, self.sz, self.type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfDatasec<'a> {
    pub name: &'a str,
    pub sz: u32,
    pub vars: Vec<BtfDatasecVar>,
}

impl<'a> fmt::Display for BtfDatasec<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' sz:{} n:{}",
            "DATASEC",
            disp_name(self.name),
            self.sz,
            self.vars.len()
        )?;
        for i in 0..self.vars.len() {
            write!(f, "\n\t#{:02} {}", i, self.vars[i])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BtfFloat<'a> {
    pub name: &'a str,
    pub sz: u32,
}

impl<'a> fmt::Display for BtfFloat<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}> '{}' sz:{}", "FLOAT", disp_name(self.name), self.sz)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BtfDeclTag<'a> {
    pub name: &'a str,
    pub type_id: u32,
    pub comp_idx: u32,
}

impl<'a> fmt::Display for BtfDeclTag<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' --> [{}] comp_idx:{}",
            "DECL_TAG",
            disp_name(self.name),
            self.type_id,
            self.comp_idx,
        )
    }
}

#[derive(Debug)]
pub struct BtfTypeTag<'a> {
    pub name: &'a str,
    pub type_id: u32,
}

impl<'a> fmt::Display for BtfTypeTag<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<{}> '{}' --> [{}]",
            "TYPE_TAG",
            disp_name(self.name),
            self.type_id
        )
    }
}

#[derive(Debug)]
pub enum BtfType<'a> {
    Void,
    Int(BtfInt<'a>),
    Ptr(BtfPtr),
    Array(BtfArray),
    Struct(BtfComposite<'a>),
    Union(BtfComposite<'a>),
    Enum(BtfEnum<'a>),
    Fwd(BtfFwd<'a>),
    Typedef(BtfTypedef<'a>),
    Volatile(BtfVolatile),
    Const(BtfConst),
    Restrict(BtfRestrict),
    Func(BtfFunc<'a>),
    FuncProto(BtfFuncProto<'a>),
    Var(BtfVar<'a>),
    Datasec(BtfDatasec<'a>),
    Float(BtfFloat<'a>),
    DeclTag(BtfDeclTag<'a>),
    TypeTag(BtfTypeTag<'a>),
    Enum64(BtfEnum64<'a>),
}

impl<'a> fmt::Display for BtfType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfType::Void => write!(f, "<{}>", "VOID"),
            BtfType::Int(t) => t.fmt(f),
            BtfType::Ptr(t) => t.fmt(f),
            BtfType::Array(t) => t.fmt(f),
            BtfType::Struct(t) => t.fmt(f),
            BtfType::Union(t) => t.fmt(f),
            BtfType::Enum(t) => t.fmt(f),
            BtfType::Fwd(t) => t.fmt(f),
            BtfType::Typedef(t) => t.fmt(f),
            BtfType::Volatile(t) => t.fmt(f),
            BtfType::Const(t) => t.fmt(f),
            BtfType::Restrict(t) => t.fmt(f),
            BtfType::Func(t) => t.fmt(f),
            BtfType::FuncProto(t) => t.fmt(f),
            BtfType::Var(t) => t.fmt(f),
            BtfType::Datasec(t) => t.fmt(f),
            BtfType::Float(t) => t.fmt(f),
            BtfType::DeclTag(t) => t.fmt(f),
            BtfType::TypeTag(t) => t.fmt(f),
            BtfType::Enum64(t) => t.fmt(f),
        }
    }
}

impl<'a> BtfType<'a> {
    pub fn kind(&self) -> BtfKind {
        match self {
            BtfType::Void => BtfKind::Void,
            BtfType::Int(_) => BtfKind::Int,
            BtfType::Ptr(_) => BtfKind::Ptr,
            BtfType::Array(_) => BtfKind::Array,
            BtfType::Struct(_) => BtfKind::Struct,
            BtfType::Union(_) => BtfKind::Union,
            BtfType::Enum(_) => BtfKind::Enum,
            BtfType::Fwd(_) => BtfKind::Fwd,
            BtfType::Typedef(_) => BtfKind::Typedef,
            BtfType::Volatile(_) => BtfKind::Volatile,
            BtfType::Const(_) => BtfKind::Const,
            BtfType::Restrict(_) => BtfKind::Restrict,
            BtfType::Func(_) => BtfKind::Func,
            BtfType::FuncProto(_) => BtfKind::FuncProto,
            BtfType::Var(_) => BtfKind::Var,
            BtfType::Datasec(_) => BtfKind::Datasec,
            BtfType::Float(_) => BtfKind::Float,
            BtfType::DeclTag(_) => BtfKind::DeclTag,
            BtfType::TypeTag(_) => BtfKind::TypeTag,
            BtfType::Enum64(_) => BtfKind::Enum64,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            BtfType::Void => EMPTY,
            BtfType::Int(t) => &t.name,
            BtfType::Ptr(_) => EMPTY,
            BtfType::Array(_) => EMPTY,
            BtfType::Struct(t) => &t.name,
            BtfType::Union(t) => &t.name,
            BtfType::Enum(t) => &t.name,
            BtfType::Fwd(t) => &t.name,
            BtfType::Typedef(t) => &t.name,
            BtfType::Volatile(_) => EMPTY,
            BtfType::Const(_) => EMPTY,
            BtfType::Restrict(_) => EMPTY,
            BtfType::Func(t) => &t.name,
            BtfType::FuncProto(_) => EMPTY,
            BtfType::Var(t) => &t.name,
            BtfType::Datasec(t) => &t.name,
            BtfType::Float(t) => &t.name,
            BtfType::DeclTag(t) => &t.name,
            BtfType::TypeTag(t) => &t.name,
            BtfType::Enum64(t) => &t.name,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum BtfKind {
    Void,
    Int,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Func,
    FuncProto,
    Var,
    Datasec,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
}

impl std::str::FromStr for BtfKind {
    type Err = BtfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "void" => Ok(BtfKind::Void),
            "int" | "i" => Ok(BtfKind::Int),
            "ptr" | "p" => Ok(BtfKind::Ptr),
            "array" | "arr" | "a" => Ok(BtfKind::Array),
            "struct" | "s" => Ok(BtfKind::Struct),
            "union" | "u" => Ok(BtfKind::Union),
            "enum" | "e" => Ok(BtfKind::Enum),
            "fwd" => Ok(BtfKind::Fwd),
            "typedef" | "t" => Ok(BtfKind::Typedef),
            "volatile" => Ok(BtfKind::Volatile),
            "const" => Ok(BtfKind::Const),
            "restrict" => Ok(BtfKind::Restrict),
            "func_proto" | "funcproto" | "fnproto" | "fp" => Ok(BtfKind::FuncProto),
            "func" | "fn" => Ok(BtfKind::Func),
            "var" | "v" => Ok(BtfKind::Var),
            "datasec" => Ok(BtfKind::Datasec),
            "float" => Ok(BtfKind::Float),
            "decl_tag" => Ok(BtfKind::DeclTag),
            "type_tag" => Ok(BtfKind::TypeTag),
            "enum64" | "e64" => Ok(BtfKind::Enum64),
            _ => Err(BtfError::new_owned(format!(
                "unrecognized btf kind: '{}'",
                s
            ))),
        }
    }
}

#[derive(Debug)]
pub struct BtfExtSection<'a, T> {
    pub name: &'a str,
    pub rec_sz: usize,
    pub recs: Vec<T>,
}

#[derive(Debug)]
pub struct BtfExtFunc {
    pub insn_off: u32,
    pub type_id: u32,
}

impl fmt::Display for BtfExtFunc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "func: insn #{} --> [{}]",
            self.insn_off / 8,
            self.type_id
        )
    }
}

#[derive(Debug)]
pub struct BtfExtLine<'a> {
    pub insn_off: u32,
    pub file_name: &'a str,
    pub src_line: &'a str,
    pub line_num: u32,
    pub col_num: u32,
}

impl<'a> fmt::Display for BtfExtLine<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "line: insn #{} --> {}:{} @ {}\n\t{}",
            self.insn_off / 8,
            self.line_num,
            self.col_num,
            self.file_name,
            self.src_line
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BtfCoreRelocKind {
    ByteOff = 0,
    ByteSz = 1,
    FieldExists = 2,
    Signed = 3,
    LShiftU64 = 4,
    RShiftU64 = 5,
    LocalTypeId = 6,
    TargetTypeId = 7,
    TypeExists = 8,
    TypeSize = 9,
    EnumvalExists = 10,
    EnumvalValue = 11,
    TypeMatches = 12,
}

impl fmt::Display for BtfCoreRelocKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfCoreRelocKind::ByteOff => write!(f, "byte_off"),
            BtfCoreRelocKind::ByteSz => write!(f, "byte_sz"),
            BtfCoreRelocKind::FieldExists => write!(f, "field_exists"),
            BtfCoreRelocKind::Signed => write!(f, "signed"),
            BtfCoreRelocKind::LShiftU64 => write!(f, "lshift_u64"),
            BtfCoreRelocKind::RShiftU64 => write!(f, "rshift_u64"),
            BtfCoreRelocKind::LocalTypeId => write!(f, "local_type_id"),
            BtfCoreRelocKind::TargetTypeId => write!(f, "target_type_id"),
            BtfCoreRelocKind::TypeExists => write!(f, "type_exists"),
            BtfCoreRelocKind::TypeMatches => write!(f, "type_matches"),
            BtfCoreRelocKind::TypeSize => write!(f, "type_size"),
            BtfCoreRelocKind::EnumvalExists => write!(f, "enumval_exists"),
            BtfCoreRelocKind::EnumvalValue => write!(f, "enumval_value"),
        }
    }
}

#[derive(Debug)]
pub struct BtfExtCoreReloc<'a> {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_spec_str: &'a str,
    pub access_spec: Vec<usize>,
    pub kind: BtfCoreRelocKind,
}

impl<'a> fmt::Display for BtfExtCoreReloc<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "core_reloc: insn #{} --> [{}] + {}: {}",
            self.insn_off / 8,
            self.type_id,
            self.access_spec_str,
            self.kind,
        )
    }
}

#[derive(Debug)]
pub struct Btf<'a> {
    endian: scroll::Endian,
    types: Vec<BtfType<'a>>,
    ptr_sz: u32,

    // .BTF.ext stuff
    has_ext: bool,
    func_secs: Vec<BtfExtSection<'a, BtfExtFunc>>,
    line_secs: Vec<BtfExtSection<'a, BtfExtLine<'a>>>,
    core_reloc_secs: Vec<BtfExtSection<'a, BtfExtCoreReloc<'a>>>,
}

impl<'a> Btf<'a> {
    pub fn ptr_sz(&self) -> u32 {
        self.ptr_sz
    }

    pub fn types(&self) -> &[BtfType] {
        &self.types
    }

    pub fn type_by_id(&self, type_id: u32) -> &BtfType {
        &self.types[type_id as usize]
    }

    pub fn type_cnt(&self) -> u32 {
        self.types.len() as u32
    }

    pub fn has_ext(&self) -> bool {
        self.has_ext
    }

    pub fn func_secs(&self) -> &[BtfExtSection<BtfExtFunc>] {
        &self.func_secs
    }

    pub fn line_secs(&self) -> &[BtfExtSection<BtfExtLine>] {
        &self.line_secs
    }

    pub fn core_reloc_secs(&self) -> &[BtfExtSection<BtfExtCoreReloc>] {
        &self.core_reloc_secs
    }

    pub fn get_size_of(&self, type_id: u32) -> u32 {
        match self.type_by_id(type_id) {
            BtfType::Void => 0,
            BtfType::Int(t) => (t.bits + 7) / 8,
            BtfType::Volatile(t) => self.get_size_of(t.type_id),
            BtfType::Const(t) => self.get_size_of(t.type_id),
            BtfType::Restrict(t) => self.get_size_of(t.type_id),
            BtfType::Ptr(_) => self.ptr_sz,
            BtfType::Array(t) => t.nelems * self.get_size_of(t.val_type_id),
            BtfType::FuncProto(_) => 0,
            BtfType::Struct(t) => t.sz,
            BtfType::Union(t) => t.sz,
            BtfType::Enum(t) => t.sz,
            BtfType::Fwd(_) => 0,
            BtfType::Typedef(t) => self.get_size_of(t.type_id),
            BtfType::Func(_) => 0,
            BtfType::Var(_) => 0,
            BtfType::Datasec(t) => t.sz,
            BtfType::Float(t) => t.sz,
            BtfType::DeclTag(t) => self.get_size_of(t.type_id),
            BtfType::TypeTag(t) => self.get_size_of(t.type_id),
            BtfType::Enum64(t) => t.sz,
        }
    }

    pub fn get_align_of(&self, type_id: u32) -> u32 {
        match self.type_by_id(type_id) {
            BtfType::Void => 0,
            BtfType::Int(t) => min(self.ptr_sz, (t.bits + 7) / 8),
            BtfType::Volatile(t) => self.get_align_of(t.type_id),
            BtfType::Const(t) => self.get_align_of(t.type_id),
            BtfType::Restrict(t) => self.get_align_of(t.type_id),
            BtfType::Ptr(_) => self.ptr_sz,
            BtfType::Array(t) => self.get_align_of(t.val_type_id),
            BtfType::FuncProto(_) => 0,
            BtfType::Struct(t) => {
                let mut align = 1;
                for m in &t.members {
                    align = max(align, self.get_align_of(m.type_id));
                }
                align
            }
            BtfType::Union(t) => {
                let mut align = 1;
                for m in &t.members {
                    align = max(align, self.get_align_of(m.type_id));
                }
                align
            }
            BtfType::Enum(t) => min(self.ptr_sz, t.sz),
            BtfType::Fwd(_) => 0,
            BtfType::Typedef(t) => self.get_align_of(t.type_id),
            BtfType::Func(_) => 0,
            BtfType::Var(_) => 0,
            BtfType::Datasec(_) => 0,
            BtfType::Float(t) => min(self.ptr_sz, t.sz),
            BtfType::DeclTag(_) => 0,
            BtfType::TypeTag(t) => self.get_align_of(t.type_id),
            BtfType::Enum64(t) => min(self.ptr_sz, t.sz),
        }
    }

    pub fn skip_mods(&self, mut type_id: u32) -> u32 {
        loop {
            match self.type_by_id(type_id) {
                BtfType::Volatile(t) => type_id = t.type_id,
                BtfType::Const(t) => type_id = t.type_id,
                BtfType::Restrict(t) => type_id = t.type_id,
                BtfType::TypeTag(t) => type_id = t.type_id,
                _ => return type_id,
            }
        }
    }

    pub fn skip_mods_and_typedefs(&self, mut type_id: u32) -> u32 {
        loop {
            match self.type_by_id(type_id) {
                BtfType::Volatile(t) => type_id = t.type_id,
                BtfType::Const(t) => type_id = t.type_id,
                BtfType::Restrict(t) => type_id = t.type_id,
                BtfType::Typedef(t) => type_id = t.type_id,
                BtfType::TypeTag(t) => type_id = t.type_id,
                _ => return type_id,
            }
        }
    }

    pub fn load(elf: &object::File<'a>) -> BtfResult<Btf<'a>> {
        let endian = if elf.is_little_endian() {
            scroll::LE
        } else {
            scroll::BE
        };
        let mut btf = Btf::<'a> {
            endian: endian,
            ptr_sz: if elf.is_64() { 8 } else { 4 },
            types: vec![BtfType::Void],
            has_ext: false,
            func_secs: Vec::new(),
            line_secs: Vec::new(),
            core_reloc_secs: Vec::new(),
        };

        let btf_section = elf
            .section_by_name(BTF_ELF_SEC)
            .ok_or_else(|| Box::new(BtfError::new("No .BTF section found!")))?;
        let data = match btf_section.data() {
            Ok(d) => d,
            _ => panic!("expected borrowed data"),
        };
        let hdr = data.pread_with::<btf_header>(0, endian)?;
        if hdr.magic != BTF_MAGIC {
            return btf_error(format!("Invalid BTF magic: {}", hdr.magic));
        }
        if hdr.version != BTF_VERSION {
            return btf_error(format!(
                "Unsupported BTF version: {}, expect: {}",
                hdr.version, BTF_VERSION
            ));
        }

        let str_off = (hdr.hdr_len + hdr.str_off) as usize;
        let str_data = &data[str_off..str_off + hdr.str_len as usize];

        let type_off = (hdr.hdr_len + hdr.type_off) as usize;
        let type_data = &data[type_off..type_off + hdr.type_len as usize];
        let mut off: usize = 0;
        while off < hdr.type_len as usize {
            let t = btf.load_type(&type_data[off..], str_data)?;
            off += Btf::type_size(&t);
            btf.types.push(t);
        }

        if let Some(ext_section) = elf.section_by_name(BTF_EXT_ELF_SEC) {
            btf.has_ext = true;
            let ext_data = match ext_section.data() {
                Ok(d) => d,
                _ => panic!("expected borrowed data"),
            };
            let ext_hdr = ext_data.pread_with::<btf_ext_header_v1>(0, endian)?;
            if ext_hdr.magic != BTF_MAGIC {
                return btf_error(format!("Invalid .BTF.ext magic: {}", ext_hdr.magic));
            }
            if ext_hdr.version != BTF_VERSION {
                return btf_error(format!(
                    "Unsupported .BTF.ext version: {}, expect: {}",
                    ext_hdr.version, BTF_VERSION
                ));
            }
            let ext_hdr2 = if ext_hdr.hdr_len >= size_of::<btf_ext_header_v2>() as u32 {
                Some(ext_data.pread_with::<btf_ext_header_v2>(0, endian)?)
            } else {
                None
            };
            if ext_hdr.func_info_len > 0 {
                let func_off = (ext_hdr.hdr_len + ext_hdr.func_info_off) as usize;
                let func_data = &ext_data[func_off..func_off + ext_hdr.func_info_len as usize];
                btf.func_secs = btf.load_func_secs(func_data, str_data)?;
            }
            if ext_hdr.line_info_len > 0 {
                let line_off = (ext_hdr.hdr_len + ext_hdr.line_info_off) as usize;
                let line_data = &ext_data[line_off..line_off + ext_hdr.line_info_len as usize];
                btf.line_secs = btf.load_line_secs(line_data, str_data)?;
            }
            if let Some(h) = ext_hdr2 {
                if h.core_reloc_len > 0 {
                    let reloc_off = (h.hdr_len + h.core_reloc_off) as usize;
                    let reloc_data = &ext_data[reloc_off..reloc_off + h.core_reloc_len as usize];
                    btf.core_reloc_secs = btf.load_core_reloc_secs(reloc_data, str_data)?;
                }
            }
        }

        Ok(btf)
    }

    pub fn type_size(t: &BtfType) -> usize {
        let common = size_of::<btf_type>();
        match t {
            BtfType::Void => 0,
            BtfType::Ptr(_)
            | BtfType::Fwd(_)
            | BtfType::Typedef(_)
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Func(_)
            | BtfType::Float(_)
            | BtfType::TypeTag(_) => common,
            BtfType::Int(_) | BtfType::Var(_) | BtfType::DeclTag(_) => common + size_of::<u32>(),
            BtfType::Array(_) => common + size_of::<btf_array>(),
            BtfType::Struct(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Union(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Enum(t) => common + t.values.len() * size_of::<btf_enum>(),
            BtfType::Enum64(t) => common + t.values.len() * size_of::<btf_enum64>(),
            BtfType::FuncProto(t) => common + t.params.len() * size_of::<btf_param>(),
            BtfType::Datasec(t) => common + t.vars.len() * size_of::<btf_datasec_var>(),
        }
    }

    fn load_type(&self, data: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let t = data.pread_with::<btf_type>(0, self.endian)?;
        let extra = &data[size_of::<btf_type>()..];
        let kind = Btf::get_kind(t.info);
        match kind {
            BTF_KIND_INT => self.load_int(&t, extra, strs),
            BTF_KIND_PTR => Ok(BtfType::Ptr(BtfPtr { type_id: t.type_id })),
            BTF_KIND_ARRAY => self.load_array(extra),
            BTF_KIND_STRUCT => self.load_struct(&t, extra, strs),
            BTF_KIND_UNION => self.load_union(&t, extra, strs),
            BTF_KIND_ENUM => self.load_enum(&t, extra, strs),
            BTF_KIND_FWD => self.load_fwd(&t, strs),
            BTF_KIND_TYPEDEF => Ok(BtfType::Typedef(BtfTypedef {
                name: Btf::get_btf_str(strs, t.name_off)?,
                type_id: t.type_id,
            })),
            BTF_KIND_VOLATILE => Ok(BtfType::Volatile(BtfVolatile { type_id: t.type_id })),
            BTF_KIND_CONST => Ok(BtfType::Const(BtfConst { type_id: t.type_id })),
            BTF_KIND_RESTRICT => Ok(BtfType::Restrict(BtfRestrict { type_id: t.type_id })),
            BTF_KIND_FUNC => Ok(BtfType::Func(BtfFunc {
                name: Btf::get_btf_str(strs, t.name_off)?,
                proto_type_id: t.type_id,
                kind: match Btf::get_vlen(t.info) {
                    BTF_FUNC_STATIC => BtfFuncKind::Static,
                    BTF_FUNC_GLOBAL => BtfFuncKind::Global,
                    BTF_FUNC_EXTERN => BtfFuncKind::Extern,
                    _ => BtfFuncKind::Unknown,
                },
            })),
            BTF_KIND_FUNC_PROTO => self.load_func_proto(&t, extra, strs),
            BTF_KIND_VAR => self.load_var(&t, extra, strs),
            BTF_KIND_DATASEC => self.load_datasec(&t, extra, strs),
            BTF_KIND_FLOAT => Ok(BtfType::Float(BtfFloat {
                name: Btf::get_btf_str(strs, t.name_off)?,
                sz: t.type_id,
            })),
            BTF_KIND_DECL_TAG => self.load_decl_tag(&t, extra, strs),
            BTF_KIND_TYPE_TAG => Ok(BtfType::TypeTag(BtfTypeTag {
                name: Btf::get_btf_str(strs, t.name_off)?,
                type_id: t.type_id,
            })),
            BTF_KIND_ENUM64 => self.load_enum64(&t, extra, strs),
            _ => btf_error(format!("Unknown BTF kind: {}", kind)),
        }
    }

    fn load_int(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let info = extra.pread_with::<u32>(0, self.endian)?;
        let enc = (info >> 24) & 0xf;
        let off = (info >> 16) & 0xff;
        let bits = info & 0xff;
        Ok(BtfType::Int(BtfInt {
            name: Btf::get_btf_str(strs, t.name_off)?,
            bits: bits,
            offset: off,
            encoding: match enc {
                0 => BtfIntEncoding::None,
                BTF_INT_SIGNED => BtfIntEncoding::Signed,
                BTF_INT_CHAR => BtfIntEncoding::Char,
                BTF_INT_BOOL => BtfIntEncoding::Bool,
                _ => {
                    return btf_error(format!("Unknown BTF int encoding: {}", enc));
                }
            },
        }))
    }

    fn load_array(&self, extra: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let info = extra.pread_with::<btf_array>(0, self.endian)?;
        Ok(BtfType::Array(BtfArray {
            nelems: info.nelems,
            idx_type_id: info.idx_type_id,
            val_type_id: info.val_type_id,
        }))
    }

    fn load_struct(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        Ok(BtfType::Struct(BtfComposite {
            is_struct: true,
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            members: self.load_members(t, extra, strs)?,
        }))
    }

    fn load_union(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        Ok(BtfType::Union(BtfComposite {
            is_struct: false,
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            members: self.load_members(t, extra, strs)?,
        }))
    }

    fn load_members(
        &self,
        t: &btf_type,
        extra: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<Vec<BtfMember<'a>>> {
        let mut res = Vec::new();
        let mut off: usize = 0;
        let bits = Btf::get_kind_flag(t.info);

        for _ in 0..Btf::get_vlen(t.info) {
            let m = extra.pread_with::<btf_member>(off, self.endian)?;
            res.push(BtfMember {
                name: Btf::get_btf_str(strs, m.name_off)?,
                type_id: m.type_id,
                bit_size: if bits { (m.offset >> 24) as u8 } else { 0 },
                bit_offset: if bits { m.offset & 0xffffff } else { m.offset },
            });
            off += size_of::<btf_member>();
        }
        Ok(res)
    }

    fn load_enum(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let mut vals = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread_with::<btf_enum>(off, self.endian)?;
            vals.push(BtfEnumValue {
                name: Btf::get_btf_str(strs, v.name_off)?,
                value: v.val,
            });
            off += size_of::<btf_enum>();
        }
        Ok(BtfType::Enum(BtfEnum {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            values: vals,
        }))
    }

    fn load_enum64(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let mut vals = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread_with::<btf_enum64>(off, self.endian)?;
            vals.push(BtfEnum64Value {
                name: Btf::get_btf_str(strs, v.name_off)?,
                value: i64::from(v.val_lo32) + i64::from(v.val_hi32) << 32,
            });
            off += size_of::<btf_enum64>();
        }
        Ok(BtfType::Enum64(BtfEnum64 {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            values: vals,
        }))
    }

    fn load_fwd(&self, t: &btf_type, strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        Ok(BtfType::Fwd(BtfFwd {
            name: Btf::get_btf_str(strs, t.name_off)?,
            kind: if Btf::get_kind_flag(t.info) {
                BtfFwdKind::Union
            } else {
                BtfFwdKind::Struct
            },
        }))
    }

    fn load_func_proto(
        &self,
        t: &btf_type,
        extra: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<BtfType<'a>> {
        let mut params = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let p = extra.pread_with::<btf_param>(off, self.endian)?;
            params.push(BtfFuncParam {
                name: Btf::get_btf_str(strs, p.name_off)?,
                type_id: p.type_id,
            });
            off += size_of::<btf_param>();
        }
        Ok(BtfType::FuncProto(BtfFuncProto {
            res_type_id: t.type_id,
            params: params,
        }))
    }

    fn load_var(&self, t: &btf_type, extra: &'a [u8], strs: &'a [u8]) -> BtfResult<BtfType<'a>> {
        let kind = extra.pread_with::<u32>(0, self.endian)?;
        Ok(BtfType::Var(BtfVar {
            name: Btf::get_btf_str(strs, t.name_off)?,
            type_id: t.type_id,
            kind: match kind {
                BTF_VAR_STATIC => BtfVarKind::Static,
                BTF_VAR_GLOBAL_ALLOCATED => BtfVarKind::GlobalAlloc,
                BTF_VAR_GLOBAL_EXTERNAL => BtfVarKind::GlobalExtern,
                _ => {
                    return btf_error(format!("Unknown BTF var kind: {}", kind));
                }
            },
        }))
    }

    fn load_datasec(
        &self,
        t: &btf_type,
        extra: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<BtfType<'a>> {
        let mut vars = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread_with::<btf_datasec_var>(off, self.endian)?;
            vars.push(BtfDatasecVar {
                type_id: v.type_id,
                offset: v.offset,
                sz: v.size,
            });
            off += size_of::<btf_datasec_var>();
        }
        Ok(BtfType::Datasec(BtfDatasec {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            vars: vars,
        }))
    }

    fn load_decl_tag(
        &self,
        t: &btf_type,
        extra: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<BtfType<'a>> {
        let comp_idx = extra.pread_with::<u32>(0, self.endian)?;
        Ok(BtfType::DeclTag(BtfDeclTag {
            name: Btf::get_btf_str(strs, t.name_off)?,
            type_id: t.type_id,
            comp_idx: comp_idx,
        }))
    }

    fn get_vlen(info: u32) -> u32 {
        info & 0xffff
    }

    fn get_kind(info: u32) -> u32 {
        (info >> 24) & 0x1f
    }

    fn get_kind_flag(info: u32) -> bool {
        (info >> 31) == 1
    }

    fn load_func_secs(
        &self,
        mut data: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<Vec<BtfExtSection<'a, BtfExtFunc>>> {
        let rec_sz = data.pread_with::<u32>(0, self.endian)?;
        if rec_sz < size_of::<btf_ext_func_info>() as u32 {
            return btf_error(format!(
                "Too small func info record size: {}, expect at least: {}",
                rec_sz,
                size_of::<btf_ext_func_info>()
            ));
        }

        data = &data[size_of::<u32>()..];
        let mut secs = Vec::new();
        while !data.is_empty() {
            let sec_hdr = data.pread_with::<btf_ext_info_sec>(0, self.endian)?;
            data = &data[size_of::<btf_ext_info_sec>()..];

            let mut recs = Vec::new();
            for i in 0..sec_hdr.num_info {
                let off = (i * rec_sz) as usize;
                let rec = data.pread_with::<btf_ext_func_info>(off, self.endian)?;
                recs.push(BtfExtFunc {
                    insn_off: rec.insn_off,
                    type_id: rec.type_id,
                });
            }
            secs.push(BtfExtSection::<BtfExtFunc> {
                name: Btf::get_btf_str(strs, sec_hdr.sec_name_off)?,
                rec_sz: rec_sz as usize,
                recs: recs,
            });

            data = &data[(sec_hdr.num_info * rec_sz) as usize..];
        }
        Ok(secs)
    }

    fn load_line_secs(
        &self,
        mut data: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<Vec<BtfExtSection<'a, BtfExtLine<'a>>>> {
        let rec_sz = data.pread_with::<u32>(0, self.endian)?;
        if rec_sz < size_of::<btf_ext_line_info>() as u32 {
            return btf_error(format!(
                "Too small line info record size: {}, expect at least: {}",
                rec_sz,
                size_of::<btf_ext_line_info>()
            ));
        }
        data = &data[size_of::<u32>()..];
        let mut secs = Vec::new();
        while !data.is_empty() {
            let sec_hdr = data.pread_with::<btf_ext_info_sec>(0, self.endian)?;
            data = &data[size_of::<btf_ext_info_sec>()..];

            let mut recs = Vec::new();
            for i in 0..sec_hdr.num_info {
                let off = (i * rec_sz) as usize;
                let rec = data.pread_with::<btf_ext_line_info>(off, self.endian)?;
                recs.push(BtfExtLine {
                    insn_off: rec.insn_off,
                    file_name: Btf::get_btf_str(strs, rec.file_name_off)?,
                    src_line: Btf::get_btf_str(strs, rec.line_off)?,
                    line_num: rec.line_col >> 10,
                    col_num: rec.line_col & 0x3ff,
                });
            }
            secs.push(BtfExtSection::<BtfExtLine> {
                name: Btf::get_btf_str(strs, sec_hdr.sec_name_off)?,
                rec_sz: rec_sz as usize,
                recs: recs,
            });

            data = &data[(sec_hdr.num_info * rec_sz) as usize..];
        }
        Ok(secs)
    }

    fn load_core_reloc_secs(
        &self,
        mut data: &'a [u8],
        strs: &'a [u8],
    ) -> BtfResult<Vec<BtfExtSection<'a, BtfExtCoreReloc<'a>>>> {
        let rec_sz = data.pread_with::<u32>(0, self.endian)?;
        if rec_sz < size_of::<btf_ext_core_reloc>() as u32 {
            return btf_error(format!(
                "Too small CO-RE reloc record size: {}, expect at least: {}",
                rec_sz,
                size_of::<btf_ext_core_reloc>()
            ));
        }
        data = &data[size_of::<u32>()..];
        let mut secs = Vec::new();
        while !data.is_empty() {
            let sec_hdr = data.pread_with::<btf_ext_info_sec>(0, self.endian)?;
            data = &data[size_of::<btf_ext_info_sec>()..];

            let mut recs = Vec::new();
            for i in 0..sec_hdr.num_info {
                let off = (i * rec_sz) as usize;
                let rec = data.pread_with::<btf_ext_core_reloc>(off, self.endian)?;
                let kind = match rec.kind {
                    BTF_FIELD_BYTE_OFFSET => BtfCoreRelocKind::ByteOff,
                    BTF_FIELD_BYTE_SIZE => BtfCoreRelocKind::ByteSz,
                    BTF_FIELD_EXISTS => BtfCoreRelocKind::FieldExists,
                    BTF_FIELD_SIGNED => BtfCoreRelocKind::Signed,
                    BTF_FIELD_LSHIFT_U64 => BtfCoreRelocKind::LShiftU64,
                    BTF_FIELD_RSHIFT_U64 => BtfCoreRelocKind::RShiftU64,
                    BTF_TYPE_LOCAL_ID => BtfCoreRelocKind::LocalTypeId,
                    BTF_TYPE_TARGET_ID => BtfCoreRelocKind::TargetTypeId,
                    BTF_TYPE_EXISTS => BtfCoreRelocKind::TypeExists,
                    BTF_TYPE_MATCHES => BtfCoreRelocKind::TypeMatches,
                    BTF_TYPE_SIZE => BtfCoreRelocKind::TypeSize,
                    BTF_ENUMVAL_EXISTS => BtfCoreRelocKind::EnumvalExists,
                    BTF_ENUMVAL_VALUE => BtfCoreRelocKind::EnumvalValue,
                    _ => {
                        return btf_error(format!("Unknown BTF CO-RE reloc kind: {}", rec.kind));
                    }
                };
                let relo = {
                    let access_spec_str = Btf::get_btf_str(strs, rec.access_spec_off)?;
                    let access_spec = Btf::parse_reloc_access_spec(&access_spec_str)?;
                    BtfExtCoreReloc {
                        insn_off: rec.insn_off,
                        type_id: rec.type_id,
                        access_spec_str: access_spec_str,
                        access_spec: access_spec,
                        kind: kind,
                    }
                };
                recs.push(relo);
            }
            secs.push(BtfExtSection::<BtfExtCoreReloc> {
                name: Btf::get_btf_str(strs, sec_hdr.sec_name_off)?,
                rec_sz: rec_sz as usize,
                recs: recs,
            });

            data = &data[(sec_hdr.num_info * rec_sz) as usize..];
        }
        Ok(secs)
    }
    fn parse_reloc_access_spec(access_spec_str: &str) -> BtfResult<Vec<usize>> {
        let mut spec = Vec::new();
        for p in access_spec_str.split(':') {
            spec.push(p.parse::<usize>()?);
        }
        Ok(spec)
    }

    fn get_btf_str(strs: &[u8], off: u32) -> BtfResult<&str> {
        let c_str = unsafe { CStr::from_ptr(&strs[off as usize] as *const u8 as *const c_char) };
        Ok(c_str.to_str()?)
    }
}
