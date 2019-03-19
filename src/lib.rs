use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::mem::size_of;

use object::{Object, ObjectSection};
use scroll::Pread;
use scroll_derive::{IOread, IOwrite, Pread as DerivePread, Pwrite, SizeWith};

const BTF_MAGIC: u16 = 0xeB9F;
const BTF_VERSION: u8 = 1;

//const BTF_MAX_TYPE: u32 = 0xffff;
//const BTF_MAX_NAME_OFFSET: u32 = 0xffff;
//const BTF_MAX_VLEN: u32 = 0xffff;

//const BTF_MAX_NR_TYPES: u32 = 0x7fffffff;
//const BTF_MAX_STR_OFFSET: u32 = 0x7fffffff;

//const BTF_KIND_UNKN: u32 = 0;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FWD: u32 = 7;
const BTF_KIND_TYPEDEF: u32 = 8;
const BTF_KIND_VOLATILE: u32 = 9;
const BTF_KIND_CONST: u32 = 10;
const BTF_KIND_RESTRICT: u32 = 11;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
//const BTF_KIND_MAX: u32 = 15;
//const NR_BTF_KINDS: u32 = BTF_KIND_MAX + 1;

const BTF_INT_SIGNED: u32 = 0b001;
const BTF_INT_CHAR: u32 = 0b010;
const BTF_INT_BOOL: u32 = 0b100;

const BTF_VAR_STATIC: u32 = 0;
const BTF_VAR_GLOBAL_ALLOCATED: u32 = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_header {
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
struct btf_type {
    pub name_off: u32,
    pub info: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_enum {
    pub name_off: u32,
    pub val: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_array {
    pub val_type_id: u32,
    pub idx_type_id: u32,
    pub nelems: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_member {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_param {
    pub name_off: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, DerivePread, Pwrite, IOread, IOwrite, SizeWith)]
struct btf_datasec_var {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

pub const ANON_NAME: &'static str = "<anon>";

fn disp_name(s: &str) -> &str {
    if s == "" {
        ANON_NAME
    } else {
        s
    }
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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
pub struct BtfMember {
    name: String,
    type_id: u32,
    bit_offset: u32,
    bit_size: u8,
}

impl fmt::Display for BtfMember {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "'{}' off:{}", disp_name(&self.name), self.bit_offset)?;
        if self.bit_size != 0 {
            write!(f, " sz:{}", self.bit_size)?;
        }
        write!(f, " --> [{}]", self.type_id)
    }
}

#[derive(Debug)]
pub struct BtfEnumValue {
    name: String,
    value: i32,
}

impl fmt::Display for BtfEnumValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", disp_name(&self.name), self.value)
    }
}

#[derive(Debug)]
pub struct BtfFuncParam {
    name: String,
    type_id: u32,
}

impl fmt::Display for BtfFuncParam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "'{}' --> [{}]", disp_name(&self.name), self.type_id)
    }
}

#[derive(Debug)]
pub enum BtfVarKind {
    Static,
    GlobalAlloc,
}

impl fmt::Display for BtfVarKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfVarKind::Static => write!(f, "static"),
            BtfVarKind::GlobalAlloc => write!(f, "global-alloc"),
        }
    }
}

#[derive(Debug)]
pub struct BtfDatasecVar {
    type_id: u32,
    offset: u32,
    sz: u32,
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
pub enum BtfType {
    Void,
    Int {
        name: String,
        bits: u32,
        offset: u32,
        encoding: BtfIntEncoding,
    },
    Ptr {
        type_id: u32,
    },
    Array {
        nelems: u32,
        idx_type_id: u32,
        val_type_id: u32,
    },
    Struct {
        name: String,
        sz: u32,
        members: Vec<BtfMember>,
    },
    Union {
        name: String,
        sz: u32,
        members: Vec<BtfMember>,
    },
    Enum {
        name: String,
        sz_bits: u32,
        values: Vec<BtfEnumValue>,
    },
    Fwd {
        name: String,
        kind: BtfFwdKind,
    },
    Typedef {
        name: String,
        type_id: u32,
    },
    Volatile {
        type_id: u32,
    },
    Const {
        type_id: u32,
    },
    Restrict {
        type_id: u32,
    },
    Func {
        name: String,
        proto_type_id: u32,
    },
    FuncProto {
        res_type_id: u32,
        params: Vec<BtfFuncParam>,
    },
    Var {
        name: String,
        type_id: u32,
        kind: BtfVarKind,
    },
    Datasec {
        name: String,
        sz: u32,
        vars: Vec<BtfDatasecVar>,
    },
}

impl fmt::Display for BtfType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BtfType::Void => write!(f, "<{}>", "VOID"),
            BtfType::Int {
                name,
                bits,
                offset,
                encoding,
            } => {
                write!(
                    f,
                    "<{}> '{}' bits:{} off:{}",
                    "INT",
                    disp_name(name),
                    bits,
                    offset
                )?;
                match encoding {
                    BtfIntEncoding::None => (),
                    _ => write!(f, " enc:{}", encoding)?,
                }
                Ok(())
            }
            BtfType::Ptr { type_id } => write!(f, "<{}> --> [{}]", "PTR", type_id),
            BtfType::Array {
                nelems,
                idx_type_id,
                val_type_id,
            } => write!(
                f,
                "<{}> n:{} idx-->[{}] val-->[{}]",
                "ARRAY", nelems, idx_type_id, val_type_id
            ),
            BtfType::Struct { name, sz, members } => {
                write!(
                    f,
                    "<{}> '{}' sz:{} n:{}",
                    "STRUCT",
                    disp_name(name),
                    sz,
                    members.len()
                )?;
                for i in 0..members.len() {
                    write!(f, "\n\t#{:02} {}", i, members[i])?;
                }
                Ok(())
            }
            BtfType::Union { name, sz, members } => {
                write!(
                    f,
                    "<{}> '{}' sz:{} n:{}",
                    "UNION",
                    disp_name(name),
                    sz,
                    members.len()
                )?;
                for i in 0..members.len() {
                    write!(f, "\n\t#{:02} {}", i, members[i])?;
                }
                Ok(())
            }
            BtfType::Enum {
                name,
                sz_bits,
                values,
            } => {
                write!(
                    f,
                    "<{}> '{}' sz:{} n:{}",
                    "ENUM",
                    disp_name(name),
                    sz_bits,
                    values.len()
                )?;
                for i in 0..values.len() {
                    write!(f, "\n\t#{:02} {}", i, values[i])?;
                }
                Ok(())
            }
            BtfType::Fwd { name, kind } => {
                write!(f, "<{}> '{}' kind:{}", "FWD", disp_name(name), kind)
            }
            BtfType::Typedef { name, type_id } => {
                write!(f, "<{}> '{}' --> [{}]", "TYPEDEF", disp_name(name), type_id)
            }
            BtfType::Volatile { type_id } => write!(f, "<{}> --> [{}]", "VOLATILE", type_id),
            BtfType::Const { type_id } => write!(f, "<{}> --> [{}]", "CONST", type_id),
            BtfType::Restrict { type_id } => write!(f, "<{}> --> [{}]", "RESTRICT", type_id),
            BtfType::Func {
                name,
                proto_type_id,
            } => write!(
                f,
                "<{}> '{}' --> [{}]",
                "FUNC",
                disp_name(name),
                proto_type_id
            ),
            BtfType::FuncProto {
                res_type_id,
                params,
            } => {
                write!(
                    f,
                    "<{}> r-->[{}] n:{}",
                    "FUNC_PROTO",
                    res_type_id,
                    params.len()
                )?;
                for i in 0..params.len() {
                    write!(f, "\n\t#{:02} {}", i, params[i])?;
                }
                Ok(())
            }
            BtfType::Var {
                name,
                type_id,
                kind,
            } => write!(
                f,
                "<{}> '{}' kind:{} --> [{}]",
                "VAR",
                disp_name(name),
                kind,
                type_id
            ),
            BtfType::Datasec { name, sz, vars } => {
                write!(
                    f,
                    "<{}> '{}' sz:{} n:{}",
                    "DATASEC",
                    disp_name(name),
                    sz,
                    vars.len()
                )?;
                for i in 0..vars.len() {
                    write!(f, "\n\t#{:02} {}", i, vars[i])?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
struct BtfError {
    details: String,
}

impl BtfError {
    fn new(msg: &str) -> BtfError {
        BtfError {
            details: msg.to_string(),
        }
    }
    fn new_owned(msg: String) -> BtfError {
        BtfError { details: msg }
    }
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for BtfError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Debug)]
struct BtfHeader {
    pub flags: u8,
    pub hdr_len: usize,
    pub type_off: usize,
    pub type_len: usize,
    pub str_off: usize,
    pub str_len: usize,
}

pub struct Btf {
    hdr: BtfHeader,
    endian: scroll::Endian,
    types: Vec<BtfType>,
}

type BtfResult<T> = Result<T, Box<dyn Error>>;

fn btf_error<T>(msg: String) -> BtfResult<T> {
    Err(Box::new(BtfError::new_owned(msg)))
}

impl Btf {
    pub fn types(&self) -> &Vec<BtfType> {
        &self.types
    }

    pub fn load<'data>(elf: object::ElfFile<'data>) -> BtfResult<Btf> {
        let endian = if elf.is_little_endian() {
            scroll::LE
        } else {
            scroll::BE
        };
        let btf_section = elf
            .section_by_name(".BTF")
            .ok_or_else(|| Box::new(BtfError::new("No .BTF section found!")))?;
        let data = btf_section.data();

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

        let mut btf = Btf {
            endian: endian,
            hdr: BtfHeader {
                flags: hdr.flags,
                hdr_len: hdr.hdr_len as usize,
                type_off: hdr.type_off as usize,
                type_len: hdr.type_len as usize,
                str_off: hdr.str_off as usize,
                str_len: hdr.str_len as usize,
            },
            types: vec![BtfType::Void],
        };

        let type_off = size_of::<btf_header>() + btf.hdr.type_off;
        let type_data = &data[type_off..type_off + btf.hdr.type_len];
        let str_off = size_of::<btf_header>() + btf.hdr.str_off;
        let str_data = &data[str_off..str_off + btf.hdr.str_len];
        let mut off: usize = 0;
        while off < btf.hdr.type_len {
            let t = btf.load_type(&type_data[off..], str_data)?;
            off += Btf::type_size(&t);
            btf.types.push(t);
        }

        Ok(btf)
    }

    fn type_size(t: &BtfType) -> usize {
        let common = size_of::<btf_type>();
        match t {
            BtfType::Void => 0,
            BtfType::Ptr { .. }
            | BtfType::Fwd { .. }
            | BtfType::Typedef { .. }
            | BtfType::Volatile { .. }
            | BtfType::Const { .. }
            | BtfType::Restrict { .. }
            | BtfType::Func { .. } => common,
            BtfType::Int { .. } | BtfType::Var { .. } => common + size_of::<u32>(),
            BtfType::Array { .. } => common + size_of::<btf_array>(),
            BtfType::Struct { members: m, .. } => common + m.len() * size_of::<btf_member>(),
            BtfType::Union { members: m, .. } => common + m.len() * size_of::<btf_member>(),
            BtfType::Enum { values: v, .. } => common + v.len() * size_of::<btf_enum>(),
            BtfType::FuncProto { params: m, .. } => common + m.len() * size_of::<btf_param>(),
            BtfType::Datasec { vars: v, .. } => common + v.len() * size_of::<btf_datasec_var>(),
        }
    }

    fn load_type(&self, data: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
        let t = data.pread_with::<btf_type>(0, self.endian)?;
        let extra = &data[size_of::<btf_type>()..];
        let kind = (t.info >> 24) & 0xf;
        match kind {
            BTF_KIND_INT => self.load_int(&t, extra, strs),
            BTF_KIND_PTR => Ok(BtfType::Ptr { type_id: t.type_id }),
            BTF_KIND_ARRAY => self.load_array(extra),
            BTF_KIND_STRUCT => self.load_struct(&t, extra, strs),
            BTF_KIND_UNION => self.load_union(&t, extra, strs),
            BTF_KIND_ENUM => self.load_enum(&t, extra, strs),
            BTF_KIND_FWD => Ok(BtfType::Fwd {
                name: Btf::get_btf_str(strs, t.name_off)?,
                kind: if Btf::get_kind(t.info) {
                    BtfFwdKind::Struct
                } else {
                    BtfFwdKind::Union
                },
            }),
            BTF_KIND_TYPEDEF => Ok(BtfType::Typedef {
                name: Btf::get_btf_str(strs, t.name_off)?,
                type_id: t.type_id,
            }),
            BTF_KIND_VOLATILE => Ok(BtfType::Volatile { type_id: t.type_id }),
            BTF_KIND_CONST => Ok(BtfType::Const { type_id: t.type_id }),
            BTF_KIND_RESTRICT => Ok(BtfType::Restrict { type_id: t.type_id }),
            BTF_KIND_FUNC => Ok(BtfType::Func {
                name: Btf::get_btf_str(strs, t.name_off)?,
                proto_type_id: t.type_id,
            }),
            BTF_KIND_FUNC_PROTO => self.load_func_proto(&t, extra, strs),
            BTF_KIND_VAR => self.load_var(&t, extra, strs),
            BTF_KIND_DATASEC => self.load_datasec(&t, extra, strs),
            _ => btf_error(format!("Unknown BTF kind: {}", kind)),
        }
    }

    fn load_int(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
        let info = extra.pread_with::<u32>(0, self.endian)?;
        let enc = (info >> 24) & 0xf;
        let off = (info >> 16) & 0xff;
        let bits = info & 0xff;
        Ok(BtfType::Int {
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
        })
    }

    fn load_array(&self, extra: &[u8]) -> BtfResult<BtfType> {
        let info = extra.pread_with::<btf_array>(0, self.endian)?;
        Ok(BtfType::Array {
            nelems: info.nelems,
            idx_type_id: info.idx_type_id,
            val_type_id: info.val_type_id,
        })
    }

    fn load_struct(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
        Ok(BtfType::Struct {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            members: self.load_members(t, extra, strs)?,
        })
    }

    fn load_union(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
        Ok(BtfType::Union {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            members: self.load_members(t, extra, strs)?,
        })
    }

    fn load_members(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<Vec<BtfMember>> {
        let mut res = Vec::new();
        let mut off: usize = 0;
        let bits = Btf::get_kind(t.info);

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

    fn load_enum(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
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
        Ok(BtfType::Enum {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz_bits: t.type_id, // it's a type/size union in C
            values: vals,
        })
    }

    fn load_func_proto(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
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
        Ok(BtfType::FuncProto {
            res_type_id: t.type_id,
            params: params,
        })
    }

    fn load_var(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
        let kind = extra.pread_with::<u32>(0, self.endian)?;
        Ok(BtfType::Var {
            name: Btf::get_btf_str(strs, t.name_off)?,
            type_id: t.type_id,
            kind: match kind {
                BTF_VAR_STATIC => BtfVarKind::Static,
                BTF_VAR_GLOBAL_ALLOCATED => BtfVarKind::GlobalAlloc,
                _ => {
                    return btf_error(format!("Unknown BTF var kind: {}", kind));
                }
            },
        })
    }

    fn load_datasec(&self, t: &btf_type, extra: &[u8], strs: &[u8]) -> BtfResult<BtfType> {
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
        Ok(BtfType::Datasec {
            name: Btf::get_btf_str(strs, t.name_off)?,
            sz: t.type_id, // it's a type/size union in C
            vars: vars,
        })
    }

    fn get_btf_str(strs: &[u8], off: u32) -> BtfResult<String> {
        let c_str = unsafe { CStr::from_ptr(&strs[off as usize] as *const u8 as *const i8) };
        Ok(c_str.to_str()?.to_owned())
    }

    fn get_vlen(info: u32) -> u32 {
        info & 0xffff
    }

    fn get_kind(info: u32) -> bool {
        (info >> 31) == 1
    }
}
