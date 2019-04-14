use std::fmt;
use std::fmt::Write;

use crate::btf_index::BtfIndex;
use crate::types::*;
use crate::{btf_error, BtfResult};

#[derive(Debug)]
pub struct Reloc {
    pub reloc_id: u32,
    pub local_type_id: u32,
    pub local_offset: usize,
    pub targ_type_id: u32,
    pub targ_offset: usize,
}

impl fmt::Display for Reloc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "#{}: [{}] + {} --> [{}] + {}",
            self.reloc_id,
            self.local_type_id,
            self.local_offset,
            self.targ_type_id,
            self.targ_offset
        )
    }
}

#[derive(Debug)]
pub struct Relocator<'a, 'b> {
    targ_btf: &'a Btf,
    local_btf: &'b Btf,
    targ_index: BtfIndex<'a>,
}

impl<'a, 'b> Relocator<'a, 'b> {
    pub fn new(targ_btf: &'a Btf, local_btf: &'b Btf) -> Relocator<'a, 'b> {
        let relocator = Relocator {
            targ_btf: targ_btf,
            local_btf: local_btf,
            targ_index: BtfIndex::new(targ_btf),
        };
        relocator
    }

    pub fn relocate(&mut self) -> BtfResult<Vec<Reloc>> {
        let mut relocs = Vec::new();
        Ok(relocs)
    }

    pub fn pretty_print_access_spec(btf: &Btf, rec: &BtfExtOffsetReloc) -> BtfResult<String> {
        let mut buf = String::new();
        let spec = &rec.access_spec;
        let mut id = rec.type_id;
        match btf.type_by_id(id) {
            BtfType::Struct(t) => {
                write!(
                    buf,
                    "struct {}",
                    if t.name.is_empty() { "<anon>" } else { &t.name }
                )?;
            }
            BtfType::Union(t) => {
                write!(
                    buf,
                    "union {}",
                    if t.name.is_empty() { "<anon>" } else { &t.name }
                )?;
            }
            _ => btf_error(format!(
                "Unsupported accessor spec: '{}', at #{}, type_id: {}, type: {}",
                rec.access_spec_str,
                0,
                id,
                btf.type_by_id(id),
            ))?,
        }
        if spec[0] > 0 {
            write!(buf, "[{}]", spec[0])?;
        }

        for i in 1..spec.len() {
            match btf.type_by_id(id) {
                BtfType::Struct(t) => {
                    let m = &t.members[spec[i] as usize];
                    write!(buf, ".{}", m.name)?;
                    id = btf.skip_mods_and_typedefs(m.type_id);
                }
                BtfType::Union(t) => {
                    let m = &t.members[spec[i] as usize];
                    if !m.name.is_empty() {
                        write!(buf, ".{}", m.name)?;
                    } else {
                        write!(buf, ".<anon>")?;
                    }
                    id = btf.skip_mods_and_typedefs(m.type_id);
                }
                BtfType::Array(t) => {
                    write!(buf, "[{}]", spec[i] as usize)?;
                    id = btf.skip_mods_and_typedefs(t.val_type_id);
                }
                _ => btf_error(format!(
                    "Unsupported accessor spec: {}, at #{}, type_id: {}, type: {}",
                    rec.access_spec_str,
                    i,
                    id,
                    btf.type_by_id(id),
                ))?,
            }
        }
        Ok(buf)
    }
}
