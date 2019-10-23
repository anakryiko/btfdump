use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;

use crate::btf_index::BtfIndex;
use crate::types::*;
use crate::{btf_error, BtfResult};

#[derive(Debug)]
pub struct Reloc {
    pub sec_id: usize,
    pub reloc_id: usize,
    pub local_type_id: u32,
    pub local_offset: usize,
    pub local_spec: Vec<usize>,
    pub targ_type_id: u32,
    pub targ_offset: usize,
    pub targ_spec: Vec<usize>,
}

impl fmt::Display for Reloc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sec#{}, r#{}: [{}] + {} ({}) --> [{}] + {} ({})",
            self.sec_id,
            self.reloc_id,
            self.local_type_id,
            self.local_offset,
            Relocator::spec_to_str(&self.local_spec),
            self.targ_type_id,
            self.targ_offset,
            Relocator::spec_to_str(&self.targ_spec),
        )
    }
}

#[derive(Debug)]
enum Accessor {
    Field {
        type_id: u32,
        field_idx: usize,
        field_name: String,
    },
    Array {
        type_id: u32,
        arr_idx: usize,
    },
}

impl fmt::Display for Accessor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Accessor::Field {
                type_id,
                field_idx,
                field_name,
            } => write!(f, "field:[{}].#{}('{}')", type_id, field_idx, field_name),
            Accessor::Array { type_id, arr_idx } => write!(f, "array:*[{}] + {}", type_id, arr_idx),
        }
    }
}

#[derive(Debug)]
pub struct RelocatorCfg {
    pub verbose: bool,
}

#[derive(Debug)]
pub struct Relocator<'a, 'b> {
    cfg: RelocatorCfg,
    targ_btf: &'a Btf<'a>,
    local_btf: &'b Btf<'b>,
    targ_index: BtfIndex<'a>,
    type_map: HashMap<u32, Vec<u32>>,
}

impl<'a, 'b> Relocator<'a, 'b> {
    pub fn new(targ_btf: &'a Btf, local_btf: &'b Btf, cfg: RelocatorCfg) -> Relocator<'a, 'b> {
        Relocator {
            cfg: cfg,
            targ_btf: targ_btf,
            local_btf: local_btf,
            targ_index: BtfIndex::new(targ_btf),
            type_map: HashMap::new(),
        }
    }

    pub fn relocate(&mut self) -> BtfResult<Vec<Reloc>> {
        let mut relocs = Vec::new();
        for (sec_id, sec) in self.local_btf.field_reloc_secs().iter().enumerate() {
            for (reloc_id, rec) in sec.recs.iter().enumerate() {
                let local_type = self.local_btf.type_by_id(rec.type_id);
                let local_off = self.calc_off(self.local_btf, rec.type_id, &rec.access_spec)?;
                let local_access =
                    self.transform_access(self.local_btf, rec.type_id, &rec.access_spec)?;
                if self.cfg.verbose {
                    print!("sec#{}, r#{}: accessors = ", sec_id, reloc_id);
                    for a in &local_access {
                        print!("{}, ", a);
                    }
                    println!("");
                }

                let mut targ_off = 0;
                let mut targ_type_id = 0;
                let mut targ_spec = Vec::new();

                let mut matched_ids = Vec::new();
                let cand_targ_ids = if self.type_map.contains_key(&rec.type_id) {
                    self.type_map.get(&rec.type_id).unwrap()
                } else {
                    //TODO: strip __suffix, kernel version suffix, etc
                    self.targ_index.get_by_name(local_type.name())
                };
                for &id in cand_targ_ids {
                    if self.cfg.verbose {
                        println!("sec#{}, r#{}: matching to [{}]", sec_id, reloc_id, id);
                    }
                    match self.calc_targ_spec(&local_access, id) {
                        Ok(spec) => {
                            if self.cfg.verbose {
                                println!(
                                    "sec#{}, r#{}: targ_spec: {}",
                                    sec_id,
                                    reloc_id,
                                    Relocator::spec_to_str(&spec)
                                );
                            }
                            let off = self.calc_off(self.targ_btf, id, &spec)?;
                            if !matched_ids.is_empty() {
                                if off != targ_off {
                                    btf_error(format!(
                                        concat!(
                                            "ambiguous offset for local type (id: {}, spec: {}),",
                                            " at least 2 different target type matched",
                                            " with different offsets: ",
                                            "(id: {}, off: {}, spec: {}) vs ",
                                            "(id: {}, off: {}, spec: {})"
                                        ),
                                        rec.type_id,
                                        rec.access_spec_str,
                                        targ_type_id,
                                        targ_off,
                                        Relocator::spec_to_str(&targ_spec),
                                        id,
                                        off,
                                        Relocator::spec_to_str(&spec)
                                    ))?;
                                }
                            } else {
                                targ_off = off;
                                targ_type_id = id;
                                targ_spec = spec;
                            }
                            matched_ids.push(id);
                        }
                        Err(e) => {
                            if self.cfg.verbose {
                                println!(
                                    "sec#{}, r#{}: failed to match targ [{}]: {}",
                                    sec_id, reloc_id, id, e
                                );
                            }
                            continue;
                        }
                    }
                }
                if matched_ids.is_empty() {
                    btf_error(format!("failed to find any candidate for reloc {}", rec))?;
                }
                self.type_map.insert(rec.type_id, matched_ids);
                relocs.push(Reloc {
                    sec_id: sec_id,
                    reloc_id: reloc_id,
                    local_type_id: rec.type_id,
                    local_offset: local_off as usize,
                    local_spec: rec.access_spec.clone(),
                    targ_type_id: targ_type_id,
                    targ_offset: targ_off as usize,
                    targ_spec: targ_spec,
                });
            }
        }
        Ok(relocs)
    }

    fn transform_access(
        &self,
        btf: &Btf,
        type_id: u32,
        spec: &[usize],
    ) -> BtfResult<Vec<Accessor>> {
        let mut res = Vec::new();
        let mut id = btf.skip_mods_and_typedefs(type_id);
        res.push(Accessor::Array {
            type_id: id,
            arr_idx: spec[0],
        });
        for i in 1..spec.len() {
            id = btf.skip_mods_and_typedefs(id);
            match btf.type_by_id(id) {
                BtfType::Struct(t) => {
                    let m = &t.members[spec[i]];
                    let next_id = btf.skip_mods_and_typedefs(m.type_id);
                    if !m.name.is_empty() {
                        res.push(Accessor::Field {
                            type_id: id,
                            field_idx: spec[i],
                            field_name: m.name.to_owned(),
                        });
                    }
                    id = next_id;
                }
                BtfType::Union(t) => {
                    let m = &t.members[spec[i]];
                    let next_id = btf.skip_mods_and_typedefs(m.type_id);
                    if !m.name.is_empty() {
                        res.push(Accessor::Field {
                            type_id: id,
                            field_idx: spec[i],
                            field_name: m.name.to_owned(),
                        });
                    }
                    id = next_id;
                }
                BtfType::Array(t) => {
                    id = btf.skip_mods_and_typedefs(t.val_type_id);
                    res.push(Accessor::Array {
                        type_id: id,
                        arr_idx: spec[i],
                    });
                }
                _ => spec_error(
                    spec,
                    i,
                    "must be struct/union/array",
                    id,
                    btf.type_by_id(id),
                )?,
            }
        }
        Ok(res)
    }

    fn calc_off(&self, btf: &Btf, type_id: u32, spec: &[usize]) -> BtfResult<u32> {
        let mut id = btf.skip_mods_and_typedefs(type_id);
        let mut off = spec[0] as u32 * Relocator::type_size(btf, id)?;

        for i in 1..spec.len() {
            id = btf.skip_mods_and_typedefs(id);
            match btf.type_by_id(id) {
                BtfType::Struct(t) => {
                    let m = &t.members[spec[i]];
                    off += m.bit_offset / 8;
                    id = m.type_id;
                }
                BtfType::Union(t) => {
                    let m = &t.members[spec[i]];
                    off += m.bit_offset / 8;
                    id = m.type_id;
                }
                BtfType::Array(t) => {
                    off += spec[i] as u32 * Relocator::type_size(btf, t.val_type_id)?;
                    id = t.val_type_id;
                }
                _ => spec_error(
                    spec,
                    i,
                    "must be struct/union/array",
                    id,
                    btf.type_by_id(id),
                )?,
            }
        }
        Ok(off)
    }

    fn calc_targ_spec(&self, local_spec: &[Accessor], mut targ_id: u32) -> BtfResult<Vec<usize>> {
        targ_id = self.targ_btf.skip_mods_and_typedefs(targ_id);
        let mut targ_type = self.targ_btf.type_by_id(targ_id);
        let mut targ_spec = Vec::new();

        match local_spec[0] {
            Accessor::Array { arr_idx, .. } => targ_spec.push(arr_idx),
            _ => btf_error(format!(
                "first spec must be array access, but is: {}",
                local_spec[0]
            ))?,
        }

        for i in 1..local_spec.len() {
            let s = &local_spec[i];
            match s {
                &Accessor::Array { arr_idx, .. } => match targ_type {
                    BtfType::Array(t) => {
                        targ_id = self.targ_btf.skip_mods_and_typedefs(t.val_type_id);
                        targ_type = self.targ_btf.type_by_id(targ_id);
                        targ_spec.push(arr_idx);
                    }
                    _ => access_error(s, i, "target must be array", targ_id, targ_type)?,
                },
                Accessor::Field {
                    type_id: local_id,
                    field_idx,
                    ..
                } => {
                    let local_type = self.local_btf.type_by_id(*local_id);
                    let local_members = match local_type {
                        BtfType::Struct(t) => &t.members,
                        BtfType::Union(t) => &t.members,
                        _ => {
                            access_error(s, i, "local must be struct/union", *local_id, local_type)?
                        }
                    };
                    let local_member = &local_members[*field_idx];
                    let targ_members = match targ_type {
                        BtfType::Struct(t) => &t.members,
                        BtfType::Union(t) => &t.members,
                        _ => access_error(s, i, "target must be struct/union", targ_id, targ_type)?,
                    };
                    match self.targ_member_spec(local_member, targ_members) {
                        Ok(Some((t_id, mut t_spec))) => {
                            targ_id = t_id;
                            targ_type = self.targ_btf.type_by_id(targ_id);
                            targ_spec.append(&mut t_spec);
                        }
                        Ok(None) => {
                            access_error(s, i, "target field not found", targ_id, targ_type)?
                        }
                        Err(e) => access_error(s, i, &format!("{}", e), targ_id, targ_type)?,
                    }
                }
            }
        }
        Ok(targ_spec)
    }

    fn targ_member_spec(
        &self,
        local_member: &BtfMember,
        targ_members: &[BtfMember],
    ) -> BtfResult<Option<(u32, Vec<usize>)>> {
        for (i, m) in targ_members.iter().enumerate() {
            if m.name == local_member.name {
                let local_id = self.local_btf.skip_mods_and_typedefs(local_member.type_id);
                let targ_id = self.targ_btf.skip_mods_and_typedefs(m.type_id);
                if self.are_kinds_compat(local_id, targ_id) {
                    return Ok(Some((targ_id, vec![i])));
                } else {
                    return btf_error(format!(
                        concat!(
                            "incompatible types for field '{}', ",
                            "local_id: {}, local_kind: {:?}, ",
                            "targ_id: {}, targ_kind: {:?}"
                        ),
                        local_member.name,
                        local_id,
                        self.local_btf.type_by_id(local_id).kind(),
                        targ_id,
                        self.targ_btf.type_by_id(targ_id).kind()
                    ));
                }
            } else if m.name.is_empty() {
                if let Some(members) = self.get_composite_members(self.targ_btf, m.type_id) {
                    match self.targ_member_spec(local_member, members) {
                        Ok(Some((t_id, mut spec))) => {
                            spec.insert(0, i);
                            return Ok(Some((t_id, spec)));
                        }
                        Ok(None) => {}
                        e @ Err(_) => return e,
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_composite_members<'c>(&self, btf: &'c Btf, type_id: u32) -> Option<&'c [BtfMember<'c>]> {
        let id = btf.skip_mods(type_id);
        match btf.type_by_id(id) {
            BtfType::Struct(t) => Some(&t.members),
            BtfType::Union(t) => Some(&t.members),
            _ => None,
        }
    }

    fn are_kinds_compat(&self, local_id: u32, targ_id: u32) -> bool {
        let local_kind = self.local_btf.type_by_id(local_id).kind();
        let targ_kind = self.targ_btf.type_by_id(targ_id).kind();
        local_kind == targ_kind || (local_kind == BtfKind::Struct && targ_kind == BtfKind::Union)
    }

    fn type_size(btf: &Btf, type_id: u32) -> BtfResult<u32> {
        let id = btf.skip_mods_and_typedefs(type_id);
        Ok(match btf.type_by_id(id) {
            BtfType::Int(t) if t.offset == 0 && t.bits % 8 == 0 => t.bits / 8,
            BtfType::Enum(t) => t.sz,
            BtfType::Struct(t) => t.sz,
            BtfType::Union(t) => t.sz,
            BtfType::Array(t) => t.nelems * Relocator::type_size(btf, t.val_type_id)?,
            BtfType::Ptr(_) => btf.ptr_sz(),
            _ => btf_error(format!(
                "can't calculate byte size of type_id: {}, type: {}",
                id,
                btf.type_by_id(id),
            ))?,
        })
    }

    pub fn pretty_print_access_spec(btf: &Btf, rec: &BtfExtFieldReloc) -> BtfResult<String> {
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
            _ => spec_error(spec, 0, "must be struct/union", id, btf.type_by_id(id))?,
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
                _ => spec_error(
                    spec,
                    i,
                    "must be struct/union/array",
                    id,
                    btf.type_by_id(id),
                )?,
            }
        }
        Ok(buf)
    }

    fn spec_to_str(spec: &[usize]) -> String {
        spec.iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(":")
    }
}

fn spec_error<T>(
    spec: &[usize],
    idx: usize,
    details: &str,
    type_id: u32,
    bt: &BtfType,
) -> BtfResult<T> {
    btf_error(format!(
        "Unsupported accessor: {}, at #{}: {}, but is type_id: {}, type: {}",
        Relocator::spec_to_str(spec),
        idx,
        details,
        type_id,
        bt,
    ))?
}
fn access_error<T>(
    spec: &Accessor,
    idx: usize,
    details: &str,
    type_id: u32,
    bt: &BtfType,
) -> BtfResult<T> {
    btf_error(format!(
        "Unsupported accessor: {}, at #{}: {}, but is type_id: {}, type: {}",
        spec, idx, details, type_id, bt,
    ))?
}
