use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::RegexSet;

use crate::types::*;
use crate::{btf_error, BtfResult};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum OrderState {
    NotOrdered,
    Ordering,
    Ordered,
}

impl Default for OrderState {
    fn default() -> Self {
        OrderState::NotOrdered
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EmitState {
    NotEmitted,
    Emitting,
    Emitted,
}

impl Default for EmitState {
    fn default() -> Self {
        EmitState::NotEmitted
    }
}

#[derive(Default)]
struct TypeState {
    order_state: OrderState,
    emit_state: EmitState,
    fwd_emitted: bool,
    name: String,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
enum NamedKind {
    Type,
    Ident,
}

#[derive(Debug)]
pub struct CDumperCfg {
    pub verbose: bool,
    pub union_as_struct: bool,
}

pub struct CDumper<'a> {
    btf: &'a Btf<'a>,
    cfg: CDumperCfg,
    state: Vec<TypeState>,
    names: HashMap<(NamedKind, &'a str), u32>,
}

impl<'a> CDumper<'a> {
    pub fn new(btf: &'a Btf<'a>, cfg: CDumperCfg) -> CDumper<'a> {
        let mut dumper = CDumper {
            btf: btf,
            cfg: cfg,
            state: Vec::new(),
            names: HashMap::new(),
        };
        dumper
            .state
            .resize_with(btf.type_cnt() as usize, Default::default);
        dumper
    }

    pub fn dump_types(&mut self, filter: Box<Fn(u32, &'a BtfType<'a>) -> bool>) -> BtfResult<()> {
        for id in 1..self.btf.type_cnt() {
            let bt = self.btf.type_by_id(id);
            if filter(id, bt) {
                self.dump_type(id)?;
            }
        }
        Ok(())
    }

    pub fn dump_type(&mut self, id: u32) -> BtfResult<()> {
        let mut order = Vec::new();
        if self.cfg.verbose {
            println!("===================================================");
            println!("ORDERING id: {}, type: {}", id, self.btf.type_by_id(id));
        }
        self.order_type(id, false, &mut order)?;
        if self.cfg.verbose {
            for (i, &id) in order.iter().enumerate() {
                println!("ORDER #{} id: {}, type: {}", i, id, self.btf.type_by_id(id));
            }
        }
        // emit struct/union and fwds required by them in correct order
        for id in order {
            self.emit_type(id, 0)?;
        }
        Ok(())
    }

    fn order_type(&mut self, id: u32, has_ptr: bool, order: &mut Vec<u32>) -> BtfResult<bool> {
        if self.cfg.verbose && self.get_order_state(id) != OrderState::Ordered {
            println!(
                "ORDER TYPE id:{}, has_ptr:{}, type:{}, order_state:{:?}",
                id,
                has_ptr,
                self.btf.type_by_id(id),
                self.get_order_state(id)
            );
        }
        // order state is used to detect strong link cycles, but only for BTF kinds that are or
        // could be an independent definition (i.e., stand-alone fwd decl, enum, typedef, struct,
        // union). Ptrs, arrays, func_protos, modifiers are just means to get to these definitions.
        // Int/void don't need definitions, they are assumed to be always properly defined.
        // We also ignore datasec, var, and funcs. So for all non-defining kinds, we never even set
        // ordering state, for defining kinds we set OrderState::Ordering and subsequently
        // OrderState::Ordered only if it forms a strong link.
        match self.get_order_state(id) {
            OrderState::NotOrdered => {}
            OrderState::Ordering => match self.btf.type_by_id(id) {
                BtfType::Struct(t) | BtfType::Union(t) if has_ptr && !t.name.is_empty() => {
                    return Ok(false);
                }
                _ => {
                    return btf_error(format!(
                        "Unsatisfiable type cycle, id: {}, type: {}",
                        id,
                        self.btf.type_by_id(id)
                    ));
                }
            },
            // return true, letting typedefs know that it's ok to be emitted
            OrderState::Ordered => return Ok(true),
        }
        match self.btf.type_by_id(id) {
            BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {}
            BtfType::Void | BtfType::Int(_) => {
                self.set_order_state(id, OrderState::Ordered);
                return Ok(false);
            }
            BtfType::Volatile(t) => return self.order_type(t.type_id, has_ptr, order),
            BtfType::Const(t) => return self.order_type(t.type_id, has_ptr, order),
            BtfType::Restrict(t) => return self.order_type(t.type_id, has_ptr, order),
            BtfType::Ptr(t) => {
                let res = self.order_type(t.type_id, true, order);
                self.set_order_state(id, OrderState::Ordered);
                return res;
            }
            BtfType::Array(t) => return self.order_type(t.val_type_id, has_ptr, order),
            BtfType::FuncProto(t) => {
                let mut is_strong = self.order_type(t.res_type_id, has_ptr, order)?;
                for p in &t.params {
                    if self.order_type(p.type_id, has_ptr, order)? {
                        is_strong = true;
                    }
                }
                return Ok(is_strong);
            }
            BtfType::Struct(t) | BtfType::Union(t) => {
                // struct/union is part of strong link, only if it's embedded (so no ptr in a path)
                // or it's anonymous (so has to be defined inline, even if declared through ptr)
                if !has_ptr || t.name.is_empty() {
                    self.set_order_state(id, OrderState::Ordering);

                    for m in &t.members {
                        self.order_type(m.type_id, false, order)?;
                    }
                    // no need to explicitly order anonymous embedded struct
                    if !t.name.is_empty() {
                        order.push(id);
                    }

                    self.set_order_state(id, OrderState::Ordered);
                    // report this was strong link
                    return Ok(true);
                }
            }
            BtfType::Enum(t) => {
                if !t.name.is_empty() {
                    order.push(id);
                }
                self.set_order_state(id, OrderState::Ordered);
                // report this was strong link
                return Ok(true);
            }
            BtfType::Fwd(t) => {
                if !t.name.is_empty() {
                    order.push(id);
                }
                self.set_order_state(id, OrderState::Ordered);
                // report this was strong link
                return Ok(true);
            }
            BtfType::Typedef(t) => {
                let is_strong = self.order_type(t.type_id, has_ptr, order)?;
                if !has_ptr || is_strong {
                    order.push(id);
                    self.set_order_state(id, OrderState::Ordered);
                    // report this was strong link
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn emit_type(&mut self, id: u32, cont_id: u32) -> BtfResult<()> {
        let top_level_def = cont_id == 0;
        if self.cfg.verbose {
            println!(
                "EMIT_TYPE id: {}, cont_id: {}, is_def: {}, state: {:?}, type: {}",
                id,
                cont_id,
                top_level_def,
                self.get_emit_state(id),
                self.btf.type_by_id(id)
            );
        }
        match self.get_emit_state(id) {
            EmitState::NotEmitted => {}
            EmitState::Emitting => {
                if self.get_fwd_emitted(id) {
                    return Ok(());
                }
                match self.btf.type_by_id(id) {
                    BtfType::Struct(t) | BtfType::Union(t) => {
                        // fwd was already emitted or no need for fwd declare if we are referencing
                        // a struct/union we are part of
                        if id == cont_id {
                            return Ok(());
                        }
                        if t.name.is_empty() {
                            return btf_error(format!(
                                "anonymous struct loop, id: {}, type: {}",
                                id,
                                self.btf.type_by_id(id)
                            ));
                        }
                        if self.emit_composite_fwd(id, t) {
                            println!(";\n");
                        }
                        self.set_fwd_emitted(id, true);
                        return Ok(());
                    }
                    BtfType::Typedef(t) => {
                        // for typedef fwd_emitted means typedef definition was emitted, but it can
                        // be used only for "weak" references through pointer only
                        if self.emit_typedef_def(id, t, 0) {
                            println!(";\n");
                        }
                        self.set_fwd_emitted(id, true);
                        return Ok(());
                    }
                    _ => return Ok(()),
                };
            }
            EmitState::Emitted => return Ok(()),
        }

        if top_level_def && self.btf.type_by_id(id).name().is_empty() {
            return btf_error(format!(
                "unexpected nameless definition, id: {}, type: {}",
                id,
                self.btf.type_by_id(id)
            ));
        }

        match self.btf.type_by_id(id) {
            BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {}
            BtfType::Void | BtfType::Int(_) => {}
            BtfType::Volatile(t) => self.emit_type(t.type_id, cont_id)?,
            BtfType::Const(t) => self.emit_type(t.type_id, cont_id)?,
            BtfType::Restrict(t) => self.emit_type(t.type_id, cont_id)?,
            BtfType::Ptr(t) => self.emit_type(t.type_id, cont_id)?,
            BtfType::Array(t) => self.emit_type(t.val_type_id, cont_id)?,
            BtfType::FuncProto(t) => {
                self.emit_type(t.res_type_id, cont_id)?;
                for p in &t.params {
                    self.emit_type(p.type_id, cont_id)?;
                }
            }
            BtfType::Struct(t) | BtfType::Union(t) => {
                self.set_emit_state(id, EmitState::Emitting);
                if top_level_def || t.name.is_empty() {
                    // top-level struct definition or embedded anonymous struct, ensure all field
                    // types have their fwds declared
                    for m in &t.members {
                        self.emit_type(m.type_id, if t.name.is_empty() { cont_id } else { id })?;
                    }
                } else if !self.get_fwd_emitted(id) && id != cont_id {
                    if self.emit_composite_fwd(id, t) {
                        println!(";\n");
                    }
                    self.set_fwd_emitted(id, true);
                }
                if top_level_def {
                    self.emit_composite_def(id, t, 0);
                    println!(";\n");
                    self.set_emit_state(id, EmitState::Emitted);
                } else {
                    self.set_emit_state(id, EmitState::NotEmitted);
                }
            }
            BtfType::Enum(t) => {
                if top_level_def {
                    self.emit_enum_def(id, t, 0);
                    println!(";\n");
                }
                self.set_emit_state(id, EmitState::Emitted);
            }
            BtfType::Fwd(t) => {
                self.emit_fwd_def(id, t);
                println!(";\n");
                self.set_emit_state(id, EmitState::Emitted);
            }
            BtfType::Typedef(t) => {
                self.set_emit_state(id, EmitState::Emitting);
                self.emit_type(t.type_id, id)?;
                if !self.get_fwd_emitted(id) {
                    // emit typedef right now, if someone depends on it "weakly" (though pointer)
                    if self.emit_typedef_def(id, t, 0) {
                        println!(";\n");
                    }
                    self.set_fwd_emitted(id, true);
                }
                self.set_emit_state(id, EmitState::Emitted);
            }
        }
        Ok(())
    }

    fn get_fwd_emitted(&self, id: u32) -> bool {
        self.state[id as usize].fwd_emitted
    }

    fn set_fwd_emitted(&mut self, id: u32, emitted: bool) {
        self.state[id as usize].fwd_emitted = emitted;
    }

    fn get_order_state(&self, id: u32) -> OrderState {
        self.state[id as usize].order_state
    }

    fn set_order_state(&mut self, id: u32, state: OrderState) {
        self.state[id as usize].order_state = state;
    }

    fn get_emit_state(&self, id: u32) -> EmitState {
        self.state[id as usize].emit_state
    }

    fn set_emit_state(&mut self, id: u32, state: EmitState) {
        self.state[id as usize].emit_state = state;
    }

    fn emit_composite_fwd(&mut self, id: u32, t: &'a BtfComposite) -> bool {
        if NAMES_BLACKLIST.is_match(&t.name) {
            return false;
        }
        let keyword = if !t.is_struct && self.cfg.union_as_struct {
            "struct /*union*/"
        } else if t.is_struct {
            "struct"
        } else {
            "union"
        };
        print!(
            "{} {}",
            keyword,
            self.resolve_type_name(NamedKind::Type, id, t.name)
        );
        return true;
    }

    fn emit_composite_def(&mut self, id: u32, t: &'a BtfComposite, lvl: usize) {
        if NAMES_BLACKLIST.is_match(&t.name) {
            return;
        }
        let keyword = if !t.is_struct && self.cfg.union_as_struct {
            "struct /*union*/"
        } else if t.is_struct {
            "struct"
        } else {
            "union"
        };
        let packed = self.is_struct_packed(id, t);
        let name = self.resolve_type_name(NamedKind::Type, id, t.name);
        print!("{}{}{} {{", keyword, sep(&name), name);
        let mut offset = 0;
        for m in &t.members {
            self.emit_bit_padding(offset, m, packed, lvl + 1);

            print!("\n{}", pfx(lvl + 1));
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);

            if m.bit_size == 0 {
                offset = m.bit_offset + self.btf.get_size_of(m.type_id) * 8;
            } else {
                print!(": {}", m.bit_size);
                offset = m.bit_offset + m.bit_size as u32;
            }
            print!(";");
        }
        if !t.members.is_empty() {
            print!("\n");
        }
        print!("{}}}", pfx(lvl));
        if packed {
            print!(" __attribute__((packed))");
        }
    }

    fn is_struct_packed(&self, id: u32, t: &BtfComposite) -> bool {
        if !t.is_struct {
            return false;
        }
        // size of a struct has to be a multiple of its alignment
        if t.sz % self.btf.get_align_of(id) != 0 {
            return true;
        }
        // all the non-bitfield fields have to be naturally aligned
        for m in &t.members {
            if m.bit_size == 0 && m.bit_offset % (self.btf.get_align_of(m.type_id) * 8) != 0 {
                return true;
            }
        }
        // even if original struct was marked as packed, we haven't detected any misalignment, so
        // there is no effect of packedness for given struct
        return false;
    }

    fn emit_bit_padding(&self, offset: u32, m: &BtfMember, packed: bool, lvl: usize) {
        if offset >= m.bit_offset {
            return;
        }
        let mut bit_diff = m.bit_offset - offset;
        let align = if packed {
            1
        } else {
            self.btf.get_align_of(m.type_id)
        };
        if m.bit_size == 0 && bit_diff < align * 8 {
            // natural padding will take care of a gap
            return;
        }
        let ptr_sz_bits = self.btf.ptr_sz() * 8;
        while bit_diff > 0 {
            let (pad_type, pad_bits) = if ptr_sz_bits > 32 && bit_diff > 32 {
                ("long", CDumper::chip_away_bits(bit_diff, ptr_sz_bits))
            } else if bit_diff > 16 {
                ("int", CDumper::chip_away_bits(bit_diff, 32))
            } else if bit_diff > 8 {
                ("short", CDumper::chip_away_bits(bit_diff, 16))
            } else {
                ("char", CDumper::chip_away_bits(bit_diff, 8))
            };
            bit_diff -= pad_bits;
            print!("\n{}{}: {};", pfx(lvl), pad_type, pad_bits);
        }
    }

    fn chip_away_bits(total: u32, at_most: u32) -> u32 {
        if total % at_most == 0 {
            at_most
        } else {
            total % at_most
        }
    }

    fn emit_enum_def(&mut self, id: u32, t: &'a BtfEnum, lvl: usize) {
        if NAMES_BLACKLIST.is_match(&t.name) {
            return;
        }
        let name = self.resolve_type_name(NamedKind::Type, id, t.name);
        if t.values.is_empty() {
            // enum fwd
            print!("enum{}{}", sep(&name), name);
        } else {
            print!("enum{}{} {{", sep(&name), name);
            for v in &t.values {
                let val_uniq_name = self.resolve_name(NamedKind::Ident, &v.name);
                print!("\n{}{} = {},", pfx(lvl + 1), &val_uniq_name, v.value);
            }
            print!("\n{}}}", pfx(lvl));
        }
    }

    fn emit_fwd_def(&mut self, id: u32, t: &'a BtfFwd) {
        if NAMES_BLACKLIST.is_match(&t.name) {
            return;
        }
        let name = self.resolve_type_name(NamedKind::Type, id, t.name);
        match t.kind {
            BtfFwdKind::Struct => print!("struct {}", name),
            BtfFwdKind::Union => {
                if self.cfg.union_as_struct {
                    print!("struct /*union*/ {}", name)
                } else {
                    print!("union {}", name)
                }
            }
        }
    }

    fn emit_typedef_def(&mut self, id: u32, t: &'a BtfTypedef, lvl: usize) -> bool {
        if NAMES_BLACKLIST.is_match(&t.name) {
            return false;
        }
        let name = self.resolve_type_name(NamedKind::Ident, id, t.name);
        print!("typedef ");
        self.emit_type_decl(t.type_id, &name, lvl);
        return true;
    }

    fn emit_type_decl(&mut self, mut id: u32, fname: &str, lvl: usize) {
        // This algorithm emits correct C syntax for any type definition.
        //
        // For most types it's trivial, but there are few quirky type declaration  cases worth
        // mentioning:
        //   - function prototypes;
        //   - arrays;
        //   - const/volatile/restrict for pointers vs other types.
        // See Peter van der Linden's "Expert C Programming: Deep C Secrets", Ch.3 "Unscrambling
        // Declarations in C" for good discussion of this topic.
        //
        // This algorithm is in reverse to van der Linden's parsing algorithm. It goes from
        // structured BTF representation of type declaration to a valid compilable C syntax.
        let mut chain = Vec::new();
        loop {
            chain.push(id);
            match self.btf.type_by_id(id) {
                BtfType::Ptr(t) => id = t.type_id,
                BtfType::Const(t) => id = t.type_id,
                BtfType::Volatile(t) => id = t.type_id,
                BtfType::Restrict(t) => id = t.type_id,
                BtfType::Array(t) => id = t.val_type_id,
                BtfType::FuncProto(t) => id = t.res_type_id,
                BtfType::Var(_) | BtfType::Datasec(_) | BtfType::Func(_) => {
                    chain.pop();
                    print!("!@#! UNEXPECT TYPE DECL CHAIN ");
                    for parent_id in chain.iter().rev() {
                        print!("[{}] --> ", parent_id);
                    }
                    print!("[{}] {}", id, self.btf.type_by_id(id));
                    return;
                }
                _ => break,
            }
        }
        self.emit_type_chain(chain, fname, lvl);
    }

    fn emit_type_chain(&mut self, mut chain: Vec<u32>, fname: &str, lvl: usize) {
        // default to true, in case we have single ptr in a chain. E.g., in ptr -> func_proto case.
        // func_proto will start a new emit_type_chain with just ptr, which should be emitted as
        // (*) or (*<fname>), so we don't want to preprend space for that last ptr.
        let mut last_was_ptr = true;
        while let Some(id) = chain.pop() {
            match self.btf.type_by_id(id) {
                BtfType::Void => {
                    self.emit_mods(&mut chain);
                    print!("void");
                }
                BtfType::Int(t) => {
                    self.emit_mods(&mut chain);
                    print!("{}", t.name);
                }
                BtfType::Struct(t) | BtfType::Union(t) => {
                    self.emit_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_composite_def(id, t, lvl); // inline anonymous struct
                    } else {
                        self.emit_composite_fwd(id, t);
                    }
                }
                BtfType::Enum(t) => {
                    self.emit_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_enum_def(id, t, lvl); // inline anonymous enum
                    } else {
                        let uniq_name = self.resolve_type_name(NamedKind::Type, id, t.name);
                        print!("enum {}", &uniq_name);
                    }
                }
                BtfType::Fwd(t) => {
                    self.emit_mods(&mut chain);
                    self.emit_fwd_def(id, t);
                }
                BtfType::Typedef(t) => {
                    self.emit_mods(&mut chain);
                    let uniq_name = self.resolve_type_name(NamedKind::Ident, id, t.name);
                    print!("{}", &uniq_name);
                }
                BtfType::Ptr(_) => {
                    if last_was_ptr {
                        print!("*")
                    } else {
                        print!(" *")
                    }
                }
                BtfType::Volatile(_) => {
                    print!(" volatile");
                }
                BtfType::Const(_) => {
                    print!(" const");
                }
                BtfType::Restrict(_) => {
                    print!(" restrict");
                }
                BtfType::Array(t) => {
                    // GCC has a bug (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=8354) which
                    // causes it to emit extra const/volatile modifier for array, if array's
                    // element type has const/volatile modifier. Clang doesn't do that.
                    // In general, it doesn't seem very meaningful to have a const/volatile
                    // modifier for array, so we are going to silently skip them here.
                    while let Some(id) = chain.pop() {
                        match self.btf.type_by_id(id) {
                            BtfType::Volatile(_) | BtfType::Const(_) | BtfType::Restrict(_) => {}
                            _ => {
                                chain.push(id);
                                break;
                            }
                        }
                    }
                    if let Some(&next_id) = chain.last() {
                        let t = self.btf.type_by_id(next_id);
                        if !fname.is_empty() && !last_was_ptr {
                            print!(" ");
                        }
                        if t.kind() != BtfKind::Array {
                            print!("(");
                        }
                        self.emit_type_chain(chain, fname, lvl);
                        if t.kind() != BtfKind::Array {
                            print!(")");
                        }
                    } else {
                        self.emit_name(fname, last_was_ptr);
                    }
                    print!("[{}]", t.nelems);
                    return;
                }
                BtfType::FuncProto(t) => {
                    self.emit_mods(&mut chain);
                    if chain.is_empty() {
                        self.emit_name(fname, last_was_ptr);
                    } else {
                        print!(" (");
                        self.emit_type_chain(chain, fname, lvl);
                        print!(")");
                    }
                    print!("(");
                    //
                    // Clang for BPF target generates func_proto with no args as a func_proto with
                    // a single void arg (i.e., <ret-type> (*f)(void) vs just <ret_type> (*f)()).
                    // We are going to pretend there are no args for such case.
                    let arg_cnt = t.params.len();
                    if arg_cnt == 1 && t.params[0].type_id == 0 {
                        print!(")");
                        return;
                    }

                    for (i, p) in t.params.iter().enumerate() {
                        if i > 0 {
                            print!(", ");
                        }
                        // func_proto with vararg has last arg of type 'void'
                        if i == arg_cnt - 1 && t.params[arg_cnt - 1].type_id == 0 {
                            print!("...");
                        } else {
                            self.emit_type_decl(p.type_id, &p.name, lvl);
                        }
                    }
                    print!(")");
                    return;
                }
                BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {
                    print!(
                        "!@#! UNEXPECT TYPE DECL id: {}, type: {}",
                        id,
                        self.btf.type_by_id(id)
                    );
                }
            }
            if let BtfType::Ptr(_) = self.btf.type_by_id(id) {
                last_was_ptr = true;
            } else {
                last_was_ptr = false;
            }
        }
        self.emit_name(fname, last_was_ptr);
    }

    fn emit_name(&self, fname: &str, last_was_ptr: bool) {
        if last_was_ptr {
            print!("{}", fname);
        } else {
            print!("{}{}", sep(fname), fname);
        }
    }

    fn emit_mods(&self, chain: &mut Vec<u32>) {
        while let Some(id) = chain.pop() {
            match self.btf.type_by_id(id) {
                BtfType::Volatile(_) => {
                    print!("volatile ");
                }
                BtfType::Const(_) => {
                    print!("const ");
                }
                BtfType::Restrict(_) => {
                    print!("restrict ");
                }
                _ => {
                    chain.push(id);
                    break;
                }
            }
        }
    }

    fn resolve_type_name(&mut self, kind: NamedKind, id: u32, name: &'a str) -> String {
        if name.is_empty() {
            return EMPTY.to_owned();
        }
        let s = &mut self.state[id as usize];
        if s.name.is_empty() {
            let version = self.names.entry((kind, name)).or_insert(0);
            *version += 1;
            if *version == 1 {
                s.name = name.to_string()
            } else {
                s.name = format!("{}___{}", name, version)
            }
        }
        s.name.clone()
    }

    fn resolve_name(&mut self, kind: NamedKind, name: &'a str) -> String {
        let version = self.names.entry((kind, name)).or_insert(0);
        *version += 1;
        if *version == 1 {
            name.to_string()
        } else {
            format!("{}___{}", name, version)
        }
    }
}

lazy_static! {
    static ref NAMES_BLACKLIST: RegexSet =
        RegexSet::new(&["__builtin_va_list"]).expect("invalid blacklist regexes");
}

const EMPTY: &str = "";
const SPACE: &str = " ";
const PREFIXES: &str = "\t\t\t\t\t\t\t\t\t\t\t\t";

fn sep(name: &str) -> &str {
    if name.is_empty() {
        EMPTY
    } else {
        SPACE
    }
}

fn pfx(lvl: usize) -> &'static str {
    if lvl >= PREFIXES.len() {
        PREFIXES
    } else {
        &PREFIXES[0..lvl]
    }
}
