use std::collections::HashMap;

use crate::btf::*;
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
    Composite,
    Typedef,
    Func,
}

pub struct CDumper<'a> {
    btf: &'a Btf,
    verbose: bool,
    state: Vec<TypeState>,
    names: HashMap<(NamedKind, &'a str), u32>,
}

impl<'a> CDumper<'a> {
    pub fn new(btf: &'a Btf, verbose: bool) -> CDumper<'a> {
        let mut dumper = CDumper {
            btf: btf,
            verbose: verbose,
            state: Vec::new(),
            names: HashMap::new(),
        };
        dumper
            .state
            .resize_with(btf.type_cnt() as usize, Default::default);
        dumper
    }

    pub fn dump_types<F>(&mut self, filter: F) -> BtfResult<()>
    where
        F: Fn(&BtfType) -> bool,
    {
        let mut order = Vec::new();
        for id in 0..self.btf.type_cnt() {
            let bt = self.btf.type_by_id(id);
            if self.is_named_def(id) && filter(bt) {
                if self.verbose {
                    eprintln!("ORDERING id: {}, type: {}", id, bt);
                }
                self.order_type(id, false, &mut order)?;
            }
        }
        if self.verbose {
            for (i, &id) in order.iter().enumerate() {
                eprintln!("ORDER #{} id: {}, type: {}", i, id, self.btf.type_by_id(id));
            }
        }
        // emit struct/union and fwds required by them in correct order
        for id in order {
            if self.verbose {
                println!("XXX id:{}, is_named_def:{}", id, self.is_named_def(id));
            }
            if self.is_named_def(id) {
                self.emit_type_fwds(id, id, true)?;
                if self.verbose {
                    println!("FWDS id: {}, type: {}", id, self.btf.type_by_id(id));
                }
                self.emit_type_def(id)?;
                if self.verbose {
                    println!("DEF id: {}, type: {}", id, self.btf.type_by_id(id));
                }
            }
        }
        Ok(())
    }

    fn order_type(&mut self, id: u32, has_ptr: bool, order: &mut Vec<u32>) -> BtfResult<()> {
        if self.verbose {
            eprintln!(
                "ORDER TYPE id:{}, has_ptr:{}, type:{}, is_def:{}, order_state:{:?}",
                id,
                has_ptr,
                self.btf.type_by_id(id),
                self.is_def(id),
                self.get_order_state(id)
            );
        }
        // order state is used to detect strong link cycles, but only for BTF kinds that are or
        // could be an independent definition (i.e., stand-alone fwd decl, enum, typedef, struct,
        // union). Ptrs, arrays, func_protos, modifiers are just means to get to these definitions.
        // Int/void don't need definitions, they are assumed to be always properly defined.
        // We also ignore datasec, var, and funcs.
        if self.is_def(id) {
            match self.get_order_state(id) {
                OrderState::NotOrdered => self.set_order_state(id, OrderState::Ordering),
                OrderState::Ordering => match self.btf.type_by_id(id) {
                    BtfType::Struct(t) if has_ptr && !t.name.is_empty() => return Ok(()),
                    BtfType::Union(t) if has_ptr && !t.name.is_empty() => return Ok(()),
                    // XXX: we should check that typedef doesn't have embedded struct/union
                    // (directly or indirectly through array/func_proto/ptr
                    BtfType::Typedef(_t) if has_ptr => return Ok(()),
                    _ => {
                        return btf_error(format!(
                            "Unsatisfiable type cycle, id: {}, type: {}",
                            id,
                            self.btf.type_by_id(id)
                        ));
                    }
                },
                OrderState::Ordered => return Ok(()),
            }
        }
        match self.btf.type_by_id(id) {
            BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {}
            BtfType::Void | BtfType::Int(_) => {}
            BtfType::Volatile(t) => self.order_type(t.type_id, has_ptr, order)?,
            BtfType::Const(t) => self.order_type(t.type_id, has_ptr, order)?,
            BtfType::Restrict(t) => self.order_type(t.type_id, has_ptr, order)?,
            BtfType::Ptr(t) => self.order_type(t.type_id, true, order)?,
            BtfType::Array(t) => self.order_type(t.val_type_id, has_ptr, order)?,
            BtfType::FuncProto(t) => {
                self.order_type(t.res_type_id, has_ptr, order)?;
                for p in &t.params {
                    self.order_type(p.type_id, has_ptr, order)?;
                }
            }
            BtfType::Struct(t) => {
                // struct/union is part of strong link, only if it's embedded (so no ptr in a path)
                // or it's anonymous (so has to be defined inline, even if declared through ptr)
                if !has_ptr || t.name.is_empty() {
                    for m in &t.members {
                        self.order_type(m.type_id, false, order)?;
                    }
                    // no need to explicitly order anonymous embedded struct
                    if !t.name.is_empty() {
                        order.push(id);
                    }
                } else {
                    self.set_order_state(id, OrderState::NotOrdered);
                }
            }
            BtfType::Union(t) => {
                // see above comment for struct
                if !has_ptr || t.name.is_empty() {
                    for m in &t.members {
                        self.order_type(m.type_id, false, order)?;
                    }
                    // no need to explicitly order anonymous embedded struct
                    if !t.name.is_empty() {
                        order.push(id);
                    }
                } else {
                    self.set_order_state(id, OrderState::NotOrdered);
                }
            }
            BtfType::Enum(_) | BtfType::Fwd(_) => order.push(id),
            BtfType::Typedef(t) => {
                self.order_type(t.type_id, has_ptr, order)?;
                order.push(id);
            }
        }
        // weakly-referenced struct/union can reset OrderState to NotOrdered
        if self.get_order_state(id) == OrderState::Ordering {
            self.set_order_state(id, OrderState::Ordered);
        }
        Ok(())
    }

    fn emit_type_fwds(&mut self, id: u32, cont_id: u32, is_def: bool) -> BtfResult<()> {
        self.cache_name(id);
        match self.get_emit_state(id) {
            EmitState::NotEmitted => {}
            EmitState::Emitting => match self.btf.type_by_id(id) {
                BtfType::Struct(t) => {
                    // fwd was already emitted or no need for fwd declare if we are referencing
                    // a struct/union we are part of
                    if self.get_fwd_emitted(id) || id == cont_id {
                        return Ok(());
                    }
                    if !t.name.is_empty() {
                        if self.verbose {
                            print!("AAA ");
                        }
                        println!("struct {};\n", self.resolve_name(id));
                        self.set_fwd_emitted(id, true);
                        return Ok(());
                    } else {
                        return btf_error(format!(
                            "anonymous struct loop, id: {}, type: {}",
                            id,
                            self.btf.type_by_id(id)
                        ));
                    }
                }
                BtfType::Union(t) => {
                    // fwd was already emitted or no need for fwd declare if we are referencing
                    // a struct/union we are part of
                    if self.get_fwd_emitted(id) || id == cont_id {
                        return Ok(());
                    }
                    if !t.name.is_empty() {
                        println!("union {};\n", self.resolve_name(id));
                        self.set_fwd_emitted(id, true);
                        return Ok(());
                    } else {
                        return btf_error(format!(
                            "anonymous union loop, id: {}, type: {}",
                            id,
                            self.btf.type_by_id(id)
                        ));
                    }
                }
                BtfType::Typedef(t) => {
                    // for typedef fwd_emitted means typedef definition was emitted, but it can be
                    // used only for "weak" references through pointer only
                    if self.get_fwd_emitted(id) {
                        return Ok(());
                    }
                    self.emit_typedef_def(t, self.resolve_name(id), 0);
                    println!("\n");
                    self.set_fwd_emitted(id, true);
                    return Ok(());
                }
                _ => return Ok(()),
            },
            EmitState::Emitted => return Ok(()),
        }
        self.set_emit_state(id, EmitState::Emitting);
        match self.btf.type_by_id(id) {
            BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {}
            BtfType::Void | BtfType::Int(_) => {}
            BtfType::Volatile(t) => self.emit_type_fwds(t.type_id, cont_id, false)?,
            BtfType::Const(t) => self.emit_type_fwds(t.type_id, cont_id, false)?,
            BtfType::Restrict(t) => self.emit_type_fwds(t.type_id, cont_id, false)?,
            BtfType::Ptr(t) => self.emit_type_fwds(t.type_id, cont_id, false)?,
            BtfType::Array(t) => self.emit_type_fwds(t.val_type_id, cont_id, false)?,
            BtfType::FuncProto(t) => {
                self.emit_type_fwds(t.res_type_id, cont_id, false)?;
                for p in &t.params {
                    self.emit_type_fwds(p.type_id, cont_id, false)?;
                }
            }
            BtfType::Struct(t) => {
                if is_def || t.name.is_empty() {
                    // top-level struct definition or embedded anonymous struct, ensure all field
                    // types have their fwds declared
                    for m in &t.members {
                        self.emit_type_fwds(m.type_id, cont_id, false)?;
                    }
                } else if !self.get_fwd_emitted(id) && id != cont_id {
                    if self.verbose {
                        print!("BBB ");
                    }
                    println!("struct {};\n", self.resolve_name(id));
                    self.set_fwd_emitted(id, true);
                }
                // XXX: just emit definition directly
                self.set_emit_state(id, EmitState::NotEmitted);
            }
            BtfType::Union(t) => {
                if is_def || t.name.is_empty() {
                    // top-level union definition or embedded anonymous union, ensure all field
                    // types have their fwds declared
                    for m in &t.members {
                        self.emit_type_fwds(m.type_id, cont_id, false)?;
                    }
                } else if !self.get_fwd_emitted(id) && id != cont_id {
                    println!("union {};\n", self.resolve_name(id));
                    self.set_fwd_emitted(id, true);
                }
                // XXX: just emit definition directly
                self.set_emit_state(id, EmitState::NotEmitted);
            }
            BtfType::Enum(t) => {
                if !t.name.is_empty() {
                    self.emit_enum_def(t, self.resolve_name(id), 0);
                    println!(";\n");
                }
            }
            BtfType::Fwd(_) => {
                self.emit_type_decl(id, "", 0);
                println!(";\n");
            }
            BtfType::Typedef(t) => {
                self.emit_type_fwds(t.type_id, id, false)?;
                // XXX: just emit definition directly
                if !is_def && !self.get_fwd_emitted(id) {
                    // emit typedef right now, if someone depends on it "weakly" (though pointer)
                    self.emit_typedef_def(t, self.resolve_name(id), 0);
                    println!(";\n");
                } else {
                    self.set_emit_state(id, EmitState::NotEmitted);
                }
            }
        }
        // don't override EmitState::FwdEmitted
        if self.get_emit_state(id) == EmitState::Emitting {
            self.set_emit_state(id, EmitState::Emitted);
        }
        Ok(())
    }

    fn emit_type_def(&mut self, id: u32) -> BtfResult<()> {
        if self.verbose {
            println!(
                "EMIT_TYPE_DEF1 id:{} state:{:?} fwd_emitted:{}",
                id,
                self.get_emit_state(id),
                self.get_fwd_emitted(id),
            );
        }
        match self.get_emit_state(id) {
            EmitState::NotEmitted => {}
            EmitState::Emitting => {
                return btf_error(format!(
                    "unexpected emit_type_def loop at id:{}, type:{}",
                    id,
                    self.btf.type_by_id(id)
                ));
            }
            EmitState::Emitted => return Ok(()),
        }
        if self.verbose {
            println!("EMIT_TYPE_DEF2 id:{}", id);
        }
        self.cache_name(id);
        match self.btf.type_by_id(id) {
            BtfType::Struct(t) if !t.name.is_empty() => {
                self.emit_struct_def(t, self.resolve_name(id), 0);
                println!(";\n");
            }
            BtfType::Union(t) if !t.name.is_empty() => {
                self.emit_union_def(t, self.resolve_name(id), 0);
                println!(";\n");
            }
            BtfType::Enum(t) if !t.name.is_empty() => {
                self.emit_enum_def(t, self.resolve_name(id), 0);
                println!(";\n");
            }
            BtfType::Fwd(t) if !t.name.is_empty() => {
                self.emit_fwd_def(t, self.resolve_name(id));
                println!(";\n");
            }
            BtfType::Typedef(t) if !t.name.is_empty() => {
                self.emit_typedef_def(t, self.resolve_name(id), 0);
                println!(";\n");
            }
            _ => {
                return btf_error(format!(
                    "unexpected definition at id:{}, type:{}",
                    id,
                    self.btf.type_by_id(id)
                ));
            }
        }
        if self.verbose {
            println!("EMIT_TYPE_DEF3 id:{}", id);
        }
        self.set_emit_state(id, EmitState::Emitted);
        Ok(())
    }

    fn is_def(&self, id: u32) -> bool {
        match self.btf.type_by_id(id) {
            BtfType::Struct(_)
            | BtfType::Union(_)
            | BtfType::Enum(_)
            | BtfType::Fwd(_)
            | BtfType::Typedef(_) => true,
            _ => false,
        }
    }

    fn is_named_def(&self, id: u32) -> bool {
        match self.btf.type_by_id(id) {
            BtfType::Struct(t) if !t.name.is_empty() => true,
            BtfType::Union(t) if !t.name.is_empty() => true,
            BtfType::Enum(t) if !t.name.is_empty() => true,
            BtfType::Fwd(t) if !t.name.is_empty() => true,
            BtfType::Typedef(t) if !t.name.is_empty() => true,
            _ => false,
        }
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

    fn emit_struct_def(&self, t: &BtfStruct, name: &str, lvl: usize) {
        print!("struct{}{} {{", sep(name), name);
        for m in &t.members {
            print!("\n{}", pfx(lvl + 1));
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        if !t.members.is_empty() {
            print!("\n");
        }
        print!("{}}}", pfx(lvl));
    }

    fn emit_union_def(&self, t: &BtfUnion, name: &str, lvl: usize) {
        print!("union{}{} {{", sep(&name), name);
        for m in &t.members {
            print!("\n{}", pfx(lvl + 1));
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        if !t.members.is_empty() {
            print!("\n");
        }
        print!("{}}}", pfx(lvl));
    }

    fn emit_enum_def(&self, t: &BtfEnum, name: &str, lvl: usize) {
        if t.values.is_empty() {
            // enum fwd
            print!("enum{}{}", sep(&name), name);
        } else {
            print!("enum{}{} {{", sep(&name), name);
            for v in &t.values {
                print!("\n{}{} = {},", pfx(lvl + 1), v.name, v.value);
            }
            print!("\n{}}}", pfx(lvl));
        }
    }

    fn emit_fwd_def(&self, t: &BtfFwd, name: &str) {
        match t.kind {
            BtfFwdKind::Struct => print!("struct {}", name),
            BtfFwdKind::Union => print!("union {}", name),
        }
    }

    fn emit_typedef_def(&self, t: &BtfTypedef, name: &str, lvl: usize) {
        print!("typedef ");
        self.emit_type_decl(t.type_id, name, lvl);
    }

    fn emit_type_decl(&self, mut id: u32, fname: &str, lvl: usize) {
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

    fn emit_type_chain(&self, mut chain: Vec<u32>, fname: &str, lvl: usize) {
        // default to true, in case we have single ptr in a chain. E.g., in ptr -> func_proto case.
        // func_proto will start a new emit_type_chain with just ptr, which should be emitted as
        // (*) or (*<fname>), so we don't want to preprend space for that last ptr.
        let mut last_was_ptr = true;
        while let Some(id) = chain.pop() {
            match self.btf.type_by_id(id) {
                BtfType::Void => {
                    self.emit_non_ptr_mods(&mut chain);
                    print!("void");
                }
                BtfType::Int(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    print!("{}", t.name);
                }
                BtfType::Struct(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_struct_def(t, "", lvl); // inline anonymous struct
                    } else {
                        print!("struct {}", self.resolve_name(id));
                    }
                }
                BtfType::Union(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_union_def(t, "", lvl); // inline anonymous union
                    } else {
                        print!("union {}", self.resolve_name(id));
                    }
                }
                BtfType::Enum(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_enum_def(t, "", lvl); // inline anonymous enum
                    } else {
                        print!("enum {}", self.resolve_name(id));
                    }
                }
                BtfType::Fwd(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    self.emit_fwd_def(t, self.resolve_name(id));
                }
                BtfType::Typedef(_) => {
                    self.emit_non_ptr_mods(&mut chain);
                    print!("{}", self.resolve_name(id));
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
                    if chain.is_empty() {
                        self.emit_name(fname, last_was_ptr);
                    } else {
                        print!(" (");
                        self.emit_type_chain(chain, fname, lvl);
                        print!(")");
                    }
                    print!("[{}]", t.nelems);
                    return;
                }
                BtfType::FuncProto(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if chain.is_empty() {
                        self.emit_name(fname, last_was_ptr);
                    } else {
                        print!(" (");
                        self.emit_type_chain(chain, fname, lvl);
                        print!(")");
                    }
                    print!("(");
                    // Clang for BPF target generates func_proto with no args as a func_proto with
                    // a single void arg (i.e., <ret-type> (*f)(void) vs just <ret_type> (*f)()).
                    // We are going to pretend there are no args for such case.
                    let arg_cnt = t.params.len();
                    if arg_cnt != 1 || t.params[0].type_id != 0 {
                        let mut idx = 0;
                        for p in &t.params {
                            if idx > 0 {
                                print!(", ");
                            }
                            // func_proto with vararg has last arg of type 'void'
                            if idx == arg_cnt - 1 && t.params[arg_cnt - 1].type_id == 0 {
                                print!("...");
                            } else {
                                self.emit_type_decl(p.type_id, &p.name, lvl);
                            }
                            idx = idx + 1;
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

    fn emit_non_ptr_mods(&self, chain: &mut Vec<u32>) {
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

    fn cache_name(&mut self, id: u32) {
        match self.btf.type_by_id(id) {
            BtfType::Struct(t) => self.cache_kind_name(NamedKind::Composite, id, &t.name),
            BtfType::Union(t) => self.cache_kind_name(NamedKind::Composite, id, &t.name),
            BtfType::Enum(t) => self.cache_kind_name(NamedKind::Composite, id, &t.name),
            BtfType::Fwd(t) => self.cache_kind_name(NamedKind::Composite, id, &t.name),
            BtfType::Typedef(t) => self.cache_kind_name(NamedKind::Typedef, id, &t.name),
            BtfType::Func(t) => self.cache_kind_name(NamedKind::Func, id, &t.name),
            _ => {}
        }
    }

    fn cache_kind_name(&mut self, kind: NamedKind, id: u32, name: &'a str) {
        if name.is_empty() {
            return;
        }
        let s = &mut self.state[id as usize];
        if s.name.is_empty() {
            let version = self.names.entry((kind, name)).or_insert(0);
            *version = *version + 1;
            if *version == 1 {
                s.name = name.to_string();
            } else {
                s.name = format!("{}__{}", name, version);
            }
        }
    }

    fn resolve_name(&self, id: u32) -> &str {
        &self.state[id as usize].name
    }
}

const EMPTY: &str = "";
const SPACE: &str = " ";
const PREFIXES: [&str; 13] = [
    "",
    "\t",
    "\t\t",
    "\t\t\t",
    "\t\t\t\t",
    "\t\t\t\t\t",
    "\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t\t\t\t\t",
];

fn sep(name: &str) -> &str {
    if name.is_empty() {
        EMPTY
    } else {
        SPACE
    }
}

fn pfx(lvl: usize) -> &'static str {
    if lvl >= PREFIXES.len() {
        PREFIXES[PREFIXES.len() - 1]
    } else {
        PREFIXES[lvl]
    }
}
