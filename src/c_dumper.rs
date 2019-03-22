use crate::btf::*;
use crate::BtfResult;

enum EmitState {
    NotEmitted,
    Emitting,
    FwdEmitted,
    Emitted,
}

impl Default for EmitState {
    fn default() -> Self {
        EmitState::NotEmitted
    }
}

#[derive(Default)]
struct TypeState {
    emit_state: EmitState,
}

pub struct CDumper<'a> {
    btf: &'a Btf,
    state: Vec<TypeState>,
}

impl<'a> CDumper<'a> {
    pub fn new(btf: &'a Btf) -> CDumper<'a> {
        let mut dumper = CDumper {
            btf: btf,
            state: Vec::new(),
        };
        dumper.state.resize_with(btf.type_cnt(), Default::default);
        dumper
    }

    pub fn dump_type(&mut self, id: u32) -> BtfResult<()> {
        self.emit_type(id, id)
    }

    pub fn emit_type(&mut self, id: u32, container_id: u32) -> BtfResult<()> {
        let bt = self.btf.type_by_id(id);

        let mut s = &mut self.state[id as usize];
        match s.emit_state {
            EmitState::NotEmitted => s.emit_state = EmitState::Emitting,
            EmitState::Emitting => {
                // no need for fwd declaration if we are referencing a struct/union we are part of
                if id == container_id {
                    return Ok(());
                }
                // only struct, union and enum can be forward-declared
                match bt {
                    BtfType::Struct(t) => println!("struct {};\n", t.name),
                    BtfType::Union(t) => println!("union {};\n", t.name),
                    BtfType::Enum(t) => println!("enum {};\n", t.name),
                    _ => return Ok(()),
                }
                s.emit_state = EmitState::FwdEmitted;
                return Ok(());
            }
            EmitState::FwdEmitted => return Ok(()),
            EmitState::Emitted => return Ok(()),
        }

        match bt {
            BtfType::Void | BtfType::Int(_) => {}
            BtfType::Var(_) | BtfType::Datasec(_) => {}
            BtfType::Ptr(t) => self.emit_type(t.type_id, container_id)?,
            BtfType::Volatile(t) => self.emit_type(t.type_id, container_id)?,
            BtfType::Const(t) => self.emit_type(t.type_id, container_id)?,
            BtfType::Restrict(t) => self.emit_type(t.type_id, container_id)?,
            BtfType::Array(t) => self.emit_type(t.val_type_id, container_id)?,
            BtfType::FuncProto(t) => {
                self.emit_type(t.res_type_id, container_id)?;
                for p in &t.params {
                    self.emit_type(p.type_id, container_id)?;
                }
            }
            BtfType::Struct(t) => {
                for m in &t.members {
                    self.emit_type(m.type_id, id)?;
                }
                if !t.name.is_empty() {
                    self.emit_struct_def(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Union(t) => {
                for m in &t.members {
                    self.emit_type(m.type_id, id)?;
                }
                if !t.name.is_empty() {
                    self.emit_union_def(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Enum(t) => {
                if !t.name.is_empty() {
                    self.emit_enum_def(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Fwd(_) => {
                self.emit_type_decl(id, "", 0);
                println!(";\n");
            }
            BtfType::Typedef(t) => {
                self.emit_type(t.type_id, container_id)?;
                print!("typedef ");
                self.emit_type_decl(t.type_id, &t.name, 0);
                println!(";\n");
            }
            BtfType::Func(t) => {
                self.emit_type(t.proto_type_id, container_id)?;
                self.emit_type_decl(t.proto_type_id, &t.name, 0);
                println!(";\n");
            }
        }

        self.state[id as usize].emit_state = EmitState::Emitted;

        Ok(())
    }

    fn emit_struct_def(&self, t: &BtfStruct, lvl: usize) {
        print!("struct{}{} {{", sep(&t.name), t.name);
        for m in &t.members {
            print!("\n{}", pfx(lvl + 1));
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        print!("\n{}}}", pfx(lvl));
    }

    fn emit_union_def(&self, t: &BtfUnion, lvl: usize) {
        print!("union{}{} {{", sep(&t.name), t.name);
        for m in &t.members {
            print!("\n{}", pfx(lvl + 1));
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        print!("\n{}}}", pfx(lvl));
    }

    fn emit_enum_def(&self, t: &BtfEnum, lvl: usize) {
        print!("enum{}{} {{", sep(&t.name), t.name);
        for v in &t.values {
            print!("\n{}{} = {},", pfx(lvl + 1), v.name, v.value);
        }
        print!("\n{}}}", pfx(lvl));
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
            let bt = self.btf.type_by_id(id);
            match bt {
                BtfType::Ptr(t) => {
                    chain.push(bt);
                    id = t.type_id;
                }
                BtfType::Const(t) => {
                    chain.push(bt);
                    id = t.type_id;
                }
                BtfType::Volatile(t) => {
                    chain.push(bt);
                    id = t.type_id;
                }
                BtfType::Restrict(t) => {
                    chain.push(bt);
                    id = t.type_id;
                }
                BtfType::Array(t) => {
                    chain.push(bt);
                    id = t.val_type_id;
                }
                BtfType::FuncProto(t) => {
                    chain.push(bt);
                    id = t.res_type_id;
                }
                BtfType::Var(_) | BtfType::Datasec(_) | BtfType::Func(_) => {
                    print!("!@#! UNEXPECT TYPE DECL CHAIN ");
                    for parent_id in chain.iter().rev() {
                        print!("[{}] --> ", parent_id);
                    }
                    print!("[{}] {}", id, bt);
                    return;
                }
                _ => {
                    chain.push(bt);
                    break;
                }
            }
        }
        self.emit_type_chain(chain, fname, lvl);
    }

    fn emit_type_chain(&self, mut chain: Vec<&BtfType>, fname: &str, lvl: usize) {
        // default to true, in case we have single ptr in a chain. E.g., in ptr -> func_proto case.
        // func_proto will start a new emit_type_chain with just ptr, which should be emitted as
        // (*) or (*<fname>), so we don't want to preprend space for that last ptr.
        let mut last_was_ptr = true;
        while let Some(bt) = chain.pop() {
            match bt {
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
                        self.emit_struct_def(t, lvl); // inline anonymous struct
                    } else {
                        print!("struct {}", t.name);
                    }
                }
                BtfType::Union(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_union_def(t, lvl); // inline anonymous union
                    } else {
                        print!("union {}", t.name);
                    }
                }
                BtfType::Enum(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    if t.name.is_empty() {
                        self.emit_enum_def(t, lvl); // inline anonymous enum
                    } else {
                        print!("enum {}", t.name);
                    }
                }
                BtfType::Fwd(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    match t.kind {
                        BtfFwdKind::Struct => print!("struct {}", t.name),
                        BtfFwdKind::Union => print!("union {}", t.name),
                    }
                }
                BtfType::Typedef(t) => {
                    self.emit_non_ptr_mods(&mut chain);
                    print!("{}", t.name);
                }
                BtfType::Ptr(_) => {
                    if last_was_ptr {
                        print!("*");
                    } else {
                        print!(" *");
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
                    self.emit_non_ptr_mods(&mut chain);
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
                    let mut first = true;
                    for p in &t.params {
                        if !first {
                            print!(", ");
                        }
                        first = false;
                        self.emit_type_decl(p.type_id, &p.name, lvl);
                    }
                    print!(")");
                    return;
                }
                BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {
                    print!("!@#! UNEXPECT TYPE DECL TYPE: {}", bt);
                }
            }
            last_was_ptr = match bt {
                BtfType::Ptr(_) => true,
                _ => false,
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

    fn emit_non_ptr_mods(&self, chain: &mut Vec<&BtfType>) {
        while !chain.is_empty() {
            match chain[chain.len() - 1] {
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
                    break;
                }
            }
            chain.pop();
        }
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
