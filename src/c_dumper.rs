use std::collections::HashMap;

use crate::btf::*;
use crate::{btf_error, BtfResult};

enum VisitState {
    Unvisited,
    Visiting,
    Visited,
}

impl Default for VisitState {
    fn default() -> Self {
        VisitState::Unvisited
    }
}

#[derive(Default)]
struct TypeState {
    visit: VisitState,
    fwd_emitted: bool,
}

pub struct CDumper<'a> {
    btf: &'a Btf,
    state: HashMap<u32, TypeState>,
}

impl<'a> CDumper<'a> {
    pub fn new(btf: &'a Btf) -> CDumper<'a> {
        CDumper {
            btf: btf,
            state: HashMap::new(),
        }
    }

    pub fn dump(&mut self, id: u32) -> BtfResult<()> {
        let s = self.state.entry(id).or_default();
        let bt = self.btf.type_by_id(id);

        match s.visit {
            VisitState::Unvisited => s.visit = VisitState::Visiting,
            VisitState::Visited => return Ok(()),
            VisitState::Visiting => match bt {
                BtfType::Struct(_) | BtfType::Union(_) | BtfType::Enum(_) => {
                    // we have type loop, have to forward-declare type
                    if !s.fwd_emitted {
                        s.fwd_emitted = true;
                        self.emit_type_decl(id, "", 0);
                        println!(";\n");
                    }
                    return Ok(());
                }
                _ => {
                    return btf_error(format!("Loop detected involving id:{}, type:{}", id, bt));
                }
            },
        }

        match bt {
            BtfType::Void
            | BtfType::Int(_)
            | BtfType::Ptr(_)
            | BtfType::Array(_)
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::FuncProto(_)
            | BtfType::Var(_)
            | BtfType::Datasec(_) => {}
            BtfType::Struct(t) => {
                if !t.name.is_empty() {
                    self.emit_struct(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Union(t) => {
                if !t.name.is_empty() {
                    self.emit_union(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Enum(t) => {
                if !t.name.is_empty() {
                    self.emit_enum(t, 0);
                    println!(";\n");
                }
            }
            BtfType::Fwd(_) => {
                self.emit_type_decl(id, "", 0);
                println!(";\n");
            }
            BtfType::Typedef(t) => {
                print!("typedef ");
                self.emit_type_decl(t.type_id, &t.name, 0);
                println!(";\n");
            }
            BtfType::Func(t) => {
                self.emit_type_decl(t.proto_type_id, &t.name, 0);
                println!(";\n");
            }
        }

        self.mark_visited(id);
        Ok(())
    }

    fn mark_visited(&mut self, id: u32) {
        let mut s = self.state.entry(id).or_default();
        s.visit = VisitState::Visited;
    }

    fn emit_struct(&self, t: &BtfStruct, lvl: usize) {
        print!("{}struct{}{} {{", pfx(lvl), sep(&t.name), t.name);
        for m in &t.members {
            print!("\n");
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        print!("\n{}}}", pfx(lvl));
    }

    fn emit_union(&self, t: &BtfUnion, lvl: usize) {
        print!("{}union{}{} {{", pfx(lvl), sep(&t.name), t.name);
        for m in &t.members {
            print!("\n");
            self.emit_type_decl(m.type_id, &m.name, lvl + 1);
            print!(";");
        }
        print!("\n{}}}", pfx(lvl));
    }

    fn emit_enum(&self, t: &BtfEnum, lvl: usize) {
        print!("{}enum{}{} {{", pfx(lvl), sep(&t.name), t.name);
        for v in &t.values {
            print!("\n{}{} = {},", pfx(lvl + 1), v.name, v.value);
        }
        print!("\n{}}}", pfx(lvl));
    }

    fn emit_type_decl(&self, id: u32, fname: &str, lvl: usize) {
        let bt = self.btf.type_by_id(id);
        match bt {
            BtfType::Void => print!("{}void{}{}", pfx(lvl), sep(fname), fname),
            BtfType::Int(t) => print!("{}{}{}{}", pfx(lvl), t.name, sep(fname), fname),
            BtfType::Ptr(t) => {
                // XXX: handle array and func_proto pointers properly
                self.emit_type_decl(t.type_id, "", lvl);
                print!(" *{}", fname);
            }
            BtfType::Array(t) => {
                self.emit_type_decl(t.val_type_id, "", lvl);
                print!("{}{}[{}]", sep(fname), fname, t.nelems);
            }
            BtfType::Struct(t) => {
                if t.name.is_empty() {
                    self.emit_struct(t, lvl); // inline anonymous struct
                } else {
                    print!("{}struct {}", pfx(lvl), t.name);
                }
                print!("{}{}", sep(fname), fname);
            }
            BtfType::Union(t) => {
                if t.name.is_empty() {
                    self.emit_union(t, lvl); // inline anonymous union
                } else {
                    print!("{}union {}", pfx(lvl), t.name);
                }
                print!("{}{}", sep(fname), fname);
            }
            BtfType::Enum(t) => {
                if t.name.is_empty() {
                    self.emit_enum(t, lvl); // inline anonymous enum
                } else {
                    print!("{}enum {}", pfx(lvl), t.name);
                }
                print!("{}{}", sep(fname), fname);
            }
            BtfType::Fwd(t) => {
                print!("{}", pfx(lvl));
                match t.kind {
                    BtfFwdKind::Struct => print!("struct {}", t.name),
                    BtfFwdKind::Union => print!("union {}", t.name),
                }
                print!("{}{}", sep(fname), fname);
            }
            BtfType::Typedef(t) => print!("{}{}{}{}", pfx(lvl), t.name, sep(fname), fname),
            BtfType::Volatile(t) => {
                print!("volatile ");
                self.emit_type_decl(t.type_id, fname, lvl);
            }
            BtfType::Const(t) => {
                print!("const ");
                self.emit_type_decl(t.type_id, fname, lvl);
            }
            BtfType::Restrict(t) => {
                print!("restrict ");
                self.emit_type_decl(t.type_id, fname, lvl);
            }
            BtfType::FuncProto(t) => {
                self.emit_type_decl(t.res_type_id, "", lvl);
                print!("{}{}(", sep(fname), fname);
                let mut first = true;
                for p in &t.params {
                    if !first {
                        print!(", ");
                    }
                    first = false;
                    self.emit_type_decl(p.type_id, &p.name, 0);
                }
                print!(")");
            }
            BtfType::Func(_) | BtfType::Var(_) | BtfType::Datasec(_) => {
                print!("!@#! UNEXPECT TYPE DECL TYPE id:{}, type:{}", id, bt);
            }
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
