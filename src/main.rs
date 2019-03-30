use std::error::Error;

use memmap;
use object::Object;
use regex::Regex;
use structopt::StructOpt;

use btf::c_dumper;
use btf::types::*;
use btf::{BtfError, BtfResult};

#[derive(Debug)]
enum DumpFormat {
    Human,
    Json,
    JsonPretty,
    C,
}

impl std::str::FromStr for DumpFormat {
    type Err = BtfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human" | "h" => Ok(DumpFormat::Human),
            "json" | "j" => Ok(DumpFormat::Json),
            "json-pretty" | "jp" => Ok(DumpFormat::JsonPretty),
            "c" => Ok(DumpFormat::C),
            _ => Err(BtfError::new_owned(format!(
                "unrecognized dump format: '{}'",
                s
            ))),
        }
    }
}

#[derive(StructOpt)]
struct QueryArgs {
    #[structopt(short = "n", long = "name")]
    /// Regex of type names to include
    name: Option<String>,
    #[structopt(
        short = "t",
        long = "type",
        parse(try_from_str),
        raw(use_delimiter = "true")
    )]
    /// BTF type kinds to include
    kinds: Vec<BtfKind>,
    #[structopt(long = "id", parse(try_from_str), raw(use_delimiter = "true"))]
    /// Type IDs to include
    ids: Vec<u32>,
}

#[derive(StructOpt)]
#[structopt(name = "btfdump")]
/// BTF introspection and manipulation tool
enum Cmd {
    #[structopt(name = "dump")]
    /// Query and pretty-print matching BTF data
    Dump {
        #[structopt(parse(from_os_str))]
        file: std::path::PathBuf,
        #[structopt(
            short = "f",
            long = "format",
            default_value = "human",
            raw(
                possible_values = r#"&["human", "h", "c", "json", "j", "json-pretty", "jp"]"#,
                next_line_help = "true"
            )
        )]
        /// Output format
        format: DumpFormat,
        #[structopt(short = "v", long = "verbose")]
        /// Output verbose log
        verbose: bool,
        #[structopt(flatten)]
        query: QueryArgs,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cmd = Cmd::from_args();

    match cmd {
        Cmd::Dump {
            file,
            format,
            verbose,
            query,
        } => {
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::ElfFile::parse(&*file)?;
            let btf = Btf::load(&file)?;
            let btfext: Option<BtfExt> = if let Some(_) = file.section_by_name(BTF_EXT_ELF_SEC) {
                Some(BtfExt::load(&file)?)
            } else {
                None
            };
            let filter = create_query_filter(query)?;
            match format {
                DumpFormat::Human => {
                    for (i, t) in btf.types().iter().enumerate() {
                        if filter(i as u32, t) {
                            println!("#{}: {}", i, t);
                        }
                    }
                    if let Some(ext) = btfext {
                        for (i, sec) in ext.func_secs().iter().enumerate() {
                            println!("\nFunc section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                println!("#{}: {}", j, rec);
                            }
                        }
                        for (i, sec) in ext.line_secs().iter().enumerate() {
                            println!("\nLine section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                println!("#{}: {}", j, rec);
                            }
                        }
                        for (i, sec) in ext.offset_reloc_secs().iter().enumerate() {
                            println!("\nOffset reloc section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                println!("#{}: {}", j, rec);
                            }
                        }
                    }
                }
                DumpFormat::Json => panic!("JSON output is not yet supported!"),
                DumpFormat::JsonPretty => panic!("JSON output is not yet supported!"),
                DumpFormat::C => {
                    let mut dumper = c_dumper::CDumper::new(&btf, verbose);
                    dumper.dump_types(filter)?;
                }
            }
        }
    }
    Ok(())
}

fn create_query_filter(q: QueryArgs) -> BtfResult<Box<dyn Fn(u32, &BtfType) -> bool>> {
    let mut filters: Vec<Box<dyn Fn(u32, &BtfType) -> bool>> = Vec::new();
    if !q.kinds.is_empty() {
        let kinds = q.kinds;
        filters.push(Box::new(move |_id: u32, bt: &BtfType| -> bool {
            kinds.contains(&bt.kind())
        }));
    }
    if !q.ids.is_empty() {
        let ids = q.ids;
        filters.push(Box::new(move |id: u32, _bt: &BtfType| -> bool {
            ids.contains(&id)
        }));
    }
    if let Some(name) = q.name {
        let name_regex = Regex::new(&name)?;
        filters.push(Box::new(move |_id: u32, bt: &BtfType| -> bool {
            name_regex.is_match(bt.name())
        }));
    }
    if !filters.is_empty() {
        Ok(Box::new(move |id: u32, bt: &BtfType| -> bool {
            for f in &filters {
                if f(id, bt) {
                    return true;
                }
            }
            return false;
        }))
    } else {
        Ok(Box::new(|_: u32, _: &BtfType| true))
    }
}
