use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryInto as _;
use std::error::Error;
use std::io::Read as _;
use std::io::Write as _;

use bitflags::bitflags;
use clap::builder::TypedValueParser as _;
use memmap2 as memmap;
use object::{Object, ObjectSection};
use regex::Regex;
use scroll::Pread;
use std::mem::size_of;
use std::mem::size_of_val;
use std::str::FromStr as _;

use btf::c_dumper;
use btf::relocator::{Relocator, RelocatorCfg};
use btf::types::*;
use btf::{btf_error, BtfError, BtfResult};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
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

bitflags! {
    #[derive(Clone)]
    struct Datasets : u32 {
        const NONE          = 0b0000;
        const TYPES         = 0b0001;
        const FUNCINFOS     = 0b0010;
        const LINEINFOS     = 0b0100;
        const RELOCS        = 0b1000;

        const DEFAULT = Self::TYPES.bits() | Self::RELOCS.bits();
        const EXT     = Self::FUNCINFOS.bits() | Self::LINEINFOS.bits() | Self::RELOCS.bits();
        const ALL     = Self::TYPES.bits() | Self::EXT.bits();
    }
}

impl Default for Datasets {
    fn default() -> Datasets {
        Datasets::NONE
    }
}

impl std::str::FromStr for Datasets {
    type Err = BtfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Datasets::NONE),
            "types" | "type" | "t" => Ok(Datasets::TYPES),
            "funcs" | "func" | "f" => Ok(Datasets::FUNCINFOS),
            "lines" | "line" | "l" => Ok(Datasets::LINEINFOS),
            "relocs" | "reloc" | "r" => Ok(Datasets::RELOCS),
            "exts" | "ext" | "e" => Ok(Datasets::EXT),
            "all" | "a" => Ok(Datasets::ALL),
            "default" | "def" | "d" => Ok(Datasets::DEFAULT),
            _ => Err(BtfError::new_owned(format!(
                "unrecognized dataset: '{}'",
                s
            ))),
        }
    }
}

#[derive(clap::Parser)]
struct QueryArgs {
    #[clap(short = 'n', long = "name")]
    /// Regex of type names to include
    name: Option<String>,
    #[clap(short = 't', long = "type", use_value_delimiter = true)]
    /// BTF type kinds to include
    kinds: Vec<BtfKind>,
    #[clap(long = "id", use_value_delimiter = true)]
    /// Type IDs to include
    ids: Vec<u32>,
}

#[derive(clap::Parser)]
#[clap(name = "btfdump")]
/// BTF introspection and manipulation tool
enum Cmd {
    #[clap(name = "dump")]
    /// Query and pretty-print matching BTF data
    Dump {
        file: std::path::PathBuf,
        #[clap(
            short = 'f',
            long = "format",
            default_value = "human",
            value_parser = clap::builder::PossibleValuesParser::new([
                "human",
                "h",
                "c",
                "json",
                "j",
                "json-pretty",
                "jp",
            ]).map(|s| DumpFormat::from_str(&s).unwrap()),
        )]
        /// Output format
        format: DumpFormat,
        #[clap(
            short = 'd',
            long = "dataset",
            default_value = "default",
            value_parser = clap::builder::PossibleValuesParser::new([
                "default",
                "def",
                "d",
                "types",
                "type",
                "t",
                "funcs",
                "func",
                "f",
                "lines",
                "line",
                "l",
                "relocs",
                "reloc",
                "r",
                "all",
                "a",
                "exts",
                "ext",
                "none",
            ]).map(|s| Datasets::from_str(&s).unwrap()),
        )]
        /// Datasets to output
        datasets: Datasets,
        #[clap(flatten)]
        query: QueryArgs,
        #[clap(short = 'v', long = "verbose")]
        /// Output verbose log
        verbose: bool,
        #[clap(long = "union-as-struct")]
        /// Replace unions with structs (for BPF CORE)
        union_as_struct: bool,
    },
    #[clap(name = "reloc")]
    /// Print detailed relocation information
    Reloc {
        /// Kernel image (target BTF)
        targ_file: std::path::PathBuf,
        /// BPF program (local BTF)
        local_file: std::path::PathBuf,
        #[clap(short = 'v', long = "verbose")]
        /// Output verbose log
        verbose: bool,
    },
    #[clap(name = "stat")]
    /// Stats about .BTF and .BTF.ext data
    Stat { file: std::path::PathBuf },

    #[clap(name = "version")]
    /// Print btfdump version
    Version,
}

fn load_file<'a>(
    file: impl AsRef<std::path::Path>,
    contents: &'a mut Vec<u8>,
    mmap: &'a mut Option<memmap::Mmap>,
) -> BtfResult<Btf<'a>> {
    let mut file = std::fs::File::open(file)?;

    // Read the magic number first.
    let size = size_of_val(&BTF_MAGIC).try_into()?;
    std::io::Read::by_ref(&mut file)
        .take(size)
        .read_to_end(contents)?;

    if *contents == BTF_MAGIC.to_ne_bytes() {
        // If the file starts with BTF magic number, parse BTF from the
        // full file content.

        file.read_to_end(contents)?;
        Btf::load_raw(&*contents)
    } else {
        // Otherwise, assume it's an object file and  parse BTF from
        // the `.BTF` section.

        let file = unsafe { memmap::Mmap::map(&file) }?;
        let file = &*mmap.insert(file);
        let file = object::File::parse(file.as_ref())?;
        Btf::load_elf(&file)
    }
}

macro_rules! load_btf {
    ($ident:ident, $file:expr) => {
        // These variables must be declared in the caller because the return
        // value of load_file is borrowed from them.
        let mut contents = Vec::new();
        let mut mmap = None;

        let $ident = load_file($file, &mut contents, &mut mmap)?;
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Parser::parse();

    match cmd {
        Cmd::Dump {
            file,
            format,
            datasets,
            query,
            verbose,
            union_as_struct,
        } => {
            load_btf!(btf, file);
            let filter = create_query_filter(query)?;

            match format {
                DumpFormat::Human => {
                    if datasets.contains(Datasets::TYPES) {
                        for (i, t) in btf.types().iter().enumerate() {
                            if filter(i as u32, t) {
                                println!("#{}: {}", i, t);
                            }
                        }
                    }
                    if datasets.contains(Datasets::FUNCINFOS) {
                        for (i, sec) in btf.func_secs().iter().enumerate() {
                            println!("\nFunc section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                println!("#{}: {}", j, rec);
                            }
                        }
                    }
                    if datasets.contains(Datasets::LINEINFOS) {
                        for (i, sec) in btf.line_secs().iter().enumerate() {
                            println!("\nLine section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                println!("#{}: {}", j, rec);
                            }
                        }
                    }
                    if datasets.contains(Datasets::RELOCS) {
                        for (i, sec) in btf.core_reloc_secs().iter().enumerate() {
                            println!("\nCore reloc section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                print!("#{}: {} --> ", j, rec);
                                std::io::stdout().flush()?;
                                match Relocator::pretty_print_access_spec(&btf, rec) {
                                    Ok(s) => print!("{}", s),
                                    Err(e) => print!(" ERROR: {}", e),
                                };
                                println!();
                            }
                        }
                    }
                }
                DumpFormat::Json => panic!("JSON output is not yet supported!"),
                DumpFormat::JsonPretty => panic!("JSON output is not yet supported!"),
                DumpFormat::C => {
                    let cfg = c_dumper::CDumperCfg {
                        verbose,
                        union_as_struct,
                    };
                    let mut dumper = c_dumper::CDumper::new(&btf, cfg);
                    dumper.dump_types(filter)?;
                }
            }
        }
        Cmd::Reloc {
            targ_file,
            local_file,
            verbose,
        } => {
            load_btf!(local_btf, local_file);
            if !local_btf.has_ext() {
                return btf_error(format!(
                    "No {} section found for local ELF file, can't perform relocations.",
                    BTF_EXT_ELF_SEC
                ));
            }
            load_btf!(targ_btf, targ_file);
            let cfg = RelocatorCfg { verbose };
            let mut relocator = Relocator::new(&targ_btf, &local_btf, cfg);
            let relocs = relocator.relocate()?;
            for r in relocs {
                println!("{}", r);
            }
        }
        Cmd::Stat { file } => {
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::File::parse(&*file)?;
            stat_elf(&file)?;
        }
        Cmd::Version => {
            println!("btfdump v{}", VERSION);
        }
    }
    Ok(())
}

type Filter = Box<dyn Fn(u32, &BtfType) -> bool>;

fn create_query_filter(q: QueryArgs) -> BtfResult<Filter> {
    let mut filters: Vec<Filter> = Vec::new();
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
            false
        }))
    } else {
        Ok(Box::new(|_: u32, _: &BtfType| true))
    }
}

fn stat_elf(elf: &object::File) -> BtfResult<()> {
    let endian = if elf.is_little_endian() {
        scroll::LE
    } else {
        scroll::BE
    };
    if let Some(btf_section) = elf.section_by_name(BTF_ELF_SEC) {
        let data = btf_section.data()?;
        let hdr = data.pread_with::<btf_header>(0, endian)?;
        println!(
            "{} ELF section\n=======================================",
            BTF_ELF_SEC
        );
        println!("Data size:\t{}", data.len());
        println!("Header size:\t{}", hdr.hdr_len);
        println!("Types size:\t{}", hdr.type_len);
        println!("Strings size:\t{}", hdr.str_len);
    } else {
        println!("{} not found.", BTF_ELF_SEC);
        return Ok(());
    }
    println!(
        "\n{} ELF section\n========================================",
        BTF_EXT_ELF_SEC
    );
    if let Some(ext_section) = elf.section_by_name(BTF_EXT_ELF_SEC) {
        let ext_data = ext_section.data()?;
        let ext_hdr = ext_data.pread_with::<btf_ext_header_v1>(0, endian)?;
        println!("Data size:\t{}", ext_data.len());
        println!("Header size:\t{}", ext_hdr.hdr_len);
        println!("Func info size:\t{}", ext_hdr.func_info_len);
        println!("Line info size:\t{}", ext_hdr.line_info_len);
        if ext_hdr.hdr_len >= size_of::<btf_ext_header_v2>() as u32 {
            let ext_hdr2 = ext_data.pread_with::<btf_ext_header_v2>(0, endian)?;
            println!("Relocs size:\t{}", ext_hdr2.core_reloc_len);
        }
    } else {
        println!("{} not found.", BTF_EXT_ELF_SEC);
    }
    match Btf::load_elf(elf) {
        Err(e) => println!("Failed to parse BTF data: {}", e),
        Ok(btf) => {
            let mut type_stats: HashMap<BtfKind, (usize, usize)> = HashMap::new();
            for t in &btf.types()[1..] {
                let (cnt, sz) = type_stats.entry(t.kind()).or_insert((0, 0));
                *cnt += 1;
                *sz += Btf::type_size(t);
            }
            let mut total_cnt = 0;
            let mut total_sz = 0;
            for (cnt, sz) in type_stats.values() {
                total_cnt += cnt;
                total_sz += sz;
            }
            let mut type_stats = type_stats
                .into_iter()
                .map(|(k, (cnt, sz))| (k, cnt, sz))
                .collect::<Vec<(BtfKind, usize, usize)>>();
            type_stats.sort_by_key(|&(_, _, sz)| std::cmp::Reverse(sz));
            println!("\nBTF types\n=======================================");
            println!("{:10} {:9} bytes ({} types)", "Total", total_sz, total_cnt);
            for (k, cnt, sz) in type_stats {
                println!("{:10} {:9} bytes ({} types)", format!("{:?}:", k), sz, cnt);
            }

            if btf.has_ext() {
                #[derive(Default)]
                struct Section {
                    func_cnt: usize,
                    func_sz: usize,
                    line_cnt: usize,
                    line_sz: usize,
                    core_reloc_cnt: usize,
                    core_reloc_sz: usize,
                }
                let mut sec_stats = BTreeMap::<_, Section>::new();
                let mut total = Section::default();
                for sec in btf.func_secs() {
                    let s = sec_stats.entry(&sec.name).or_default();
                    s.func_cnt += sec.recs.len();
                    s.func_sz += sec.rec_sz * sec.recs.len();
                    total.func_cnt += sec.recs.len();
                    total.func_sz += sec.rec_sz * sec.recs.len();
                }
                for sec in btf.line_secs() {
                    let s = sec_stats.entry(&sec.name).or_default();
                    s.line_cnt += sec.recs.len();
                    s.line_sz += sec.rec_sz * sec.recs.len();
                    total.line_cnt += sec.recs.len();
                    total.line_sz += sec.rec_sz * sec.recs.len();
                }
                for sec in btf.core_reloc_secs() {
                    let s = sec_stats.entry(&sec.name).or_default();
                    s.core_reloc_cnt += sec.recs.len();
                    s.core_reloc_sz += sec.rec_sz * sec.recs.len();
                    total.core_reloc_cnt += sec.recs.len();
                    total.core_reloc_sz += sec.rec_sz * sec.recs.len();
                }
                println!("\nBTF ext sections\n=======================================");
                println!(
                    "{:32} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                    "Section",
                    "Func sz",
                    "Func cnt",
                    "Line sz",
                    "Line cnt",
                    "Reloc sz",
                    "Reloc cnt"
                );
                println!(
                    "{:32} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                    "--------------------------------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                );
                for (k, s) in sec_stats {
                    println!(
                        "{:32} {:10} {:10} {:10} {:10} {:10} {:10}",
                        k,
                        s.func_sz,
                        s.func_cnt,
                        s.line_sz,
                        s.line_cnt,
                        s.core_reloc_sz,
                        s.core_reloc_cnt
                    );
                }
                println!(
                    "{:32} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                    "--------------------------------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                    "----------",
                );
                println!(
                    "{:32} {:10} {:10} {:10} {:10} {:10} {:10}",
                    "Total",
                    total.func_sz,
                    total.func_cnt,
                    total.line_sz,
                    total.line_cnt,
                    total.core_reloc_sz,
                    total.core_reloc_cnt
                );
            }
        }
    }
    Ok(())
}
