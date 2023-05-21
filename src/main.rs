use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error;
use std::io::Write;

use bitflags::bitflags;
use memmap;
use object::{Object, ObjectSection};
use regex::Regex;
use scroll::Pread;
use std::mem::size_of;
use structopt::StructOpt;

use btf::c_dumper;
use btf::relocator::{Relocator, RelocatorCfg};
use btf::types::*;
use btf::{btf_error, BtfError, BtfResult};

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

bitflags! {
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

#[derive(StructOpt)]
struct QueryArgs {
    #[structopt(short = "n", long = "name")]
    /// Regex of type names to include
    name: Option<String>,
    #[structopt(short = "t", long = "type", parse(try_from_str), use_delimiter = true)]
    /// BTF type kinds to include
    kinds: Vec<BtfKind>,
    #[structopt(long = "id", parse(try_from_str), use_delimiter = true)]
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
            possible_values = &["human", "h", "c", "json", "j", "json-pretty", "jp"],
        )]
        /// Output format
        format: DumpFormat,
        #[structopt(
            short = "d",
            long = "dataset",
            default_value = "default",
            possible_values = &["default", "def", "d", "types", "type", "t", "funcs", "func", "f", "lines", "line", "l", "relocs", "reloc", "r", "all", "a", "exts", "ext", "none"],
        )]
        /// Datasets to output
        datasets: Datasets,
        #[structopt(flatten)]
        query: QueryArgs,
        #[structopt(short = "v", long = "verbose")]
        /// Output verbose log
        verbose: bool,
        #[structopt(long = "union-as-struct")]
        /// Replace unions with structs (for BPF CORE)
        union_as_struct: bool,
    },
    #[structopt(name = "reloc")]
    /// Print detailed relocation information
    Reloc {
        #[structopt(parse(from_os_str))]
        /// Kernel image (target BTF)
        targ_file: std::path::PathBuf,
        #[structopt(parse(from_os_str))]
        /// BPF program (local BTF)
        local_file: std::path::PathBuf,
        #[structopt(short = "v", long = "verbose")]
        /// Output verbose log
        verbose: bool,
    },
    #[structopt(name = "stat")]
    /// Stats about .BTF and .BTF.ext data
    Stat {
        #[structopt(parse(from_os_str))]
        file: std::path::PathBuf,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cmd = Cmd::from_args();

    match cmd {
        Cmd::Dump {
            file,
            format,
            datasets,
            query,
            verbose,
            union_as_struct,
        } => {
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::File::parse(&*file)?;
            let btf = Btf::load(&file)?;
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
                                println!("");
                            }
                        }
                    }
                }
                DumpFormat::Json => panic!("JSON output is not yet supported!"),
                DumpFormat::JsonPretty => panic!("JSON output is not yet supported!"),
                DumpFormat::C => {
                    let cfg = c_dumper::CDumperCfg {
                        verbose: verbose,
                        union_as_struct: union_as_struct,
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
            let local_file = std::fs::File::open(&local_file)?;
            let local_mmap = unsafe { memmap::Mmap::map(&local_file) }?;
            let local_elf = object::File::parse(&*local_mmap)?;
            let local_btf = Btf::load(&local_elf)?;
            if !local_btf.has_ext() {
                return btf_error(format!(
                    "No {} section found for local ELF file, can't perform relocations.",
                    BTF_EXT_ELF_SEC
                ));
            }
            let targ_file = std::fs::File::open(&targ_file)?;
            let targ_mmap = unsafe { memmap::Mmap::map(&targ_file) }?;
            let targ_elf = object::File::parse(&*targ_mmap)?;
            let targ_btf = Btf::load(&targ_elf)?;
            let cfg = RelocatorCfg { verbose: verbose };
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
            stat_btf(&file)?;
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

fn stat_btf(elf: &object::File) -> BtfResult<()> {
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
    match Btf::load(elf) {
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
                struct Section {
                    func_cnt: usize,
                    func_sz: usize,
                    line_cnt: usize,
                    line_sz: usize,
                    core_reloc_cnt: usize,
                    core_reloc_sz: usize,
                }
                let new_sec = || Section {
                    func_cnt: 0,
                    func_sz: 0,
                    line_cnt: 0,
                    line_sz: 0,
                    core_reloc_cnt: 0,
                    core_reloc_sz: 0,
                };
                let mut sec_stats = BTreeMap::new();
                let mut total = new_sec();
                for sec in btf.func_secs() {
                    let s = sec_stats.entry(&sec.name).or_insert_with(new_sec);
                    s.func_cnt += sec.recs.len();
                    s.func_sz += sec.rec_sz * sec.recs.len();
                    total.func_cnt += sec.recs.len();
                    total.func_sz += sec.rec_sz * sec.recs.len();
                }
                for sec in btf.line_secs() {
                    let s = sec_stats.entry(&sec.name).or_insert_with(new_sec);
                    s.line_cnt += sec.recs.len();
                    s.line_sz += sec.rec_sz * sec.recs.len();
                    total.line_cnt += sec.recs.len();
                    total.line_sz += sec.rec_sz * sec.recs.len();
                }
                for sec in btf.core_reloc_secs() {
                    let s = sec_stats.entry(&sec.name).or_insert_with(new_sec);
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
