use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error;

use bitflags::bitflags;
use memmap;
use object::{Object, ObjectSection};
use regex::Regex;
use scroll::Pread;
use std::mem::size_of;
use structopt::StructOpt;

use btf::c_dumper;
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
        const OFFSETRELOCS  = 0b1000;

        const RELOCS = Self::OFFSETRELOCS.bits;
        const EXT    = Self::FUNCINFOS.bits | Self::LINEINFOS.bits | Self::OFFSETRELOCS.bits;
        const ALL    = Self::TYPES.bits | Self::EXT.bits;
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
        #[structopt(
            short = "d",
            long = "dataset",
            default_value = "types",
            raw(
                possible_values = r#"&["types", "type", "t", "funcs", "func", "f", "lines", "line", "l", "relocs", "reloc", "r", "all", "a", "exts", "ext", "none"]"#,
                next_line_help = "true"
            )
        )]
        /// Datasets to output
        datasets: Vec<Datasets>,
        #[structopt(short = "v", long = "verbose")]
        /// Output verbose log
        verbose: bool,
        #[structopt(flatten)]
        query: QueryArgs,
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
            verbose,
            query,
        } => {
            let datasets = datasets.iter().fold(Datasets::NONE, |x, &y| x | y);
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::ElfFile::parse(&*file)?;
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
                    if datasets.contains(Datasets::OFFSETRELOCS) {
                        for (i, sec) in btf.offset_reloc_secs().iter().enumerate() {
                            println!("\nOffset reloc section #{} '{}':", i, sec.name);
                            for (j, rec) in sec.recs.iter().enumerate() {
                                print!("#{}: ", j);
                                emit_access_spec(&btf, rec)?;
                                println!("");
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
        Cmd::Stat { file } => {
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::ElfFile::parse(&*file)?;
            stat_btf(&file)?;
        }
    }
    Ok(())
}

fn emit_access_spec(btf: &Btf, rec: &BtfExtOffsetReloc) -> BtfResult<()> {
    use std::io::Write;
    print!("{} --> &", rec);
    std::io::stdout().flush()?;
    let spec = parse_reloc_access_spec(&rec.access_spec)?;

    let mut id = rec.type_id;
    match btf.type_by_id(id) {
        BtfType::Struct(t) => {
            print!(
                "struct {}",
                if t.name.is_empty() { "<anon>" } else { &t.name }
            );
        }
        BtfType::Union(t) => {
            print!(
                "union {}",
                if t.name.is_empty() { "<anon>" } else { &t.name }
            );
        }
        _ => btf_error(format!(
            "Unsupported accessor spec: '{}', at #{}, type_id: {}, type: {}",
            rec.access_spec,
            0,
            id,
            btf.type_by_id(id),
        ))?,
    }
    if spec[0] > 0 {
        print!("[{}]", spec[0]);
    }

    for i in 1..spec.len() {
        match btf.type_by_id(id) {
            BtfType::Struct(t) => {
                let m = &t.members[spec[i] as usize];
                if !m.name.is_empty() {
                    print!(".{}", m.name);
                }
                id = btf.skip_mods_and_typedefs(m.type_id);
            }
            BtfType::Union(t) => {
                let m = &t.members[spec[i] as usize];
                if !m.name.is_empty() {
                    print!(".{}", m.name);
                }
                id = btf.skip_mods_and_typedefs(m.type_id);
            }
            BtfType::Array(t) => {
                print!("[{}]", spec[i] as usize);
                id = btf.skip_mods_and_typedefs(t.val_type_id);
            }
            _ => btf_error(format!(
                "Unsupported accessor spec: {}, at #{}, type_id: {}, type: {}",
                rec.access_spec,
                i,
                id,
                btf.type_by_id(id),
            ))?,
        }
    }
    Ok(())
}

fn parse_reloc_access_spec(access_spec_str: &str) -> BtfResult<Vec<u32>> {
    let mut spec = Vec::new();
    for p in access_spec_str.trim_end_matches(':').split(':') {
        spec.push(p.parse::<u32>()?);
    }
    Ok(spec)
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

fn stat_btf(elf: &object::ElfFile) -> BtfResult<()> {
    let endian = if elf.is_little_endian() {
        scroll::LE
    } else {
        scroll::BE
    };
    if let Some(btf_section) = elf.section_by_name(BTF_ELF_SEC) {
        let data = btf_section.data();
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
        let ext_data = ext_section.data();
        let ext_hdr = ext_data.pread_with::<btf_ext_header_v1>(0, endian)?;
        println!("Data size:\t{}", ext_data.len());
        println!("Header size:\t{}", ext_hdr.hdr_len);
        println!("Func info size:\t{}", ext_hdr.func_info_len);
        println!("Line info size:\t{}", ext_hdr.line_info_len);
        if ext_hdr.hdr_len >= size_of::<btf_ext_header_v2>() as u32 {
            let ext_hdr2 = ext_data.pread_with::<btf_ext_header_v2>(0, endian)?;
            println!("Relocs size:\t{}", ext_hdr2.offset_reloc_len);
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
                    off_reloc_cnt: usize,
                    off_reloc_sz: usize,
                };
                let new_sec = || Section {
                    func_cnt: 0,
                    func_sz: 0,
                    line_cnt: 0,
                    line_sz: 0,
                    off_reloc_cnt: 0,
                    off_reloc_sz: 0,
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
                for sec in btf.offset_reloc_secs() {
                    let s = sec_stats.entry(&sec.name).or_insert_with(new_sec);
                    s.off_reloc_cnt += sec.recs.len();
                    s.off_reloc_sz += sec.rec_sz * sec.recs.len();
                    total.off_reloc_cnt += sec.recs.len();
                    total.off_reloc_sz += sec.rec_sz * sec.recs.len();
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
                        s.off_reloc_sz,
                        s.off_reloc_cnt
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
                    total.off_reloc_sz,
                    total.off_reloc_cnt
                );
            }
        }
    }
    Ok(())
}
