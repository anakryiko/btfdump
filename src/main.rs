use std::error::Error;

use memmap;
use regex::Regex;
use structopt::StructOpt;

use btfdump::btf;
use btfdump::c_dumper;
use btfdump::{BtfError, BtfResult};

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
#[structopt(name = "btfdump", about = "BTF introspection tool")]
enum Cmd {
    #[structopt(name = "dump", about = "Dump BTF data in various formats")]
    Dump {
        #[structopt(parse(from_os_str))]
        file: std::path::PathBuf,
        #[structopt(short = "f", long = "format", default_value = "human")]
        format: DumpFormat,
        #[structopt(short = "n", long = "name", default_value = "", help = "Name regex")]
        name: String,
        #[structopt(short = "v", long = "verbose")]
        verbose: bool,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cmd = Cmd::from_args();

    match cmd {
        Cmd::Dump {
            file,
            format,
            name,
            verbose,
        } => {
            let file = std::fs::File::open(&file)?;
            let file = unsafe { memmap::Mmap::map(&file) }?;
            let file = object::ElfFile::parse(&*file)?;
            let btf = btf::Btf::load(file)?;
            let filter = create_name_filter(&name)?;
            match format {
                DumpFormat::Human => {
                    for (i, t) in btf.types().iter().enumerate() {
                        if filter(t) {
                            println!("#{}: {}", i, t);
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

fn create_name_filter<'a, 'b>(name: &'a str) -> BtfResult<Box<Fn(&'b btf::BtfType) -> bool>> {
    if name.is_empty() {
        Ok(Box::new(|_: &btf::BtfType| true))
    } else {
        let name_regex = Regex::new(name)?;
        Ok(Box::new(move |bt: &'b btf::BtfType| -> bool {
            match bt {
                btf::BtfType::Struct(t) => name_regex.is_match(&t.name),
                btf::BtfType::Union(t) => name_regex.is_match(&t.name),
                btf::BtfType::Enum(t) => name_regex.is_match(&t.name),
                btf::BtfType::Fwd(t) => name_regex.is_match(&t.name),
                btf::BtfType::Typedef(t) => name_regex.is_match(&t.name),
                _ => false,
            }
        }))
    }
}
