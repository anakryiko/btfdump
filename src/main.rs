use std::error::Error;

use memmap;
use structopt::StructOpt;

use btfdump::btf;
use btfdump::c_dumper;
use btfdump::BtfError;

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
        #[structopt(short = "n", long = "name", default_value = "")]
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

            match format {
                DumpFormat::Human => {
                    for (i, t) in btf.types().iter().enumerate() {
                        println!("#{}: {}", i, t);
                    }
                }
                DumpFormat::Json => {}
                DumpFormat::JsonPretty => {}
                DumpFormat::C => {
                    let mut dumper = c_dumper::CDumper::new(&btf, verbose);
                    if !name.is_empty() {
                        dumper.dump_types(|bt: &btf::BtfType| match bt {
                            btf::BtfType::Struct(t) => t.name == name,
                            btf::BtfType::Union(t) => t.name == name,
                            btf::BtfType::Enum(t) => t.name == name,
                            btf::BtfType::Fwd(t) => t.name == name,
                            btf::BtfType::Typedef(t) => t.name == name,
                            _ => false,
                        })?;
                    } else {
                        dumper.dump_types(|_| true)?;
                    }
                }
            }
        }
    }
    Ok(())
}
