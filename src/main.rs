use memmap;
use std::error::Error;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    file_path: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();

    let file = std::fs::File::open(&args.file_path)?;
    let file = unsafe { memmap::Mmap::map(&file) }?;
    let file = object::ElfFile::parse(&*file)?;
    let btf = btfdump::Btf::load(file)?;

    let mut idx = 0;
    for t in btf.types() {
        println!("#{}: {}", idx, t);
        idx = idx + 1;
    }

    Ok(())
}
