use object::{Object as _, ObjectSection as _};

fn run_btf(args: &[&std::ffi::OsStr]) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_btf"));
    let std::process::Output {
        status,
        stdout,
        stderr,
    } = cmd.args(args).output().unwrap();
    let stdout = std::str::from_utf8(&stdout);
    let stderr = std::str::from_utf8(&stderr);
    assert_eq!(
        status.code(),
        Some(0),
        "{cmd:?} failed: stdout={stdout:?} stderr={stderr:?}"
    );
    let stdout = stdout.unwrap();
    let stderr = stderr.unwrap();
    assert!(!stdout.is_empty(), "{:?}", stdout);
    assert!(stderr.is_empty(), "{:?}", stderr);
    stdout.to_owned()
}

#[test]
fn dump() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let bpf_arch = match std::env::consts::ARCH {
        "x86_64" => "bpfel",
        arch => panic!("unsupported arch {}", arch),
    };
    let tempdir = tempfile::tempdir().unwrap();

    for entry in manifest_dir
        .join("tests")
        .join("samples")
        .read_dir()
        .unwrap()
    {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() {
            continue;
        }

        let dst = {
            let path = path.strip_prefix(manifest_dir).unwrap();

            println!("compiling {}", path.display());

            let dst = tempdir.path().join(path);
            let parent = dst.parent().unwrap();
            std::fs::create_dir_all(parent).unwrap();
            dst
        };

        // Compile the sample.
        {
            let mut cmd = std::process::Command::new("clang");
            let std::process::Output {
                status,
                stdout,
                stderr,
            } = cmd
                .args(["-g", "-target", bpf_arch, "-nostdinc", "-c", "-o"])
                .args([&dst, &path])
                .output()
                .unwrap();
            let stdout = std::str::from_utf8(&stdout);
            let stderr = std::str::from_utf8(&stderr);
            assert_eq!(
                status.code(),
                Some(0),
                "{cmd:?} failed: stdout={stdout:?} stderr={stderr:?}"
            );
            let stdout = stdout.unwrap();
            let stderr = stderr.unwrap();
            assert!(stdout.is_empty(), "{:?}", stdout);
            assert!(stderr.is_empty(), "{:?}", stderr);
        }

        // Extract raw BTF out of the ELF object, the same way it's exposed
        // by the kernel in /sys/kernel/btf/vmlinux.
        let raw = {
            let data = std::fs::read(&dst).unwrap();
            let elf = object::File::parse(&*data).unwrap();
            let sec = elf.section_by_name(".BTF").unwrap();
            let raw = dst.with_extension("btf");
            std::fs::write(&raw, sec.data().unwrap()).unwrap();
            raw
        };

        let dump = std::ffi::OsStr::new("dump");
        let stat = std::ffi::OsStr::new("stat");
        let types = std::ffi::OsStr::new("--dataset=types");

        run_btf(&[dump, dst.as_os_str()]);
        run_btf(&[dump, raw.as_os_str()]);

        // Types must be identical regardless of how BTF was loaded.
        let elf_types = run_btf(&[dump, types, dst.as_os_str()]);
        let raw_types = run_btf(&[dump, types, raw.as_os_str()]);
        assert_eq!(elf_types, raw_types);

        let elf_stat = run_btf(&[stat, dst.as_os_str()]);
        assert!(elf_stat.contains(".BTF ELF section"), "{:?}", elf_stat);
        let raw_stat = run_btf(&[stat, raw.as_os_str()]);
        assert!(raw_stat.contains("Raw BTF data"), "{:?}", raw_stat);
    }
}
