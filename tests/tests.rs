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
                "{:?} failed: stdout={:?} stderr={:?}",
                cmd,
                stdout,
                stderr
            );
            let stdout = stdout.unwrap();
            let stderr = stderr.unwrap();
            assert!(stdout.is_empty(), "{:?}", stdout);
            assert!(stderr.is_empty(), "{:?}", stderr);
        }

        // Run `dump` on the result.
        {
            let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_btf"));
            let std::process::Output {
                status,
                stdout,
                stderr,
            } = cmd.arg("dump").arg(dst).output().unwrap();
            let stdout = std::str::from_utf8(&stdout);
            let stderr = std::str::from_utf8(&stderr);
            assert_eq!(
                status.code(),
                Some(0),
                "{:?} failed: stdout={:?} stderr={:?}",
                cmd,
                stdout,
                stderr
            );
            let stdout = stdout.unwrap();
            let stderr = stderr.unwrap();
            assert!(!stdout.is_empty(), "{:?}", stdout);
            assert!(stderr.is_empty(), "{:?}", stderr);
        }
    }
}
