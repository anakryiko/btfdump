# btfdump
BTF introspection tool

# Compiling
`btfdump` is written in Rust and relies on standard Cargo package manager.

To compile btfdump:
  1. Get rust toolchain. See https://www.rust-lang.org/tools/install for instructions. 
    a. Using rustup is the simplest option: just run `curl https://sh.rustup.rs -sSf | sh`.
    b. If you are behind HTTP/HTTPS proxy, you can specify it using `http_proxy` and `https_proxy` envvars:
      ```
      $ export http_proxy=http://fwdproxy:8080
      $ export https_proxy=http://fwdproxy:8080
      $ curl https://sh.rustup.rs -sSf | sh
      ```
  2. Once Cargo and rustc is installed, run `cargo build` or `cargo build --release` to compile it. This will build `btf` binary in `target/{debug,release}/` directory.
  3. Alternatively, you can use `cargo run -- <args>` to compile and run through Cargo.
  
# Supported commands

## Dump

1. Dump BTF types in various formats:
```
btf dump --format [human|c] <elf-file>
```
2. You can filter out which types to print out using `--type`, `--name`, and `--id` options. See `btf dump --help` for more details.
3. Check also `--dataset` option for dumping .BTF.ext data as well.

## Stat

Output high-level stats about .BTF and .BTF.ext data.

```
btf stat <elf-file>
```
  
