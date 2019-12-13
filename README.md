# Differential fuzzing for rust aes crypto libraries
This is a small prototype to apply differential fuzz-testing to the different
rust-aes implementations. It has already identified this [issue](https://github.com/RustCrypto/stream-ciphers/issues/12).

Use like so:
```
rustup override set nightly
./fuzz_rust_target.sh aes_target
```
You can debug an input by running:
```
cargo hfuzz run-debug aes_target <crashing_input>
```
