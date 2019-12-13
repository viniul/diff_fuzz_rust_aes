 RUSTFLAGS="-C overflow-checks=on -Z sanitizer=address" cargo hfuzz run $1
