source $HOME/.cargo/env
cargo test -p synq-compiler -p synq-vm 2>&1 | grep -E "test result|test_"
