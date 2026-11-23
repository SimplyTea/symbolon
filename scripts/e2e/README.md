# Real-process end-to-end checks

These start the actual `symbolon` binary as separate processes on loopback and
check what they print, which `cargo test` cannot do (it tests the library, not
the command-line program). They are not part of `cargo test`.

    cargo build --release
    ./scripts/e2e/run_all.sh          # all of them
    python3 scripts/e2e/group_e2e.py  # or one

Use `SYMBOLON_BIN=/path/to/symbolon` to test a different build. Each script
prints PASS or FAIL lines; `run_all.sh` treats a script as failed if it exits non-zero, prints a FAIL line, or prints no PASS line at all. They use throwaway
identities with a weak-but-valid passphrase in a temp directory and ports
chosen at run time; nothing touches `~/.symbolon`.
