# Contributing

Thanks for looking. This is a small project with a narrow scope, so the most
useful contributions are usually bug reports with a reproduction and new
tracker-list sources.

## Before you write code

Open an issue first for anything larger than a bug fix. The project has a
deliberate design and a short list of things it refuses to do; a PR that adds
packet capture or an auto-updater will be declined, and it is better to know
that before you build it.

## What is especially welcome

- **A false attribution.** If you find a case where the tool names the wrong
  application, that is the highest-severity bug class in the project. Include
  the `tattle --json` rows and, if you can, what you expected.
- **A locale.** `src/dns/ipconfig.rs` parses localised `ipconfig` output. If it
  fails on your language, a fixture in `fixtures/` is the whole fix.
- **A list source.** A new public blocklist with a permissive licence and a
  stable URL.
- **A macOS or Linux collector.** The `Collector` seam exists for this. It is
  the largest piece of work available and it is not started.

## Development setup

Windows only at present. The development machine used to build this has no
Visual Studio Build Tools, so local builds use the GNU toolchain:

```powershell
# per-user, no admin
Invoke-WebRequest https://win.rustup.rs/x86_64 -OutFile "$env:TEMP\rustup-init.exe"
& "$env:TEMP\rustup-init.exe" -y --default-toolchain none

# MinGW: winget, or the WinLibs zip extracted to %LOCALAPPDATA%\winlibs
winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT

rustup toolchain install stable-x86_64-pc-windows-gnu -c rustfmt,clippy
rustup default stable-x86_64-pc-windows-gnu
```

CI builds with MSVC on `windows-latest`, so both toolchains must keep working.
`rust-toolchain.toml` pins the channel but not the host triple for that reason.

## The checks that must pass

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

All three run in CI. A PR that turns any of them red will not be merged.

There are also two live tests that are ignored by default because they open
real sockets:

```powershell
cargo test -- --ignored live_
```

Run them before a release, not on every commit.

## Regenerating the README media

The animated demo and the receipt screenshot are generated, not hand-made, so
they cannot drift from what the program actually prints.

```powershell
# 1. frames from the real live view
cargo run --example gif_frames | Out-File -Encoding utf8 "$env:TEMP\frames.txt"

# 2. paint them into a GIF (needs Python with Pillow)
python scripts/make_demo_gif.py "$env:TEMP\frames.txt" docs\demo.gif
```

`examples/gif_frames` drives the same `Frame::render` the binary uses. If you
change the live view's layout, the GIF changes with it — that is the point, and
it is also why the frames are not checked in.

The receipt image is a screenshot of `tattle demo --out demo.html` rendered at a
1200 px viewport, then cropped to the content.

## House rules

1. **Never guess an attribution.** An unknown connection is reported as
   unknown. A heuristic that improves the demo but invents a name is a
   regression, not a feature.
2. **Every claim in a doc needs a test.** `docs/METHODOLOGY.md` states
   behaviours; if you change one, change the test that asserts it.
3. **No new outbound network calls.** The product's privacy claim is load
   bearing. `tests/privacy.rs` fails if a new HTTP client appears outside the
   list loader.
4. **Escape everything that reaches the HTML.** Hostnames are attacker
   controlled.
5. **Comment the why, not the what.** The code should read as the thing it does.

## Commit messages

Explain the problem and the decision, not the diff. If a change fixes a bug
found by running the program rather than by a test, say so — that is the most
useful information in the history.

## Licence

Contributions are accepted under the MIT licence, the same as the project.
