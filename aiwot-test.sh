cargo run --bin aiwot -- notarize https://x.com/adria0/status/2102768520564236365
cargo run --bin aiwot -- notarize https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/c99ea0a89cdfc406123e1f3e1a21743a4fe4821e/gistfile1.txt
cargo run --bin aiwot -- notarize https://ethbcn.dev/aiwot.txt
cargo run --bin aiwot -- sign "hello world"
cargo run --bin aiwot -- verify msg.md
