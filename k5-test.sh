K5="cargo run --release --bin k5 --"
#$K5 init
$K5 attest new https://x.com/adria0/status/2103443372786495830
$K5 attest new https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/fe6fc01f2571fd0da7d6f18cd9ac364ee3a37ca5/gistfile1.txt
$K5 attest new https://ethbcn.dev/aiwot.txt
$K5 attest keysign k5:21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd "BobTheBuilder"
$K5 attest search adria0
$K5 fakegraph 50
$K5 makedot
$K5 attest list
$K5 attest audit
$K5 attest export
$K5 attest merge
$K5 msg sign "hello world"
$K5 msg verify msg.md
$K5 msg signcrypt `$K5 me` "hello world cyphered"
$K5 msg verify msg.md
