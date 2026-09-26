rm -rf db
K5="cargo run --release --bin k5cli --"
#$K5 init
$K5 attest new https://x.com/adria0/status/2103557323306225669
$K5 attest new https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/be13d239b4b4fd2068973099bba9b27e8bf8624a/gistfile1.txt
$K5 attest new https://ethbcn.dev/k5.txt
$K5 attest keysign k5:21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd "BobTheBuilder"
$K5 attest search adria0
$K5 fakegraph 5
$K5 makedot
$K5 attest list
$K5 attest audit
$K5 attest export
$K5 attest merge
$K5 msg sign "hello world"
$K5 msg verify msg.md
$K5 msg signcrypt `$K5 me` "hello world cyphered"
$K5 msg verify msg.md
