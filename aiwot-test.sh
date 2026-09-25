AIWOT="cargo run --release --bin aiwot --"
#$AIWOT init
$AIWOT attest new https://x.com/adria0/status/2103430485460369855
$AIWOT attest new https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/fe6fc01f2571fd0da7d6f18cd9ac364ee3a37ca5/gistfile1.txt
$AIWOT attest new https://ethbcn.dev/aiwot.txt
$AIWOT attest keysign aiwot:21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd "BobTheBuilder"
$AIWOT attest search adria0
$AIWOT fakegraph 50
$AIWOT makedot
$AIWOT attest list
$AIWOT attest audit
$AIWOT attest export
$AIWOT attest merge
$AIWOT msg sign "hello world"
$AIWOT msg verify msg.md
$AIWOT msg signcrypt `$AIWOT me` "hello world cyphered"
$AIWOT msg verify msg.md
