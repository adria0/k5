AIWOT="cargo run --release --bin aiwot --"
#$AIWOT init
$AIWOT attest new https://x.com/adria0/status/2102768520564236365
$AIWOT attest new https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/c99ea0a89cdfc406123e1f3e1a21743a4fe4821e/gistfile1.txt
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
$AIWOT msg signcrypt af30423b3b65ded9241d46d9ae519597cc86b9e72bfafa56b1b0bfa741bd2712 "hello world cyphered"
$AIWOT msg verify msg.md
