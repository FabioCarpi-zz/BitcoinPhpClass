<?php
require_once("keys.php");

$key = new Keys();
$key->PrivSet(reset(unpack("H*", random_bytes(32))));
echo "Private key: ".$key->PrivGet()."<br>";
echo "Extended WIF: ".$key->WifGet(true)."<br>";
echo "Compressed WIF: ".$key->WifGet()."<br>";
echo "Extended public key: ".$key->Priv2Pub(true)."<br>";
echo "Compressed public key: ".$key->PubGet()."<br>";
echo "Extended Hash160: ".$key->Pub2Hash(true)."<br>";
echo "Compressed Hash160: ".$key->Pub2Hash()."<br>";
echo "Extended address: ".$key->Priv2Address(true)."<br>";
echo "Compressed address: ".$key->Priv2Address()."<br>";