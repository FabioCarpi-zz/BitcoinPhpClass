<?php
//Version 1 from 2017-01-02
//require_once("keys.php");

class Bip32 extends Keys implements Int_Bip32{
  const Mainnet_Private = "0488ade4", Mainnet_Public = "0488b21e";

  /**
   * 
   * @param string $seed
   * @return array
   */
  public function Seed($seed = null){
    if(is_null($seed)){
      $seed = reset(unpack("H*", random_bytes(32)));
    }elseif(ctype_xdigit($seed) == false){
      return parent::Erro("The seed supplied is not in hexadecimal");
    }else{
      if(strlen($seed) < 32){
	return parent::Erro("The seed supplied must be greater than 128 bits");
      }
      if(strlen($seed) > 128){
	return parent::Erro("The seed supplied must be less than 512 bits");
      }
    }
    $seed = gmp_init($seed, 16);
    do{
      $l = hash_hmac("sha512", pack("H*", parent::gmp_tohex($seed, 32)), "Bitcoin seed");
      $ll = substr($l, 0, 64);
      $ll = gmp_init($ll, 16);
      if(ll == $this->H or $ll >= $this->N){
	$seed += 1;
      }
    }while($ll == $this->H or $ll >= $this->N);
    return array("k" => parent::gmp_tohex($ll), "c" => substr($l, 64));
  }

  /**
   * 
   * @param array $array
   * @param string $i
   * @return array
   */
  public function CkdPriv($array, $i){
    if(is_array($array) == false){
      return parent::Erro("The entry is not in array");
    }
    if(isset($array["k"]) == false){
      return parent::Erro("Private key not supplied");
    }
    if(isset($array["c"]) == false){
      return parent::Erro("Chaincode not supplied");
    }
    $kpar = $array["k"];
    $cpar = $array["c"];
    if(ctype_xdigit($kpar) == false){
      return parent::Erro("The private key is not supplied in hex");
    }
    if(ctype_xdigit($cpar) == false){
      return parent::Erro("The chaincode provided is not in hexadecimal");
    }
    if(ctype_xdigit($i) == false){
      return parent::Erro("The child is not provided in hexadecimal");
    }
    $i = gmp_init($i, 16);
    $kpar = gmp_init($kpar, 16);
    if($i > 0xffffffff){
      return parent::Erro("The child provided cannot be greater than 0xffffffff");
    }
    $key = new Keys();
    $key->PrivSet($kpar);
    $key->Priv2Pub();
    do{
      if($i >= 0x80000000){
	$l = hash_hmac("sha512", pack("H*", "00" . parent::gmp_tohex($kpar, 64) . parent::gmp_tohex($i, 8)), pack("H*", $cpar));
      }else{
	$l = hash_hmac("sha512", pack("H*", $key->PubGet() . parent::gmp_tohex($i, 8)), pack("H*", $cpar));
      }
      $ll = substr($l, 0, 64);
      $lr = substr($l, 64);
      $ll = gmp_init($ll, 16);
      $k = ($ll + $kpar) % $this->N;
      if($ll >= $this->N or $k == 0){
	$i += 1;
      }
    }while($ll >= $this->N or $k == 0);
    $finger = parent::Hash160($key->PubGet());
    $finger = substr($finger, 0, 8);
    return array("k" => parent::gmp_tohex($k, 64), "c" => $lr, "finger" => $finger);
  }

  /**
   * 
   * @param array $array
   * @param string $i
   * @return array
   */
  public function CkdPub($array, $i){
    if(is_array($array) == false){
      return parent::Erro("The entry is not in array");
    }
    if(isset($array["K"]) == false){
      return parent::Erro("Public key not supplied");
    }
    if(isset($array["c"]) == false){
      return parent::Erro("Chaincode not supplied");
    }
    if(ctype_xdigit($array["K"]) == false){
      return parent::Erro("The private key is not supplied in hex");
    }
    if(ctype_xdigit($array["c"]) == false){
      return parent::Erro("The chaincode provided is not in hexadecimal");
    }
    if(ctype_xdigit($i) == false){
      return parent::Erro("The child is not provided in hexadecimal");
    }
    $i = gmp_init($i, 16);
    if($i > 0xffffffff){
      return parent::Erro("The child provided cannot be greater than 0xffffffff");
    }
    if($i > 0x80000000){
      return parent::Erro("It's not doing a derivation possive child hardened");
    }
    $key = new Keys();
    do{
      $I = hash_hmac("sha512", pack("H*", $array["K"] . parent::gmp_tohex($i, 8)), pack("H*", $array["c"]));
      $IL = substr($I, 0, 64);
      //Obtem IL * G
      $key->PrivSet($IL);
      $Ki = $key->Priv2Pub(true);
      $Ki = array(substr($Ki, 2, 64), substr($Ki, -64));
      $Ki[0] = gmp_init($Ki[0], 16);
      $Ki[1] = gmp_init($Ki[1], 16);
      //Obtem Kpar
      $key->PubSet($array["K"]);
      $Kpar = $key->PubGet(true);
      $Kpar = array(substr($Kpar, 2, 64), substr($Kpar, -64));
      $Kpar[0] = gmp_init($Kpar[0], 16);
      $Kpar[1] = gmp_init($Kpar[1], 16);
      //Soma as 2 chaves
      $Ki = parent::EccAdd($Ki, $Kpar);
      //Verifica IL
      $IL = gmp_init($IL, 16);
      if($IL >= $this->N){
	$i += 1;
      }
    }while($IL >= $this->N);
    $Ki = "04" . parent::gmp_tohex($Ki[0]) . parent::gmp_tohex($Ki[1]);
    $key->PubSet($Ki);
    $Ki = $key->PubGet();
    //Finger
    $key->PubSet($array["K"]);
    $finger = $key->PubGet();
    $finger = parent::Hash160($finger);
    $finger = substr($finger, 0, 8);
    return array("K" => $Ki, "c" => substr($I, 64), "finger" => $finger);
  }

  /**
   * 
   * @param string $net
   * @param string $depth
   * @param string $finger
   * @param string $child
   * @param string $k
   * @param string $c
   * @return string
   */
  public function ExtEncode($net, $depth, $finger, $child, $k, $c){
    $key = $net;
    $key .= str_pad($depth, 2, 0, STR_PAD_LEFT);
    $key .= str_pad($finger, 8, 0, STR_PAD_LEFT);
    $key .= str_pad($child, 8, 0, STR_PAD_LEFT);
    $key .= $c;
    if($net == self::Mainnet_Private){
      $key .= "00";
    }
    $key .= $k;
    $check = parent::Hash256($key);
    $check = substr($check, 0, 8);
    $key .= $check;
    return parent::base58_encode($key);
  }

  /**
   * 
   * @param string $ext
   */
  public function ExtDecode($ext){
    $ext = parent::base58_decode($ext);
    $ext = substr($ext, 0, -8);
    echo "<pre>";
    echo substr($ext, 0, 8) . "\n";
    echo substr($ext, 8, 2) . "\n";
    echo substr($ext, 10, 8) . "\n";
    echo substr($ext, 18, 8) . "\n";
    echo substr($ext, 26, 64) . "\n";
    echo substr($ext, 90);
    echo "</pre>";
  }
}