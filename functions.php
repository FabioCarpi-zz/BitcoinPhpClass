<?php

class Functions{
  private $Debug;
  const DebugDie = 1, DebugTraceComplete = 2, DebugTraceResumed = 4;
  private $BitcoinBase58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  private $NormalBase58Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";

  public function __construct(){
    $this->Debug = self::DebugDie + self::DebugTraceComplete;
  }

  /**
   * 
   * @param string $n
   * @return string
   */
  protected function Hash160($n){
    $n = pack("H*", $n);
    $n = hash("sha256", $n, true);
    return hash("ripemd160", $n);
  }

  /**
   * 
   * @param string $n
   * @return string
   */
  protected function Hash256($n){
    $n = pack("H*", $n);
    $n = hash("sha256", $n, true);
    return hash("sha256", $n);
  }

  /**
   * 
   * @param string $Hex
   * @return string
   */
  protected function base58_encode($Hex){
    $return = gmp_init($Hex, 16);
    $return = gmp_strval($return, 58);
    $return = strtr($return, $this->NormalBase58Chars, $this->BitcoinBase58Chars);
    if(substr($Hex, 0, 2) == "00"){
      $return = "1" . $return;
    }
    return $return;
  }

  /**
   * 
   * @param string $Base58
   * @return string
   */
  protected function base58_decode($Base58){
    $return = strtr($Base58, $this->BitcoinBase58Chars, $this->NormalBase58Chars);
    $return = gmp_init($return, 58);
    $return = self::gmp_tohex($return);
    return $return;
  }

  /**
   * 
   * @param array $Array
   * @return array
   */
  protected function Merkle($Array){
    $len = count($Array);
    if($len == 1){
      return $Array;
    }elseif($len % 2 == 1){
      $Array[] = $Array[$len - 1];
    }
    for($i = 0; $i < count($Array) - 1;){
      $Array[] = self::Hash256(self::SwapOrder($Array[$i++]) . self::SwapOrder($Array[$i++]));
    }
    return $Array;
  }

  /**
   * 
   * @param string $in
   * @return string
   */
  protected function SwapOrder($in){
    return implode("", array_reverse(str_split($in, 2)));
  }

  /**
   * 
   * @param string $msg
   * @param int $Flags
   * @return boolean
   */
  protected function Error($msg, $Flags = null){
    if(!is_null($Flags)){
      $this->Debug = $Flags;
    }
    $debug = debug_backtrace();
    $debug = end($debug);
    echo $msg . " <b>in</b> " . $debug["file"] . " <b>line</b> " . $debug["line"];
    echo "<br><br>";
    if((($this->Debug >> 1) & 1) == 1){
      echo "<pre>";
      var_dump(debug_backtrace());
      echo "</pre>";
    }elseif((($this->Debug >> 2) & 1) == 1){
      echo "<pre>";
      var_dump(debug_print_backtrace());
      echo "</pre>";
    }
    if(($this->Debug & 1) == 1){
      die();
    }
    return false;
  }

  /**
   * 
   * @param object $n
   * @param int $count
   * @return string
   */
  protected function gmp_tohex($n, $count = null){
    $n = gmp_strval($n, 16);
    $n = self::SafeHex($n);
    if(is_null($count) == false){
      $n = str_pad($n, $count, 0, STR_PAD_LEFT);
    }
    return $n;
  }

  /**
   * 
   * @param string $n
   * @return string
   */
  protected function SafeHex($n){
    if(strlen($n) % 2 == 1){
      return "0" . $n;
    }else{
      return $n;
    }
  }
}