<?php
// Version 1 from 2016-12-20
require_once("keys.php");
require_once("script.php");

class Transaction extends Functions{
  private $TX = array(), $Raw;

  public function __construct(){
    parent::__construct();
    $this->TX["hash"] = null;
    $this->TX["size"] = 0;
    $this->TX["version"] = 1;
    $this->TX["locktime"] = 0;
  }

  /**
   * 
   * @param int $LockTime
   * @return boolean
   */
  public function LockSet($LockTime){
    if(ctype_xdigit($LockTime) and $LockTime <= 0xffffffff){
      $this->TX["locktime"] = $LockTime;
      $this->TX["hash"] = null;
      $this->Raw = null;
      return true;
    }else{
      return false;
    }
  }

  /**
   * 
   * @return int
   */
  public function LockGet(){
    return strtoupper($this->TX["locktime"]);
  }

  /**
   * 
   * @param string $PrevOut
   * @param int $Vout
   * @param string $Script
   * @param int $Sequence
   * @return boolean
   */
  public function InputAdd($PrevOut, $Vout, $Script = null, $Sequence = 0xffffffff){
    if(empty($Script)){
      $Script = null;
    }
    if(!ctype_xdigit($PrevOut) or !ctype_xdigit($Vout) or !ctype_xdigit($Sequence) or (!is_null($Script) and !ctype_xdigit($Script))){
      return false;
    }
    $this->Raw = null;
    $sc = new Script();
    $pointer = &$this->TX["vin"][];
    $pointer["txid"] = $PrevOut;
    $pointer["vout"] = $Vout;
    $pointer["scriptSig"]["hex"] = $Script;
    $pointer["scriptSig"]["asm"] = $sc->Hex2Asm($pointer["scriptSig"]["hex"]);
    $pointer["sequence"] = $Sequence;
    $this->TX["hash"] = null;
    $this->Raw = null;
    return true;
  }

  /**
   *
   * @return int
   */
  public function InputCount(){
    return count($this->TX["vin"]);
  }

  /**
   *
   * @param int $Index
   * @return array
   */
  public function InputGet($Index){
    return array(
      "txid" => strtoupper($this->TX["vin"][$Index]["txid"]),
      "vout" => strtoupper($this->TX["vin"][$Index]["vout"]),
      "scriptsig" => strtoupper($this->TX["vin"][$Index]["scriptSig"]["hex"]),
      "sequence" => strtoupper($this->TX["vin"][$Index]["sequence"])
    );
  }

  /**
   * 
   * @param int $Amount
   * @param string $Address
   * @param string $CustomScript
   * @return boolean
   */
  public function OutputAdd($Amount, $Address = null, $CustomScript = null){
    if(empty($Address)){
      $Address = null;
    }
    if(empty($CustomScript)){
      $CustomScript = null;
    }
    if(is_null($Address) and !ctype_xdigit($CustomScript)){
      return false;
    }
    if(is_null($CustomScript) and !ctype_alnum($Address)){
      return false;
    }
    if(!ctype_digit($Amount)){
      return false;
    }
    $this->Raw = null;
    $pointer = &$this->TX["vout"][];
    $pointer["value"] = $Amount;
    $pointer["n"] = count($this->TX["vout"]) - 1;
    $key = new Keys();
    $sc = new Script();
    if(is_null($CustomScript)){
      if(substr($Address, 0, 1) == 1){
        $key->AddressSet($Address);
        $pointer["scriptPubKey"]["hex"] = "76a914" . $key->Address2Hash() . "88ac";
        $pointer["scriptPubKey"]["asm"] = $sc->Hex2Asm($pointer["scriptPubKey"]["hex"]);
        $pointer["scriptPubKey"]["reqSigs"] = 1;
        $pointer["scriptPubKey"]["type"] = "pubkeyhash";
        $pointer["scriptPubKey"]["addresses"][] = $Address;
      }
    }else{
      $pointer["scriptPubKey"]["hex"] = $CustomScript;
      $pointer["scriptPubKey"]["asm"] = $sc->Hex2Asm($pointer["scriptPubKey"]["hex"]);
      $pointer["scriptPubKey"]["reqSigs"] = null;
      $pointer["scriptPubKey"]["type"] = null;
      $pointer["scriptPubKey"]["addresses"][] = null;
    }
    $this->TX["hash"] = null;
    $this->Raw = null;
    return true;
  }

  /**
   *
   * @return int
   */
  public function OutputCount(){
    return count($this->TX["vout"]);
  }

  /**
   *
   * @param int $Index
   * @return array
   */
  public function OutputGet($Index){
    return array(
      "address" => strtoupper($this->TX["vout"][$Index]["scriptPubKey"]["addresses"][0]),
      "value" => strtoupper($this->TX["vout"][$Index]["value"]),
      "scriptPubKeyhex" => strtoupper($this->TX["vout"][$Index]["scriptPubKey"]["hex"]),
      "scriptPubKeyasm" => strtoupper($this->TX["vout"][$Index]["scriptPubKey"]["asm"])
    );
  }


  /**
   * 
   * @return string
   */
  public function RawGet(){
    if(is_null($this->Raw)){
      self::RawBuild();
    }
    return strtoupper($this->Raw);
  }

  /**
   * Returns the hash of the transaction
   * @return string
   */
  public function HashGet(){
    if(is_null($this->Raw)){
      self::RawBuild();
    }
    return strtoupper($this->TX["hash"]);
  }

  /**
   * Returns the transaction size in bytes
   * @return int
   */
  public function SizeGet(){
    if(is_null($this->Raw)){
      self::RawBuild();
    }
    return $this->TX["size"];
  }

  /**
   * Prints on the screen the formatted transaction data in Json format
   */
  public function Show(){
    echo "<pre>".json_encode($this->TX, JSON_PRETTY_PRINT)."</pre>";
  }

  private function RawBuild(){
    $return = reset(unpack("H*", pack("V*", $this->TX["version"])));
    $return .= reset(unpack("H*", pack("C*", count($this->TX["vin"]))));
    if(count($this->TX["vin"]) > 0){
      foreach($this->TX["vin"] as $pt){
        $return .= parent::SwapOrder($pt["txid"]);
        $return .= str_pad($pt["vout"], 8, 0, STR_PAD_LEFT);
        $return .= reset(unpack("H*", pack("C*", strlen($pt["scriptSig"]["hex"]) / 2)));
        $return .= $pt["scriptSig"]["hex"];
        $return .= str_pad($pt["sequence"], 8, 0, STR_PAD_LEFT);
      }
    }
    $return .= reset(unpack("H*", pack("C*", count($this->TX["vout"]))));
    if(count($this->TX["vout"]) > 0){
      foreach($this->TX["vout"] as $pt){
        $return .= reset(unpack("H*", pack("P*", $pt["value"])));
        $return .= reset(unpack("H*", pack("C*", strlen($pt["scriptPubKey"]["hex"]) / 2)));
        $return .= $pt["scriptPubKey"]["hex"];
      }
    }
    $temp = $this->TX["locktime"];
    $temp = str_pad($temp, 8, 0, STR_PAD_LEFT);
    $temp = parent::SwapOrder($temp);
    $return .= $temp;
    $this->Raw = $return;
    $this->TX["size"] = strlen($return) / 2;
    $this->TX["hash"] = parent::SwapOrder(parent::Hash256($return));
  }
}