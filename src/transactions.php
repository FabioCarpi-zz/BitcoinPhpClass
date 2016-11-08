<?php
// Version 1 from 2016-11-04
require_once("keys.php");
require_once("script.php");

class Transaction extends Functions{
  private $TX = array(), $Raw;

  /**
   * 
   * @param int $Version
   * @param int $Lock
   */
  public function __construct($Version = 1, $Lock = 0){
    parent::__construct();
    $this->TX["hash"] = null;
    $this->TX["size"] = 0;
    $this->TX["version"] = $Version;
    $this->TX["locktime"] = $Lock;
  }

  /**
   * 
   * @param string $PrevOut
   * @param int $Vout
   * @param string $Script
   * @param int $Sequence
   */
  public function InputAdd($PrevOut, $Vout, $Script, $Sequence = 0xffffffff){
    $this->Raw = null;
    $sc = new Script();
    $pointer = &$this->TX["vin"][];
    $pointer["txid"] = $PrevOut;
    $pointer["vout"] = $Vout;
    $pointer["scriptSig"]["hex"] = $Script;
    $pointer["scriptSig"]["asm"] = $sc->Hex2Asm($pointer["scriptSig"]["hex"]);
    $pointer["sequence"] = $Sequence;
  }

  /**
   * 
   * @param int $Amount
   * @param string $Address
   * @param string $CustomScript
   */
  public function OutputAdd($Amount, $Address, $CustomScript = null){
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
  }

  /**
   * 
   * @return string
   */
  public function RawGet(){
    if(is_null($this->Raw)){
      self::RawBuild();
    }
    return $this->Raw;
  }

  /**
   * Returns the hash of the transaction
   * @return string
   */
  public function HashGet(){
    if(is_null($this->Raw)){
      self::RawBuild();
    }
    return $this->TX["hash"];
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
    echo "<pre>" . json_encode($this->TX, JSON_PRETTY_PRINT) . "</pre>";
  }

  private function RawBuild(){
    $return = reset(unpack("H*", pack("V*", $this->TX["version"])));
    $return .= reset(unpack("H*", pack("C*", count($this->TX["vin"]))));
    foreach($this->TX["vin"] as $pt){
      $return .= parent::SwapOrder($pt["txid"]);
      $return .= reset(unpack("H*", pack("V*", $pt["vout"])));
      $return .= reset(unpack("H*", pack("C*", strlen($pt["scriptSig"]["hex"]) / 2)));
      $return .= $pt["scriptSig"]["hex"];
      $return .= reset(unpack("H*", pack("V*", $pt["sequence"])));
    }
    $return .= reset(unpack("H*", pack("C*", count($this->TX["vout"]))));
    foreach($this->TX["vout"] as $pt){
      $return .= reset(unpack("H*", pack("P*", $pt["value"])));
      $return .= reset(unpack("H*", pack("C*", strlen($pt["scriptPubKey"]["hex"]) / 2)));
      $return .= $pt["scriptPubKey"]["hex"];
    }
    $return .= reset(unpack("H*", pack("V*", $this->Lock)));
    $this->Raw = $return;
    $this->TX["size"] = strlen($return) / 2;
    $this->TX["hash"] = parent::SwapOrder(parent::Hash256($return));
  }
}