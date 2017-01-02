<?php
//Version 1 from 2017-01-02
//require_once("transactions.php");

class Block extends Functions{
  private $Block = array();

  /**
   * 
   * @param string $PrevHash
   * @param int $Bits
   * @param int $Version
   * @param int $Time
   */
  public function __construct($PrevHash, $Bits, $Version = 4, $Time = null){
    parent::__construct();
    $this->Block["hash"] = null;
    $this->Block["version"] = $Version;
    $this->Block["prevhash"] = $PrevHash;
    $this->Block["MerkleRoot"] = null;
    if(is_null($Time)){
      $this->Block["time"] = time();
    }else{
      $this->Block["time"] = $Time;
    }
    $this->Block["bits"] = $Bits;
    $this->Block["target"] = gmp_init(substr($Bits, 2), 16) * 256 ** (gmp_init(substr($Bits, 0, 2), 16) - 3);
    $this->Block["target"] = parent::gmp_tohex($this->Block["target"], 64);
    $this->Block["nonce"] = null;
    $this->Block["tx"] = array();
  }

  /**
   * 
   * @param object $Tx
   */
  public function TxAdd($Tx){
    if(is_object($Tx) and get_class($Tx) == "Transaction"){
      $this->Block["tx"][] = $Tx;
      $this->Block["MerkleLeafs"][] = $Tx->HashGet();
      $this->Block["MerkleTree"] = parent::Merkle($this->Block["MerkleLeafs"]);
      $this->Block["MerkleRoot"] = end($this->Block["MerkleTree"]);
    }else{
      return parent::Erro("Was not passed an object of Transaction class");
    }
  }

  /**
   * 
   * @param int $Nonce
   * @return boolean
   */
  public function NonceSet($Nonce){
    $hash = parent::Hash256(
      reset(unpack("H*", pack("V*", $this->Block["version"]))) .
      parent::SwapOrder($this->Block["prevhash"]) .
      parent::SwapOrder($this->Block["MerkleRoot"]) .
      reset(unpack("H*", pack("V*", $this->Block["time"]))) .
      parent::SwapOrder($this->Block["bits"]) .
      reset(unpack("H*", pack("V*", $Nonce)))
    );
    if(gmp_init(parent::SwapOrder($hash), 16) <= gmp_init($this->Block["target"], 16)){
      $this->Block["nounce"] = $Nonce;
      return true;
    }else{
      return false;
    }
  }

  /**
   * 
   * @return string
   */
  public function RawGet(){
    $return = reset(unpack("H*", pack("V*", $this->Block["version"])));
    $return .= parent::SwapOrder($this->Block["prevhash"]);
    $return .= parent::SwapOrder($this->Block["MerkleRoot"]);
    $return .= reset(unpack("H*", pack("V*", $this->Block["time"])));
    $return .= parent::SwapOrder($this->Block["bits"]);
    $return .= reset(unpack("H*", pack("V*", $Nonce)));
    foreach($this->Block["tx"] as $pt){
      $return .= $pt->RawGet();
    }
    return $return;
  }

  /**
   * Prints on the screen the formatted block data in Json format
   */
  public function Show(){
    echo "<pre>" . json_encode($this->Block, JSON_PRETTY_PRINT) . "</pre>";
  }
}