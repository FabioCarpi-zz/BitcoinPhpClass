<?php
// Version 1 from 2016-11-04
require_once("functions.php");

class Script extends Functions{
  private $List = array(
    "OP_FALSE" => 0,
    "OP_RETURN" => "6a",
    "OP_DUP" => 76,
    "OP_EQUAL" => 87,
    "OP_EQUALVERIFY" => 88,
    "OP_HASH160" => "a9",
    "OP_CHECKSIG" => "ac",
    "OP_CHECKLOCKTIMEVERIFY" => "b1",
    "OP_CHECKSEQUENCEVERIFY" => "b2"
  );

  public function __construct(){
    parent::__construct();
  }

  /**
   * 
   * @param string $Hex
   */
  public function Hex2Asm($Hex){
    $return = "";
    $list = array_flip($this->List);
    $Hex = strtolower($Hex);
    while(strlen($Hex) > 0){
      $byte = substr($Hex, 0, 2);
      $Hex = substr($Hex, 2);
      if($byte >= 0x01 and $byte <= 0x4b){
        $return .= substr($Hex, 0, hexdec($byte) * 2) . " ";
        $Hex = substr($Hex, hexdec($byte) * 2);
      }else{
        if(isset($list[$byte])){
          $return .= $list[$byte] . " ";
        }else{
          $return .= "NA ";
        }
      }
    }
    return $return;
  }
}