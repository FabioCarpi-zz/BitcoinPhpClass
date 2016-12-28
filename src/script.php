<?php
// Version 1 from 2016-12-23
require_once("functions.php");

class Script extends Functions{
	private $List = array(
		"OP_FALSE" => 0,
		"OP_RETURN" => "6A",
		"OP_DUP" => 76,
		"OP_EQUAL" => 87,
		"OP_EQUALVERIFY" => 88,
		"OP_HASH160" => "A9",
		"OP_CHECKSIG" => "AC",
		"OP_CHECKLOCKTIMEVERIFY" => "B1",
		"OP_CHECKSEQUENCEVERIFY" => "B2"
	);

	public function __construct(){
		parent::__construct();
	}

	/**
	 * 
	 * @param string $Hex
	 */
	public function Hex2Asm($Hex, $ScriptSig = false){
		$return = "";
		$list = array_flip($this->List);
		while(strlen($Hex) > 0){
			$byte = substr($Hex, 0, 2);
			$Hex = substr($Hex, 2);
			if($ScriptSig and ($byte == "01" or $byte == "02" or $byte == "03")){
				if($byte == "01"){
					$return .= "[ALL] ";
				}
			}elseif($byte >= 0x01 and $byte <= 0x4b){
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
		return trim($return);
	}

	/**
	 *
	 * @param string $Hex
	 * @return string
	 */
	public function Type($Hex){
		if(preg_match("/76A914.*88AC/", $Hex)){
			return "pubkeyhash";
		}elseif(preg_match("/A914.*87/", $Hex)){
			return "scripthash";
		}elseif(preg_match("/21.*AC/", $Hex)){
			return "pubkey";
		}else{
			return "nonstandard";
		}
	}

	/**
	 *
	 * @param string $Script
	 * @return string
	 */
	public function GetHash($Script){
		if(self::Type($Script) == "pubkeyhash"){
			return substr($Script, 6, -4);
		}elseif(self::Type($Script) == "scripthash"){
			return substr($Script, 4, -2);
		}elseif(self::Type($Script) == "pubkey"){
			return substr($Script, 2, -2);
		}else{
			return false;
		}
	}
}