<?php
// Version 1 from 2016-12-22
require_once("keys.php");
require_once("script.php");

class Transaction extends Functions{
	private $TX = array(), $Raw;
	const SIGHASH_ALL = 1, SIGHASH_NONE = 2, SIGHASH_SINGLE = 3;

	public function __construct(){
		parent::__construct();
		$this->TX["hash"] = null;
		$this->TX["size"] = 0;
		$this->TX["version"] = 1;
		$this->TX["locktime"] = 0;
		$this->TX["vin"] = array();
		$this->TX["vout"] = array();
	}

	/**
	 * 
	 * @param int $LockTime
	 * @return boolean
	 */
	public function LockSet($LockTime){
		if(ctype_xdigit($LockTime) and $LockTime <= 0xffffffff){
			$this->TX["locktime"] = strtoupper($LockTime);
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
		return $this->TX["locktime"];
	}

	/**
	 * 
	 * @param string $PrevOut
	 * @param int $Vout
	 * @param string $Script Prev ScriptPubKey to sign or coinbase message
	 * @param int $Sequence
	 * @return boolean
	 */
	public function InputAdd($PrevOut, $Vout, $Script = null, $Sequence = 0xffffffff){
		if(empty($Script)){
			$Script = null;
		}
		if(empty($Sequence)){
			$Sequence = 0xffffffff;
		}
		if(!ctype_xdigit($PrevOut) or !ctype_xdigit($Vout) or !ctype_xdigit($Sequence) or (!is_null($Script) and !ctype_xdigit($Script))){
			return false;
		}
		$this->Raw = null;
		$script = new Script();
		$pointer = &$this->TX["vin"][];
		$pointer["txid"] = strtoupper($PrevOut);
		$pointer["vout"] = strtoupper($Vout);
		$pointer["ScriptSig"]["hex"] = strtoupper($Script);
		$pointer["ScriptSig"]["asm"] = $script->Hex2Asm($pointer["ScriptSig"]["hex"], true);
		$pointer["sequence"] = strtoupper($Sequence);
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
		if(isset($this->TX["vin"][$Index])){
			return array(
				"txid" => $this->TX["vin"][$Index]["txid"],
				"vout" => $this->TX["vin"][$Index]["vout"],
				"scriptsighex" => $this->TX["vin"][$Index]["ScriptSig"]["hex"],
				"scriptsigasm" => $this->TX["vin"][$Index]["ScriptSig"]["asm"],
				"sequence" => $this->TX["vin"][$Index]["sequence"]
			);
		}else{
			return false;
		}
	}

	/**
	 * 
	 * @param int $Amount In satoshi
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
		$key = new Keys();
		if(is_null($Address) and !ctype_xdigit($CustomScript)){
			return parent::Error("Custom script its not in hex");;
		}
		if(!ctype_digit($Amount)){
			return parent::Error("Amount is not a number");;
		}
		if(!is_null($Address)){
			$key->AddressSet($Address);
		}
		$this->Raw = null;
		$pointer = &$this->TX["vout"][];
		$pointer["value"] = parent::Satoshi2Btc($Amount);
		$pointer["n"] = count($this->TX["vout"]) - 1;

		//Script
		if(is_null($Address)){
			$pointer["ScriptPubKey"]["hex"] = $CustomScript;
		}elseif(substr($Address, 0, 1) == 1){
			$pointer["ScriptPubKey"]["hex"] = "76A914".$key->Address2Hash()."88AC";
		}elseif(substr($Address, 0, 1) == 3){
			$pointer["ScriptPubKey"]["hex"] = "A914".$key->Address2Hash()."AC";
		}
		$script = new Script();
		$pointer["ScriptPubKey"]["asm"] = $script->Hex2Asm($pointer["ScriptPubKey"]["hex"]);
		$pointer["ScriptPubKey"]["type"] = $script->Type($pointer["ScriptPubKey"]["hex"]);

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
		if(isset($this->TX["vout"][$Index])){
			return array(
				"value" => $this->TX["vout"][$Index]["value"],
				"ScriptPubKeyHex" => $this->TX["vout"][$Index]["ScriptPubKey"]["hex"],
				"ScriptPubKeyAsm" => $this->TX["vout"][$Index]["ScriptPubKey"]["asm"]
			);
		}else{
			return false;
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
	 * Prints the transaction formatted in json on the screen
	 */
	public function Show(){
		echo "<pre>".json_encode($this->TX, JSON_PRETTY_PRINT)."</pre>";
	}

	/**
	 * Sign the transaction.
	 * @param Keys $Key
	 * @param int $Contract
	 */
	public function Sign(&$Key, $Contract = 1){
		$Contract = self::SIGHASH_ALL; //Temporarily fixed
		if(get_class($Key) != "Keys"){
			return false;
		}

		$temp = $Key->Sign(self::HashGet(), true);
		$this->TX["vin"][0]["ScriptSig"]["hex"] = dechex(strlen($temp) / 2);
		$this->TX["vin"][0]["ScriptSig"]["hex"] .= $temp."01";

		$temp = $Key->Priv2Pub();
		$this->TX["vin"][0]["ScriptSig"]["hex"] .= dechex(strlen($temp) / 2);
		$this->TX["vin"][0]["ScriptSig"]["hex"] .= $temp;

		$script = new Script();
		$this->TX["vin"][0]["ScriptSig"]["asm"] = $script->Hex2Asm($this->TX["vin"][0]["ScriptSig"]["hex"], true);

		$this->Raw = null;
		$this->Size = null;
		$this->Hash = null;
	}

	private function RawBuild(){
		$temp = $this->TX["version"];
		$temp = str_pad($temp, 8, 0, STR_PAD_LEFT);
		$return = parent::SwapOrder($temp);
		$temp = unpack("H*", pack("C*", count($this->TX["vin"])));
		$return .= reset($temp);
		if(count($this->TX["vin"]) > 0){
			foreach($this->TX["vin"] as $pt){
				$return .= parent::SwapOrder($pt["txid"]);
				$return .= str_pad($pt["vout"], 8, 0, STR_PAD_LEFT);
				$temp = unpack("H*", pack("C*", strlen($pt["ScriptSig"]["hex"]) / 2));
				$return .= reset($temp);
				$return .= $pt["ScriptSig"]["hex"];
				$return .= str_pad($pt["sequence"], 8, 0, STR_PAD_LEFT);
			}
		}
		$temp = unpack("H*", pack("C*", count($this->TX["vout"])));
		$return .= reset($temp);
		if(count($this->TX["vout"]) > 0){
			foreach($this->TX["vout"] as $pt){
				$temp = str_replace(".", "", $pt["value"]);
				$temp = unpack("H*", pack("P*", $temp));
				$return .= reset($temp);
				$temp = unpack("H*", pack("C*", strlen($pt["ScriptPubKey"]["hex"]) / 2));
				$return .= reset($temp);
				$return .= $pt["ScriptPubKey"]["hex"];
			}
		}
		$temp = $this->TX["locktime"];
		$temp = str_pad($temp, 8, 0, STR_PAD_LEFT);
		$temp = parent::SwapOrder($temp);
		$return .= $temp;
		$this->Raw = strtoupper($return);
		$this->TX["size"] = strlen($return) / 2;
		$this->TX["hash"] = strtoupper(parent::SwapOrder(parent::Hash256($return)));
	}
}