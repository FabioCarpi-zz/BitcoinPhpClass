<?php
// Version 1 from 2016-12-23
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
	 * @param string $Vout
	 * @param string $ScriptSig
	 * @param string $ScriptPubkey
	 * @param string $Sequence
	 * @return boolean
	 */
	public function InputAdd($PrevOut, $Vout, $ScriptSig = null, $ScriptPubkey = null, $Sequence = 0xffffffff){
		if(empty($ScriptSig)){
			$ScriptSig = null;
		}
		if(empty($ScriptPubkey)){
			$ScriptPubkey = null;
		}
		if(empty($Sequence)){
			$Sequence = 0xffffffff;
		}
		if(ctype_xdigit($PrevOut) == false){
			return parent::Error("The tx id informed it's not in hexadecimal");
		}
		if(ctype_xdigit($Vout) == false){
			return parent::Error("The vout informed it's not in hexadecimal");
		}
		if(is_null($ScriptSig) == false and ctype_xdigit($ScriptSig) == false){
			return parent::Error("The ScriptSig informed it's not in hexadecimal");
		}
		if(is_null($ScriptPubkey) == false and ctype_xdigit($ScriptPubkey) == false){
			return parent::Error("The ScriptPubkey informed it's not in hexadecimal");
		}
		$this->Raw = null;
		$script = new Script();
		$pointer = &$this->TX["vin"][];
		$pointer["txid"] = strtoupper($PrevOut);
		$pointer["vout"] = strtoupper($Vout);
		$pointer["ScriptSig"]["hex"] = strtoupper($ScriptSig);
		$pointer["ScriptSig"]["asm"] = $script->Hex2Asm($pointer["ScriptSig"]["hex"], true);
		$pointer["ScriptSig"]["ScriptPubkey"] = strtoupper($ScriptPubkey);
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
				"scriptpubkey" => $this->TX["vin"][$Index]["ScriptSig"]["ScriptPubkey"],
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
		if($Amount < 0){
			return parent::Error("Amount is less them 0");;
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
			$pointer["ScriptPubkey"]["hex"] = $CustomScript;
		}elseif(substr($Address, 0, 1) == 1){
			$pointer["ScriptPubkey"]["hex"] = "76A914".$key->Address2Hash()."88AC";
		}elseif(substr($Address, 0, 1) == 3){
			$pointer["ScriptPubkey"]["hex"] = "A914".$key->Address2Hash()."87";
		}
		$script = new Script();
		$pointer["ScriptPubkey"]["asm"] = $script->Hex2Asm($pointer["ScriptPubkey"]["hex"]);
		$pointer["ScriptPubkey"]["type"] = $script->Type($pointer["ScriptPubkey"]["hex"]);

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
				"scriptpubkeyhex" => $this->TX["vout"][$Index]["ScriptPubkey"]["hex"],
				"scriptpubkeyasm" => $this->TX["vout"][$Index]["ScriptPubkey"]["asm"]
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
	public function Sign(&$Key, $Contract = null){
		$Contract = self::SIGHASH_ALL; //Temporarily fixed
		if(get_class($Key) != "Keys"){
			return false;
		}

		$script = new Script();
		self::RawBuild(true);
		$sign = $Key->Sign(self::HashGet(), true);
		foreach($this->TX["vin"] as &$tx){
			if(strtoupper($Key->Priv2Hash()) == $script->GetHash($tx["ScriptSig"]["ScriptPubkey"])){
				$tx["ScriptSig"]["hex"] = dechex(strlen($sign) / 2);
				$tx["ScriptSig"]["hex"] .= $sign."01";
				//Pubkey
				if($script->Type($tx["ScriptSig"]["ScriptPubkey"]) != "pubkey"){
					$temp = $Key->Priv2Pub();
					$tx["ScriptSig"]["hex"] .= dechex(strlen($temp) / 2);
					$tx["ScriptSig"]["hex"] .= $temp;
				}
			}

			$tx["ScriptSig"]["asm"] = $script->Hex2Asm($tx["ScriptSig"]["hex"], true);
		}
		$this->Raw = null;
		$this->Size = null;
		$this->Hash = null;
	}

	private function RawBuild($ForSign = false){
		$temp = $this->TX["version"];
		$temp = str_pad($temp, 8, 0, STR_PAD_LEFT);
		$return = parent::SwapOrder($temp);
		$temp = unpack("H*", pack("C*", count($this->TX["vin"])));
		$return .= reset($temp);
		if(count($this->TX["vin"]) > 0){
			foreach($this->TX["vin"] as $pt){
				$return .= parent::SwapOrder($pt["txid"]);
				$return .= str_pad($pt["vout"], 8, 0, STR_PAD_LEFT);
				if($ForSign){
					$temp = unpack("H*", pack("C*", strlen($pt["ScriptSig"]["ScriptPubkey"]) / 2));
					$return .= reset($temp);
					$return .= $pt["ScriptSig"]["ScriptPubkey"];
				}else{
					$temp = unpack("H*", pack("C*", strlen($pt["ScriptSig"]["hex"]) / 2));
					$return .= reset($temp);
					$return .= $pt["ScriptSig"]["hex"];
				}
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
				$temp = unpack("H*", pack("C*", strlen($pt["ScriptPubkey"]["hex"]) / 2));
				$return .= reset($temp);
				$return .= $pt["ScriptPubkey"]["hex"];
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