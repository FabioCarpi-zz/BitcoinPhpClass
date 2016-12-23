<?php
// Version 1 from 2016-12-23
/*
 * Credits
 * 
 * Elliptic curve maths
 * https://youtu.be/iB3HcPgm_FI
 * https://youtu.be/U2bw_N6kQL8
 * https://github.com/wobine/blackboard101
 * Decompress pubkey
 * https://bitcointalk.org/index.php?topic=644919.0
 */

require_once("functions.php");

class Keys extends Functions{
	protected $P, $A, $B, $G, $N, $H;
	private $Priv, $PubX, $PubY, $Hash160, $Address;

	/**
	 * 
	 * @param string $PrivKey
	 * @return boolean
	 */
	public function __construct($PrivKey = null){
		parent::__construct();
		$this->A = gmp_init(0);
		$this->B = gmp_init(7);
		$this->P = gmp_init("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
		$this->G = array(
			gmp_init("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
			gmp_init("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
		);
		$this->H = gmp_init(1);
		$this->N = gmp_init("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
		if(!is_null($PrivKey)){
			return self::PrivSet($PrivKey);
		}
	}

	/**
	 * Stores a private key
	 * @param mixed $Key Accept a string in hexadecimal or GMP object
	 * @return boolean
	 */
	public function PrivSet($Key){
		if(is_object($Key) == false and ctype_xdigit($Key) == false){
			return parent::Error("The private key is not in hexadecimal");
		}elseif(is_object($Key) == false and strlen($Key) > 64){
			return parent::Error("The private key is greater than 32 bytes");
		}
		if(is_object($Key) == false){
			$key_dec = gmp_init($Key, 16);
		}elseif(get_class($Key) == "GMP"){
			$key_dec = $Key;
		}else{
			return parent::Error("The private key is not a GMP object");
		}
		if($key_dec <= $this->H){
			return parent::Error("The private key is below the minimum limit of the curve");
		}elseif($key_dec >= $this->N){
			return parent::Error("The private key is above the upper limit of the curve");
		}
		$this->Priv = $key_dec;
		return true;
	}

	/**
	 * Returns the private key stored
	 * @param boolean $InGmp If the key should be returned as GMP object
	 * @return mixed Returns the private key in string or GMP
	 */
	public function PrivGet($InGmp = false){
		if(is_object($this->Priv) == false){
			return parent::Error("Was not created a private key");
		}elseif($InGmp){
			return $this->Priv;
		}else{
			return parent::gmp_tohex($this->Priv, 64);
		}
	}

	/**
	 * Stores a private key in WIF format
	 * @param string $Key WIF format private key
	 * @return boolean Returns <b>true</b> if no errors happen
	 */
	public function WifSet($Key){
		//Decodes
		$key_hex = parent::base58_decode($Key);
		//Removes the checksum
		$sum = substr($key_hex, -8);
		$key_hex = substr($key_hex, 0, -8);
		//Creates the checksum
		$check = parent::Hash256($key_hex);
		$check = substr($check, 0, 8);
		//Check the checksum
		if($sum != $check){
			return parent::Error("Invalid checksum");
		}
		//Remove identifiers
		$key_hex = substr($key_hex, 2);
		if(strlen($key_hex) == 66){
			$key_hex = substr($key_hex, 0, -2);
		}
		return self::PrivSet($key_hex);
	}

	/**
	 * Returns the private key stored in format WIF
	 * @param boolean $FullPub Whether to return the private key with the public key handle compressed
	 * @return string WIF format private key
	 */
	public function WifGet($FullPub = false){
		$key_hex = self::PrivGet();
		$key_hex = "80" . $key_hex;
		if($FullPub == false){
			$key_hex .= "01";
		}
		$check = parent::Hash256($key_hex);
		$check = substr($check, 0, 8);
		return parent::base58_encode($key_hex . $check);
	}

	/**
	 * Generates the public key from the private key
	 * @param boolean $FullPub Whether to return the extended public key
	 * @return string Public key
	 */
	public function Priv2Pub($FullPub = false){
		$priv = self::PrivGet(true);
		$pub = self::EccMultiply($this->G, $priv);
		$this->PubX = parent::gmp_tohex($pub[0]);
		$this->PubY = parent::gmp_tohex($pub[1]);
		return self::PubGet($FullPub);
	}

	/**
	 * Generates the address from the private key
	 * @param boolean $FullPub If the address must be generated using the public key extended
	 * @return string Public key
	 */
	public function Priv2Address($FullPub = false){
		if(self::Priv2Pub() == false){
			return false;
		}
		if(self::Pub2Hash($FullPub) == false){
			return false;
		}
		return self::Hash2Address();
	}

	/**
	 * 
	 * @param bollean $FullPub
	 * @return mixed
	 */
	public function PubGet($FullPub = false){
		if(is_null($this->PubX)){
			return parent::Error("Was not created a public key");
		}
		if($FullPub == true){
			return "04" . $this->PubX . $this->PubY;
		}else{
			if(preg_match("/^5.*ae$/", $this->PubX)){
				return $this->PubX;
			}elseif(gmp_init($this->PubY, 16) % 2 == 1){
				return "03" . $this->PubX;
			}else{
				return "02" . $this->PubX;
			}
		}
	}

	/**
	 * 
	 * @param string $Key
	 * @return boolean
	 */
	public function PubSet($Key){
		if(is_object($Key) == false){
			if(ctype_xdigit($Key)){
				if(substr($Key, 0, 2) != "02" and substr($Key, 0, 2) != "03" and substr($Key, 0, 2) != "04"){
					return parent::Error("The public key does not have an acceptable identifier");
				}elseif(strlen($Key) != 66 and strlen($Key) != 130){
					return parent::Error("The public key does not have a acceptable size");
				}
			}else{
				return parent::Error("The public key is in hexadecimal");
			}
		}
		if(strlen($Key) == 66){
			$this->Priv = null;
			$this->PubX = strtolower(substr($Key, 2));
			$this->PubY = self::PubGetY(substr($Key, 0, 2));
			$this->Hash160 = null;
			$this->Address = null;
		}else{
			$this->Priv = null;
			$this->PubX = strtolower(substr($Key, 2, 64));
			$this->PubY = strtolower(substr($Key, 66));
			$this->Hash160 = null;
			$this->Address = null;
		}
		return true;
	}

	/**
	 *
	 * @param int $Required
	 * @param array $Pubkeys
	 */
	public function CreateMultisig($Required, $Pubkeys){
		if(is_null($Required) or empty($Required)){
			parent::Error("N required provided is null");
		}elseif(!is_int($Required)){
			parent::Error("N required provided is not an integer");
		}elseif($Required < 1){
			parent::Error("N required provided is lower than 1");
		}else{
			$this->Priv = null;
			$this->PubY = null;
			$this->Hash160 = null;
			$this->Address = null;
			$this->PubX = dechex(0x50 + $Required);
			foreach($Pubkeys as $pub){
				$this->PubX .= dechex(strlen($pub) / 2).$pub;
			}
			$this->PubX .= dechex(0x50 + count($Pubkeys))."ae";
		}
	}

	/**
	 * 
	 * @param boolean $FullPub
	 * @return string
	 */
	public function Pub2Hash($FullPub = false){
		$key = self::PubGet($FullPub);
		return $this->Hash160 = parent::Hash160($key);
	}

	/**
	 *
	 * @param boolean $FullPub
	 * @return string
	 */
	public function Pub2Address($FullPub = false){
		self::Pub2Hash($FullPub);
		return self::Hash2Address();
	}

	/**
	 * 
	 * @return string
	 */
	public function Hash160Get(){
		if(ctype_xdigit($this->Hash160) == false){
			return parent::Error("Was not created a Hash160");
		}
		return $this->Hash160;
	}

	/**
	 * 
	 * @param string $Hash
	 * @return boolean
	 */
	public function Hash160Set($Hash){
		if(ctype_xdigit($Hash) == false){
			return parent::Error("The hash160 is not in hexadecimal");
		}
		$this->Priv = null;
		$this->PubX = null;
		$this->PubY = null;
		$this->Hash160 = $Hash;
		$this->Address = null;
		return true;
	}

	/**
	 * 
	 * @return string
	 */
	public function Hash2Address(){
		if(is_null($this->PubY)){
			$check = "05" . self::Hash160Get();
		}else{
			$check = "00" . self::Hash160Get();
		}
		$check = parent::Hash256($check);
		$check = substr($check, 0, 8);
		if(is_null($this->PubY)){
			$adr = "05" . self::Hash160Get() . $check;
		}else{
			$adr = "00" . self::Hash160Get() . $check;
		}
		return $this->Address = parent::base58_encode($adr);
	}

	/**
	 * 
	 * @return string
	 */
	public function AddressGet(){
		if(is_null($this->Address)){
			return parent::Error("Was not created an address");
		}
		return $this->Address;
	}

	/**
	 * 
	 * @param string $Adr
	 * @return boolean
	 */
	public function AddressSet($Adr){
		if(is_null($Adr) or empty($Adr)){
			return parent::Error("Not been set an address");
		}elseif(!preg_match("/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/", $Adr)){
			return parent::Error("The address is not valid");
		}
		$adr = parent::base58_decode($Adr);
		if(substr($Adr, 0, 1) == 1){
			$adr = "00".$adr;
		}
		$sum = substr($adr, -8);
		$adr = substr($adr, 0, -8);
		$check = parent::Hash256($adr);
		$check = substr($check, 0, 8);
		if($check != $sum){
			return parent::Error("The checksum of the address is not valid");
		}
		$this->Address = $Adr;
		return true;
	}

	/**
	 * 
	 * @return string
	 */
	public function Address2Hash(){
		if(is_null($this->Address)){
			return parent::Error("Not been set an address");
		}
		$hash = parent::base58_decode($this->Address);
		$hash = strtoupper($hash);
		if(substr($this->Address, 0, 1) == 1){
			$hash = "00".$hash;
		}
		return $this->Hash160 = substr($hash, 2, -8);
	}

	/**
	 * 
	 * @param string $Hash
	 * @param boolean $ReturnDer
	 * @return array
	 */
	public function Sign($Hash, $ReturnDer = false){
		self::PrivGet();
		$RandNum = bin2hex(random_bytes(32));
		$RandNum = gmp_init($RandNum, 16);
		$Hash = gmp_init($Hash, 16);
		list($xRandSignPoint, $yRandSignPoint) = self::EccMultiply($this->G, $RandNum);
		$r = $xRandSignPoint % $this->N;
		$s = (($Hash + $r * $this->Priv) * self::EccInv($RandNum, $this->N)) % $this->N;
		$return = array("r" => parent::gmp_tohex($r), "s" => parent::gmp_tohex($s));
		if($ReturnDer){
			return self::DerEncode($return);
		}else{
			return $return;
		}
	}

	/**
	 * 
	 * @param string $Hash
	 * @param array $Sign
	 * @return boolean
	 */
	public function CheckSign($Hash, $Sign){
		$Hash = gmp_init($Hash, 16);
		$r = gmp_init($Sign["r"], 16);
		$s = gmp_init($Sign["s"], 16);
		self::PubGet();
		$pub = array(gmp_init($this->PubX, 16), gmp_init($this->PubY, 16));
		$w = self::EccInv($s, $this->N);
		$u1 = self::EccMultiply($this->G, ($Hash * $w) % $this->N);
		$u2 = self::EccMultiply($pub, ($r * $w) % $this->N);
		list($x, $y) = self::EccAdd($u1, $u2);
		return $r == $x;
	}

	/**
	 * 
	 * @param array $Sign
	 * @return string
	 */
	public function DerEncode($Sign){
		$return = "02";
		$return .= dechex(strlen($Sign["r"]) / 2);
		$return .= $Sign["r"];
		$return .= "02";
		$return .= dechex(strlen($Sign["s"]) / 2);
		$return .= $Sign["s"];
		return "30" . dechex(strlen($return) / 2) . $return;
	}

//-------------------------------------------------------------------------------

	/**
	 * 
	 * @param string $byte
	 * @return string
	 */
	private function PubGetY($byte){
		$x = gmp_init($this->PubX, 16);
		$a = (gmp_powm($x, 3, $this->P) + 7) % $this->P;
		$y = gmp_powm($a, ($this->P + 1) / 4, $this->P);
		$yy = gmp_neg($y) % $this->P;
		if($byte == "02"){
			if($y % 2 == 0){
				return parent::gmp_tohex($y);
			}else{
				return parent::gmp_tohex($yy);
			}
		}else{
			if($y % 2 == 1){
				return parent::gmp_tohex($y);
			}else{
				return parent::gmp_tohex($yy);
			}
		}
	}

	/**
	 * 
	 * @param string $ScalarHex
	 * @param array $GenPoint
	 * @return array
	 */
	private function EccMultiply($GenPoint, $ScalarHex){
		$ScalarBin = gmp_strval($ScalarHex, 2);
		$ScalarBin = substr($ScalarBin, 1);
		$Q = $GenPoint;
		while(strlen($ScalarBin) > 0){
			$Q = self::EccDouble($Q);
			if(substr($ScalarBin, 0, 1) == "1"){
				$Q = self::EccAdd($Q, $GenPoint);
			}
			$ScalarBin = substr($ScalarBin, 1);
		}
		return $Q;
	}

	/**
	 * 
	 * @param array $a
	 * @return array
	 */
	private function EccDouble($a){
		$Lam = ((3 * $a[0] * $a[0] + $this->A) * self::EccInv(2 * $a[1])) % $this->P;
		$x = ($Lam * $Lam - 2 * $a[0]) % $this->P;
		$y = ($Lam * ($a[0] - $x) - $a[1]) % $this->P;
		return array($x, $y);
	}

	/**
	 * 
	 * @param string $a
	 * @return string
	 */
	private function EccInv($a, $n = null){
		if(is_null($n)){
			$n = $this->P;
		}
		$lm = 1;
		$hm = 0;
		$low = $a % $n;
		$high = $n;
		while($low > 1){
			$ratio = $high / $low;
			$nm = $hm - $lm * $ratio;
			$new = $high - $low * $ratio;
			$high = $low;
			$hm = $lm;
			$low = $new;
			$lm = $nm;
		}
		return $lm % $n;
	}

	/**
	 * 
	 * @param array $a
	 * @param array $b
	 * @return array
	 */
	protected function EccAdd($a, $b){
		$LamAdd = (($b[1] - $a[1]) * self::EccInv($b[0] - $a[0])) % $this->P;
		$x = ($LamAdd * $LamAdd - $a[0] - $b[0]) % $this->P;
		$y = ($LamAdd * ($a[0] - $x) - $a[1]) % $this->P;
		return array($x, $y);
	}
}