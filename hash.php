<?php 

class generateHash {

/* Informacinės saugos pagrindai - Hashing */

public $Study_Book_No = '000000000';

private $options;

public function __construct()
{
	echo "Script for usage from command line and http(s)." . PHP_EOL;
	if((int)$this->Study_Book_No > 0)
	{
		$this->generateHash($this->Study_Book_No);
	}
	else
	{
		echo "Error: Invalid Study Book No.";
		echo $this->PHP_EOL();
		echo "Tip. Edit the file and change variable \$Study_Book_No.";
		echo $this->PHP_EOL();
		echo "For Research. ";
		echo $this->showOpenSSLMethods();
		echo $this->PHP_EOL();
	}
}

protected function generateHash($Number = 0)
{
	$i = 0;
	$j = 0;
	if(isset($this->Study_Book_No) and (int)$Number > 0)
	{
		$i = $i + 1;
		echo $i .".".$this->PHP_EOL();
		$j++;
		/* Does it is a hash? */
		print('Username: username; Password: '. $Number);
		
		$i = $i + 1;
		echo $i .".".$this->PHP_EOL();
		$j++;
		/* Does it is a hash? */
		print('Username: base64; Password: '. base64_encode($Number));

		if (function_exists('md5')) {

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			print('Username: MD5; Password: '. md5($Number));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			print('Username: MD5(MD5); Password: '. md5(md5(md5($Number))));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			print('Username: MD5+Salt(1); Password: '. md5('security'.$Number));
		
		}
		
		if (function_exists('crypt')) {
		
			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			print('Username: MD5+Salt(2); Password: '. crypt($Number, '$1$security$'));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			/* Warning! Salt of Bytes */
			print('Username: MD5+Salt(3); Password: '. crypt($Number, '$1$'.$this->basicSalt(12).'$'));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			/* Warning! Salt of Bytes */
			print('Username: MD5+Salt(4); Password: '. crypt('abc'.$Number.'!@#', '$1$'.$this->basicSalt(12).'$'));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash? */
			print('Username: SHA1; Password: '. sha1('abc'.$Number.'!@#'));

			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strong hash */
			print('Username: SHA256; Password: '. crypt('abc'.$Number.'!@#','$5$rounds=1000$additionalsalts.'));
		
		}
		
		if(defined("PASSWORD_DEFAULT")) {
		
        	$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strongest hash */
			print('Username: BCRYPT; Password: '. password_hash($Number, PASSWORD_DEFAULT));
		
		}
		
		if(defined("PASSWORD_BCRYPT")) {
		
			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strongest hash */
			$this->options = array("cost" => 12,);
			print('Username: BCRYPT; Password: '. password_hash($Number, PASSWORD_BCRYPT, $this->options));
			
			// Does password_hash has something with crypt_blowfish?
		
		}
		
		if(defined("PASSWORD_ARGON2I")) {
		
			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strongest hash */
		
			foreach ($this->options as $key => $value) {
				unset($this->options[$key]);
			}
			
			$this->options = array("memory_cost" => 1<<10, "time_cost" => 1, "threads" => 1);
			print('Username: ARGON2; Password: '. password_hash($Number, PASSWORD_ARGON2I, $this->options));
			
			// Does this hash algorithm is a winner of Password Hashing Competition?
		
			$i = $i + 1;
			echo $i .".".$this->PHP_EOL();
			$j++;
			/* Does it is a strongest hash */
			print('Username: ARGON2; Password: '. password_hash($Number, PASSWORD_ARGON2I));

			// Does this hash algorithm is a winner of Password Hashing Competition?
		}
		
		echo "__.".$this->PHP_EOL();
		
		echo "Generated " .$i." out of ". $j.".".$this->PHP_EOL();
		
		

		echo $this->PHP_EOL();
}

}

protected function PHP_EOL()
{
	print("\n");
}

protected function basicSalt($length = 32) {
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }
    
    if (function_exists('mcrypt_create_iv')) {
        return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
    }
    
    if (function_exists('openssl_random_pseudo_bytes')) {
        return openssl_random_pseudo_bytes($length);
    }
    
    $min = '1';
    $max = '9';
    for($i = 1; $i < $length; $i++) {
        $min = $min.'0';
        $max = $max.'9';
    }
    
    settype($min, "integer");
    settype($max, "integer");
    
    return rand($min,$max);
}

public function showOpenSSLMethods()
{
	if(extension_loaded("openssl")) {
		echo "OpenSSL Message Digest Algo:";
		echo $this->PHP_EOL();
		print_r(openssl_get_md_methods());
		echo $this->PHP_EOL();
		echo "OpenSSL Ciphers:";
		echo $this->PHP_EOL();
		print_r(openssl_get_cipher_methods());
	}
	elseif(extension_loaded("mcrypt")) {
		echo "Mcrypt - available.";
		
		//for encryption & decryption only
		//i.e.
		//$encrypted_data = mcrypt_ecb (MCRYPT_3DES, 'symmetric_cryptography_key', 'Plaintext message', MCRYPT_ENCRYPT);
		
		//$encrypted_data = mcrypt_ecb (MCRYPT_3DES, 'symmetric_cryptography_key', 'Encrypted message', MCRYPT_DECRYPT);
		
		//mcrypt_list_algorithms()
		//mcrypt_list_modes() 
		
		echo $this->PHP_EOL();
	}
	else {
		echo "OpenSSL - not available.";
		echo $this->PHP_EOL();
	}
} 

public function __destruct()
{
	unset($this->Study_Book_No);
}

}

$gH = new generateHash;
