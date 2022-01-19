package rsa.cryptor;

import java.math.BigInteger;

import rsa.keyPair.PrivateKey;
import rsa.keyPair.PublicKey;

public class Cryptor {
	
	public BigInteger encrypt(final BigInteger plainText, final PublicKey publicKey) {
		// c ≡ m^e mod n
		
		if (plainText.compareTo(publicKey.getModulus()) != -1) {
			throw new RuntimeException("Plain Text is not smaller than modulus");
		}
		
		return plainText.modPow(publicKey.getExponent(), publicKey.getModulus());
		
	}
	
	public BigInteger decrypt(final BigInteger cipherText, final PrivateKey privateKey) {
		// m ≡ c^d mod n
		
		if (cipherText.compareTo(privateKey.getModulus()) != -1) {
			throw new RuntimeException("Plain Text is not smaller than modulus");
		}
		
		return cipherText.modPow(privateKey.getExponent(), privateKey.getModulus());
		
	}
	
}
