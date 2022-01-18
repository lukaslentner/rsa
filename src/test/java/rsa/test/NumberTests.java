package rsa.test;

import java.math.BigInteger;
import java.util.Optional;

import org.junit.Assert;

import rsa.Cryptex;
import rsa.keyPair.KeyPair;
import rsa.keyPair.KeyPairGenerator;

public class NumberTests {
	
	public static void run(
		final BigInteger prime1,
		final BigInteger prime2,
		final BigInteger publicExponent,
		final BigInteger mustPlainText,
		final Optional<BigInteger> mustCipherText
	) {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		final Cryptex cryptex = new Cryptex();
		
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(prime1, prime2, publicExponent);
		
		final BigInteger cipherText = cryptex.encrypt(mustPlainText, keyPair.getPublicKey());
		final BigInteger plainText = cryptex.decrypt(cipherText, keyPair.getPrivateKey());
		
		Assert.assertEquals(mustPlainText, plainText);
		
		if (mustCipherText.isPresent()) {
			Assert.assertEquals(mustCipherText.get(), cipherText);
		}
		
	}
	
	public static void run(
		final String prime1,
		final String prime2,
		final String publicExponent,
		final String mustPlainText,
		final Optional<String> mustCipherText
	) {
		run(
			new BigInteger(prime1),
			new BigInteger(prime2),
			new BigInteger(publicExponent),
			new BigInteger(mustPlainText),
			mustCipherText.map(t -> new BigInteger(t))
		);
	}
	
}
