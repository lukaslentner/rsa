package rsa.test;

import java.math.BigInteger;
import java.util.Optional;

import org.junit.Assert;

import rsa.cryptor.Cryptor;
import rsa.keyPair.KeyPair;
import rsa.keyPair.KeyPairGenerator;

public class BigIntegerTests {
	
	public static void run(
		final BigInteger prime1,
		final BigInteger prime2,
		final BigInteger publicExponentProposal,
		final BigInteger plainText,
		final Optional<BigInteger> expectedCipherText
	) {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		final Cryptor cryptor = new Cryptor();
		
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(prime1, prime2, publicExponentProposal);
		
		final BigInteger cipherText = cryptor.encrypt(plainText, keyPair.getPublicKey());
		final BigInteger decryptedPlainText = cryptor.decrypt(cipherText, keyPair.getPrivateKey());
		
		Assert.assertEquals(plainText, decryptedPlainText);
		
		if (expectedCipherText.isPresent()) {
			Assert.assertEquals(expectedCipherText.get(), cipherText);
		}
		
	}
	
	public static void run(
		final String prime1,
		final String prime2,
		final String publicExponentProposal,
		final String plainText,
		final Optional<String> expectedCipherText
	) {
		
		run(
			new BigInteger(prime1),
			new BigInteger(prime2),
			new BigInteger(publicExponentProposal),
			new BigInteger(plainText),
			expectedCipherText.map(t -> new BigInteger(t))
		);
		
	}
	
}
