package rsa.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Optional;

import org.junit.Assert;

import rsa.Cryptex;
import rsa.keyPair.KeyPair;
import rsa.keyPair.KeyPairGenerator;

public class StringTests {
	
	public static void run(final KeyPair keyPair, final String mustPlainText, final Optional<byte[]> mustCipherText) throws IOException {
		
		final Cryptex cryptex = new Cryptex();
		
		final byte[] cipherText = cryptex.encrypt(mustPlainText.getBytes(), keyPair.getPublicKey());
		final byte[] plainText = cryptex.decrypt(cipherText, keyPair.getPrivateKey());
		
		Assert.assertArrayEquals(mustPlainText.getBytes(), plainText);
		
		if (mustCipherText.isPresent()) {
			Assert.assertArrayEquals(mustCipherText.get(), cipherText);
		}
		
	}
	
	public static void run(
		final BigInteger prime1,
		final BigInteger prime2,
		final BigInteger publicExponent,
		final String mustPlainText,
		final Optional<byte[]> mustCipherText
	) throws IOException {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(prime1, prime2, publicExponent);
		
		run(keyPair, mustPlainText, mustCipherText);
		
	}
	
	public static void run(
		final String prime1,
		final String prime2,
		final String publicExponent,
		final String mustPlainText,
		final Optional<byte[]> mustCipherText
	) throws IOException {
		run(new BigInteger(prime1), new BigInteger(prime2), new BigInteger(publicExponent), mustPlainText, mustCipherText);
	}
	
	public static void run(final Integer primeBitLength, final String mustPlainText) throws IOException {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(primeBitLength);
		
		run(keyPair, mustPlainText, Optional.empty());
		
	}
	
}
