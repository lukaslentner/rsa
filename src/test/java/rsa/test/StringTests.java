package rsa.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Optional;

import org.junit.Assert;

import rsa.cryptor.ByteArrayCryptor;
import rsa.keyPair.KeyPair;
import rsa.keyPair.KeyPairGenerator;

public class StringTests {
	
	public static void run(final KeyPair keyPair, final String plainText, final Optional<byte[]> expectedCipherText) throws IOException {
		
		final ByteArrayCryptor cryptor = new ByteArrayCryptor();
		
		final byte[] cipherText = cryptor.encrypt(plainText.getBytes(), keyPair.getPublicKey());
		final byte[] decryptedPlainText = cryptor.decrypt(cipherText, keyPair.getPrivateKey());
		
		Assert.assertArrayEquals(plainText.getBytes(), decryptedPlainText);
		
		if (expectedCipherText.isPresent()) {
			Assert.assertArrayEquals(expectedCipherText.get(), cipherText);
		}
		
	}
	
	public static void run(
		final BigInteger prime1,
		final BigInteger prime2,
		final BigInteger publicExponentProposal,
		final String plainText,
		final Optional<byte[]> expectedCipherText
	) throws IOException {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(prime1, prime2, publicExponentProposal);
		
		run(keyPair, plainText, expectedCipherText);
		
	}
	
	public static void run(
		final String prime1,
		final String prime2,
		final String publicExponentProposal,
		final String plainText,
		final Optional<byte[]> expectedCipherText
	) throws IOException {
		
		run(new BigInteger(prime1), new BigInteger(prime2), new BigInteger(publicExponentProposal), plainText, expectedCipherText);
	
	}
	
	public static void run(final Integer primeBitLength, final String plainText) throws IOException {
		
		final KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		final KeyPair keyPair = keyPairGenerator.generateKeyPair(primeBitLength);
		
		run(keyPair, plainText, Optional.empty());
		
	}
	
}
