package rsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.function.BiFunction;

import rsa.keyPair.Key;
import rsa.keyPair.PrivateKey;
import rsa.keyPair.PublicKey;
import rsa.padding.DepaddingOutputStream;
import rsa.padding.PaddingInputStream;

public class Cryptex {
	
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
	
	private <K extends Key> void streamRun(
		final InputStream inputStream,
		final Integer inputWordSize,
		final OutputStream outputStream,
		final Integer outputWordSize,
		final BiFunction<BigInteger, K, BigInteger> function,
		final K key
	) throws IOException {
		
		final byte[] inputBuffer = new byte[inputWordSize];
		while (true) {
			
			final Integer bytesRead = inputStream.read(inputBuffer);
			if (bytesRead < 0) {
				return;
			}
			if (bytesRead < inputWordSize) {
				throw new RuntimeException("Unexpected end of input stream");
			}
			
			final BigInteger inputNumber = new BigInteger(inputBuffer);
			final BigInteger outputNumber = function.apply(inputNumber, key);
			final byte[] outputBuffer = outputNumber.toByteArray();
			
			outputStream.write(new byte[outputWordSize - outputBuffer.length]);
			outputStream.write(outputBuffer);
			
			if (bytesRead < inputWordSize) {
				return;
			}
			
		}
		
	}
	
	private Integer getPlainWordSize(final Key key) {
		return this.getCipherWordSize(key) - 1;
	}
	
	private Integer getCipherWordSize(final Key key) {
		return key.getModulus().subtract(BigInteger.ONE).toByteArray().length;
	}
	
	public void encrypt(final InputStream plainText, final OutputStream cipherText, final PublicKey publicKey) throws IOException {
		
		final Integer inputWordSize = this.getPlainWordSize(publicKey);
		final Integer outputWordSize = this.getCipherWordSize(publicKey);
		final InputStream paddedPlainText = new PaddingInputStream(plainText, inputWordSize);
		
		this.streamRun(paddedPlainText, inputWordSize, cipherText, outputWordSize, this::encrypt, publicKey);
	
	}
	
	public void decrypt(final InputStream cipherText, final OutputStream plainText, final PrivateKey privateKey) throws IOException {
		
		final Integer inputWordSize = this.getCipherWordSize(privateKey);
		final Integer outputWordSize = this.getPlainWordSize(privateKey);
		final OutputStream depaddedPlainText = new DepaddingOutputStream(plainText);
		
		this.streamRun(cipherText, inputWordSize, depaddedPlainText, outputWordSize, this::decrypt, privateKey);
	
	}
	
	public byte[] encrypt(final byte[] plainText, final PublicKey publicKey) throws IOException {
		final ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
		this.encrypt(new ByteArrayInputStream(plainText), cipherText, publicKey);
		return cipherText.toByteArray();
	}
	
	public byte[] decrypt(final byte[] cipherText, final PrivateKey privateKey) throws IOException {
		final ByteArrayOutputStream plainText = new ByteArrayOutputStream();
		this.decrypt(new ByteArrayInputStream(cipherText), plainText, privateKey);
		return plainText.toByteArray();
	}
	
}
