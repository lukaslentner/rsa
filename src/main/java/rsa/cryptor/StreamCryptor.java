package rsa.cryptor;

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

public class StreamCryptor {
	
	private final Cryptor innerCryptor;
	
	public StreamCryptor() {
		this.innerCryptor = new Cryptor();
	}
	
	public void encrypt(final InputStream plainText, final OutputStream cipherText, final PublicKey publicKey) throws IOException {
		
		final Integer inputWordSize = this.getPlainWordSize(publicKey);
		final Integer outputWordSize = this.getCipherWordSize(publicKey);
		final InputStream paddedPlainText = new PaddingInputStream(plainText, inputWordSize);
		
		this.xcrypt(paddedPlainText, inputWordSize, cipherText, outputWordSize, this.innerCryptor::encrypt, publicKey);
		
	}
	
	public void decrypt(final InputStream cipherText, final OutputStream plainText, final PrivateKey privateKey) throws IOException {
		
		final Integer inputWordSize = this.getCipherWordSize(privateKey);
		final Integer outputWordSize = this.getPlainWordSize(privateKey);
		final OutputStream depaddedPlainText = new DepaddingOutputStream(plainText);
		
		this.xcrypt(cipherText, inputWordSize, depaddedPlainText, outputWordSize, this.innerCryptor::decrypt, privateKey);
		
	}
	
	private Integer getPlainWordSize(final Key key) {
		
		// Plain words must be smaller than the modulus
		return key.getModulus().toByteArray().length - 1;
		
	}
	
	private Integer getCipherWordSize(final Key key) {
		
		// Cipher words must be able to keep everything up to modulus-1
		return key.getModulus().subtract(BigInteger.ONE).toByteArray().length;
		
	}
	
	private <K extends Key> void xcrypt(
		final InputStream inputStream,
		final Integer inputWordSize,
		final OutputStream outputStream,
		final Integer outputWordSize,
		final BiFunction<BigInteger, K, BigInteger> concreteXcrypt,
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
			final BigInteger outputNumber = concreteXcrypt.apply(inputNumber, key);
			final byte[] outputBuffer = outputNumber.toByteArray();
			
			outputStream.write(new byte[outputWordSize - outputBuffer.length]);
			outputStream.write(outputBuffer);
			
			if (bytesRead < inputWordSize) {
				return;
			}
			
		}
		
	}
	
}
