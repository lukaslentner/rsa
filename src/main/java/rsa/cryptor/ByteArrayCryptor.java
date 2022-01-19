package rsa.cryptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import rsa.keyPair.PrivateKey;
import rsa.keyPair.PublicKey;

public class ByteArrayCryptor {
	
	private final StreamCryptor innerCryptor;
	
	public ByteArrayCryptor() {
		this.innerCryptor = new StreamCryptor();
	}
	
	public byte[] encrypt(final byte[] plainText, final PublicKey publicKey) throws IOException {
		
		final ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
		
		this.innerCryptor.encrypt(new ByteArrayInputStream(plainText), cipherText, publicKey);
		
		return cipherText.toByteArray();
		
	}
	
	public byte[] decrypt(final byte[] cipherText, final PrivateKey privateKey) throws IOException {
		
		final ByteArrayOutputStream plainText = new ByteArrayOutputStream();
		
		this.innerCryptor.decrypt(new ByteArrayInputStream(cipherText), plainText, privateKey);
		
		return plainText.toByteArray();
		
	}
	
}
