package rsa.keyPair;

public class KeyPair {
	
	private final PublicKey publicKey;
	
	private final PrivateKey privateKey;
	
	public KeyPair(final PublicKey publicKey, final PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	public PublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	@Override
	public String toString() {
		return "KeyPair [publicKey=" + this.publicKey + ", privateKey=" + this.privateKey + "]";
	}
	
}
