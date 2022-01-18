package rsa.keyPair;

import java.math.BigInteger;

public class PublicKey implements Key {
	
	private final BigInteger exponent;
	
	private final BigInteger modulus;
	
	public PublicKey(final BigInteger exponent, final BigInteger modulus) {
		this.exponent = exponent;
		this.modulus = modulus;
	}
	
	public BigInteger getExponent() {
		return this.exponent;
	}
	
	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((this.modulus == null) ? 0 : this.modulus.hashCode());
		result = prime * result + ((this.exponent == null) ? 0 : this.exponent.hashCode());
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (obj == null) return false;
		if (getClass() != obj.getClass()) return false;
		PublicKey other = (PublicKey) obj;
		if (this.modulus == null) {
			if (other.modulus != null) return false;
		} else if (!this.modulus.equals(other.modulus)) return false;
		if (this.exponent == null) {
			if (other.exponent != null) return false;
		} else if (!this.exponent.equals(other.exponent)) return false;
		return true;
	}
	
	@Override
	public String toString() {
		return "PublicKey [exponent=" + this.exponent + ", modulus=" + this.modulus + "]";
	}
	
}
