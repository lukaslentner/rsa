package rsa.keyPair;

import java.math.BigInteger;
import java.util.Optional;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyPairGenerator {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(KeyPairGenerator.class);
	
	private static final Random RANDOM = new Random(System.currentTimeMillis());
	
	private static final BigInteger[] PUBLIC_EXPONENT_CANDIDATES =
		new BigInteger[] {
			new BigInteger("17"),
			new BigInteger("257"),
			new BigInteger("65537"),
			new BigInteger("4294967297"),
			new BigInteger("18446744073709551617") }; // Fermat Numbers
	
	private KeyPair generateKeyPair(final BigInteger prime1 /* p */, final BigInteger prime2 /* q */, final Optional<BigInteger> optionalPublicExponent /* e */) {
		
		LOGGER.debug("Prime 1 (p): {}", prime1);
		LOGGER.debug("Prime 2 (q): {}", prime2);
		
		final BigInteger modulus = prime1.multiply(prime2); // n
		final BigInteger modulusTotient = primeProductTotient(prime1, prime2); // λ(n)
		LOGGER.debug("Modulus (n): {}", modulus);
		LOGGER.debug("Modulus Totient (λ(n)): {}", modulusTotient);
		
		final BigInteger publicExponent = this.generatePublicExponent(optionalPublicExponent, modulusTotient); // e
		LOGGER.debug("Public Exponent (e): {}", publicExponent);
		
		final BigInteger privateExponent = calculatePrivateExponent(publicExponent, modulusTotient); // d
		LOGGER.debug("Private Exponent (d): {}", privateExponent);
		
		final PublicKey publicKey = new PublicKey(publicExponent, modulus);
		final PrivateKey privateKey = new PrivateKey(privateExponent, modulus);
		final KeyPair keyPair = new KeyPair(publicKey, privateKey);
		
		return keyPair;
		
	}
	
	public KeyPair generateKeyPair(final BigInteger prime1 /* p */, final BigInteger prime2 /* q */, final BigInteger publicExponent /* e */) {
		return this.generateKeyPair(prime1, prime2, Optional.of(publicExponent));
	}
	
	public KeyPair generateKeyPair(final Integer primeBitLength) {
		
		final BigInteger prime1 = BigInteger.probablePrime(primeBitLength, RANDOM);
		final BigInteger prime2 = BigInteger.probablePrime(primeBitLength, RANDOM);
		
		return this.generateKeyPair(prime1, prime2, Optional.empty());
		
	}
	
	private BigInteger generatePublicExponent(final Optional<BigInteger> optionalPublicExponent, final BigInteger modulusTotient) {
		
		if (optionalPublicExponent.isPresent()) {
			checkPublicExponent(optionalPublicExponent.get(), modulusTotient);
			return optionalPublicExponent.get();
		}
		
		for(Integer index = 0; index < PUBLIC_EXPONENT_CANDIDATES.length; index++) {
			try {
				final BigInteger publicExponent = PUBLIC_EXPONENT_CANDIDATES[index];
				checkPublicExponent(publicExponent, modulusTotient);
				return publicExponent;
			} catch(Throwable t) {
				continue;
			}
		}
		
		throw new RuntimeException("Could not find suitable Public Exponent");
	
	}
	
	private static void checkPublicExponent(final BigInteger publicExponent, final BigInteger modulusTotient) {
		
		if (publicExponent.compareTo(BigInteger.ONE) != 1) {
			throw new RuntimeException("Public Exponent is not greater than 1");
		}
		
		if (publicExponent.compareTo(modulusTotient) != -1) {
			throw new RuntimeException("Public Exponent is not smaller than modulus totient");
		}
		
		if (!greatestCommonDevisor(publicExponent, modulusTotient).equals(BigInteger.ONE)) {
			throw new RuntimeException("Public Exponent is not co-prime to modulus totient");
		}
		
	}
	
	private static BigInteger primeProductTotient(final BigInteger factor1, final BigInteger factor2) {
		// λ = lcm(p - 1, q - 1)
		return leastCommonMultiple(factor1.subtract(BigInteger.ONE), factor2.subtract(BigInteger.ONE));
	}
	
	private static BigInteger greatestCommonDevisor(final BigInteger value1, final BigInteger value2) {
		return value1.gcd(value2);
	}
	
	private static BigInteger leastCommonMultiple(final BigInteger value1, final BigInteger value2) {
		return value1.multiply(value2).divide(greatestCommonDevisor(value1, value2));
	}
	
	private static BigInteger calculatePrivateExponent(final BigInteger publicExponent, final BigInteger modulusTotient) {
		// d ≡ e^−1 (mod λ(n));
		return publicExponent.modInverse(modulusTotient);
	}
	
}
