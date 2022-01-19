package rsa.keyPair;

import java.math.BigInteger;
import java.util.Optional;
import java.util.Random;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import rsa.Utils;

public class KeyPairGenerator {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(KeyPairGenerator.class);
	
	private static final Random RANDOM = new Random(System.currentTimeMillis());
	
	private static final BigInteger[] INNER_PUBLIC_EXPONENT_PROPOSALS =
		new BigInteger[] { new BigInteger("65537"), new BigInteger("4294967297"), new BigInteger("18446744073709551617") }; // Some Fermat Numbers
	
	public KeyPair generateKeyPair(final BigInteger prime1 /* p */, final BigInteger prime2 /* q */, final Optional<BigInteger> publicExponentProposal /* e */) {
		
		LOGGER.debug("Prime 1 (p): {}", prime1);
		LOGGER.debug("Prime 2 (q): {}", prime2);
		
		final BigInteger modulus = this.calculateModulus(prime1, prime2); // n
		LOGGER.debug("Modulus (n): {}", modulus);
		
		final BigInteger modulusTotient = this.calculateModulusTotient(prime1, prime2); // λ
		LOGGER.debug("Modulus Totient (λ): {}", modulusTotient);
		
		final BigInteger publicExponent = this.calculatePublicExponent(publicExponentProposal, modulusTotient); // e
		LOGGER.debug("Public Exponent (e): {}", publicExponent);
		
		final BigInteger privateExponent = this.calculatePrivateExponent(publicExponent, modulusTotient); // d
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
	
	private BigInteger calculateModulus(final BigInteger prime1, final BigInteger prime2) {
		// n = p * q
		
		return prime1.multiply(prime2);
		
	}
	
	private BigInteger calculateModulusTotient(final BigInteger prime1, final BigInteger prime2) {
		// λ = lcm(p - 1, q - 1)
		
		return Utils.leastCommonMultiple(prime1.subtract(BigInteger.ONE), prime2.subtract(BigInteger.ONE));
		
	}
	
	private BigInteger calculatePublicExponent(final Optional<BigInteger> publicExponentProposal, final BigInteger modulusTotient) {
		// e, 1 < e < λ and e is co-prime to λ
		
		final Consumer<BigInteger> check = publicExponent -> {
			
			if (publicExponent.compareTo(BigInteger.ONE) != 1) {
				throw new RuntimeException("Public Exponent is not greater than 1");
			}
			
			if (publicExponent.compareTo(modulusTotient) != -1) {
				throw new RuntimeException("Public Exponent is not smaller than Modulus Totient");
			}
			
			if (!Utils.greatestCommonDevisor(publicExponent, modulusTotient).equals(BigInteger.ONE)) {
				throw new RuntimeException("Public Exponent is not co-prime to Modulus Totient");
			}
			
		};
		
		if (publicExponentProposal.isPresent()) {
			check.accept(publicExponentProposal.get());
			return publicExponentProposal.get();
		}
		
		for (final BigInteger innerPublicExponentProposal : INNER_PUBLIC_EXPONENT_PROPOSALS) {
			try {
				check.accept(innerPublicExponentProposal);
				return innerPublicExponentProposal;
			} catch (Throwable t) {
				continue;
			}
		}
		
		throw new RuntimeException("Could not find suitable Public Exponent");
		
	}
	
	private BigInteger calculatePrivateExponent(final BigInteger publicExponent, final BigInteger modulusTotient) {
		// d ≡ e^−1 (mod λ)
		
		return publicExponent.modInverse(modulusTotient);
		
	}
	
}
