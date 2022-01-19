package rsa;

import java.math.BigInteger;

public abstract class Utils {
	
	public static BigInteger greatestCommonDevisor(final BigInteger value1, final BigInteger value2) {
		return value1.gcd(value2);
	}
	
	public static BigInteger leastCommonMultiple(final BigInteger value1, final BigInteger value2) {
		return value1.multiply(value2).divide(greatestCommonDevisor(value1, value2));
	}
	
}
