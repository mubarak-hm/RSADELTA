package com.hsn;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Implements the cryptographic algorithm proposed in the paper:
 * "INTEGRATION OF RSA WITH DELTA ENCODING TECHNIQUES IN CLOUD SECURITY AND PRIVACY"
 * by Dr. Thomas Yeboah, et al.
 * <p>
 * The Algorithm combines the RSA public-key cryptosystem with Newton's Forward and
 * Backward Differentials (Delta Encoding) to provide a two-layered security approach.
 */
public class RsaWithDeltaEncoding {

    private final BigInteger n;
    private final BigInteger e;
    private final BigInteger d;

    public RsaWithDeltaEncoding(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bitLength, 100, random);
        BigInteger q = new BigInteger(bitLength, 100, random);

        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = new BigInteger("65537");
        d = e.modInverse(phi);
    }


    public RsaWithDeltaEncoding(BigInteger p, BigInteger q) {
        if (!p.isProbablePrime(100) || !q.isProbablePrime(100)) {
            throw new IllegalArgumentException("Inputs must be prime numbers.");
        }
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        if (p.intValue() == 3 && q.intValue() == 11) {
            e = new BigInteger("7");
        } else {

            e = new BigInteger("65537");
        }

        d = e.modInverse(phi);
    }


    public BigInteger[] deltaEncode(String message) {
        if (message == null || message.isEmpty()) {
            return new BigInteger[0];
        }


        int[] asciiValues = message.chars().toArray();
        BigInteger[] encodedValues = new BigInteger[asciiValues.length];


        encodedValues[0] = BigInteger.valueOf(asciiValues[0]);


        for (int i = 1; i < asciiValues.length; i++) {
            encodedValues[i] = BigInteger.valueOf(asciiValues[i] - asciiValues[i - 1]);
        }
        return encodedValues;
    }


    public BigInteger[] rsaEncrypt(BigInteger[] encodedMessage) {
        return Arrays.stream(encodedMessage)
                .map(val -> val.modPow(e, n))
                .toArray(BigInteger[]::new);
    }


    public BigInteger[] encrypt(String plaintext) {
        System.out.println("1. Original Message: \"" + plaintext + "\"");

        BigInteger[] encoded = deltaEncode(plaintext);
        System.out.println("2. Delta Encoded (Newton Forward): " + Arrays.toString(encoded));

        BigInteger[] encrypted = rsaEncrypt(encoded);
        System.out.println("3. Encrypted (RSA): " + Arrays.toString(encrypted));

        return encrypted;
    }


    public BigInteger[] rsaDecrypt(BigInteger[] ciphertext) {
        return Arrays.stream(ciphertext)
                .map(val -> val.modPow(d, n))
                .toArray(BigInteger[]::new);
    }


    public String deltaDecode(BigInteger[] decryptedEncodedValues) {
        if (decryptedEncodedValues == null || decryptedEncodedValues.length == 0) {
            return "";
        }

        long[] asciiValues = new long[decryptedEncodedValues.length];


        asciiValues[0] = decryptedEncodedValues[0].longValue();

        for (int i = 1; i < decryptedEncodedValues.length; i++) {
            asciiValues[i] = decryptedEncodedValues[i].longValue() + asciiValues[i - 1];
        }

        return Arrays.stream(asciiValues)
                .mapToObj(val -> String.valueOf((char) val))
                .collect(Collectors.joining());
    }


    public String decrypt(BigInteger[] ciphertext) {
        BigInteger[] decryptedEncoded = rsaDecrypt(ciphertext);
        System.out.println("4. Decrypted (RSA): " + Arrays.toString(decryptedEncoded));

        String originalMessage = deltaDecode(decryptedEncoded);
        System.out.println("5. Decoded (Newton Backward): \"" + originalMessage + "\"");

        return originalMessage;
    }


    @Override
    public String toString() {
        return "Keys {\n" +
                "  Public Key (e, n): (" + e + ", " + n + ")\n" +
                "  Private Key (d, n): (" + d + ", " + n + ")\n" +
                '}';
    }


    public static void main(String[] args) {
        System.out.println("--- DEMONSTRATION BASED ON THE PAPER'S EXAMPLE ---");

        BigInteger p = new BigInteger("3");
        BigInteger q = new BigInteger("11");
        RsaWithDeltaEncoding rsaDeltaPaper = new RsaWithDeltaEncoding(p, q);
        System.out.println(rsaDeltaPaper);

        String message = "I love my wife";

        System.out.println("\n--- ENCRYPTION PROCESS ---");
        BigInteger[] ciphertext = rsaDeltaPaper.encrypt(message);

        System.out.println("\n--- DECRYPTION PROCESS ---");
        rsaDeltaPaper.decrypt(ciphertext);

        System.out.println("\n\n--- DEMONSTRATION WITH LARGER, SECURE KEYS ---");

        RsaWithDeltaEncoding rsaDeltaSecure = new RsaWithDeltaEncoding(2048);
        System.out.println(rsaDeltaSecure);

        String secureMessage = "This is a much more secure implementation for cloud data.";

        System.out.println("\n--- ENCRYPTION PROCESS ---");
        BigInteger[] secureCiphertext = rsaDeltaSecure.encrypt(secureMessage);

        System.out.println("\n--- DECRYPTION PROCESS ---");
        rsaDeltaSecure.decrypt(secureCiphertext);
    }
}
