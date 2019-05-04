package mac;

import utils.Constants;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class SHA1 {

    /**
     * SHA-1 takes a string, hash it into 160 bit then these are bits are rendered as
     * a positive Hex Number.
     */
    public static String hash(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // SHA 1 returns an array of 160 bit (20 bytes) "From Wikipedia".
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert the bytes array into a positive big integer.
        BigInteger y = new BigInteger(1, messageDigest);

        // For simplicity, render in Hex base. So the string length is maximum of 40 digits.
        // Note: The real SHA-1 number representation is Base64.
        StringBuilder yHex = new StringBuilder(y.toString(16));

        // Pad the hash to match the MAC_BLOCK_SIZE.
        while (yHex.length() < Constants.MAC_BLOCK_SIZE) {
            yHex.insert(0, "0");
        }

        return yHex.toString();
    }
}
