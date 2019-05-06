package mac;

import utils.Constants;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;


/**
 * HMAC Algorithm.
 */
public class MAC {

    public static String authenticate(String message, BigInteger key) throws NoSuchAlgorithmException {
        // Apply HMAC using SHA-1 as the hash function.
        BigInteger oKeyPad = key.xor(BigInteger.valueOf(0x5C5C5C5C5C5C5C5CL));
        BigInteger iKeyPad = key.xor(BigInteger.valueOf(0x3636363636363636L));

        return SHA1.hash(oKeyPad.toString(16) + SHA1.hash(iKeyPad.toString(16) + message));
    }

    public static boolean verify(String message, BigInteger key) throws NoSuchAlgorithmException {
        if (message.length() <= Constants.MAC_BLOCK_SIZE) {
            return false;
        }

        int size = message.length();

        String body = message.substring(0, size - Constants.MAC_BLOCK_SIZE);
        String mac = message.substring(size - Constants.MAC_BLOCK_SIZE);

        return mac.equals(authenticate(body, key));
    }
}
