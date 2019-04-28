package mac;

import des.DES;
import utils.Constants;
import utils.Utils;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;


public class MAC {
    /**
     * HMAC Algorithm.
     */
    public static String authenticate(String message, BigInteger key) throws NoSuchAlgorithmException {

        // Apply HMAC using SHA-1 as the hash function.
        BigInteger oKeyPad = key.xor(BigInteger.valueOf(0x5C * Constants.SHA_INTERNAL_BLOCK_SIZE));
        BigInteger iKeyPad = key.xor(BigInteger.valueOf(0x36 * Constants.SHA_INTERNAL_BLOCK_SIZE));

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
