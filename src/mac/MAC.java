package mac;

import des.DES;
import utils.Constants;
import utils.Utils;

import java.util.List;


public class MAC {

    public static String authenticate(String message, long key) {
        List<Long> blocks = Utils.splitTextIntoBlocks(message, Constants.MAC_BLOCK_SIZE);

        long mac = 0;

        for (long block : blocks) {
            mac ^= block;
        }

        mac = DES.encrypt(mac, key);

        return Utils.blockToStr(mac, Constants.MAC_BLOCK_SIZE);
    }

    public static boolean verify(String message, long key) {
        if (message.length() <= Constants.MAC_BLOCK_SIZE) {
            return false;
        }

        int size = message.length();

        String body = message.substring(0, size - Constants.MAC_BLOCK_SIZE);
        String mac = message.substring(size - Constants.MAC_BLOCK_SIZE);

        return mac.equals(authenticate(body, key));
    }
}
