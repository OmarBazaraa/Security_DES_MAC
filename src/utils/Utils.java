package utils;

import java.util.ArrayList;
import java.util.List;


public class Utils {

    public static List<Long> splitTextIntoBlocks(String text, int blockSize) {
        List<Long> ret = new ArrayList<>();

        for (int i = 0; i < text.length(); i += blockSize) {
            long block = 0;

            for (int j = 0; j < blockSize && i + j < text.length(); ++j) {
                block |= ((long) text.charAt(i + j)) << (j << 3);
            }

            ret.add(block);
        }

        return ret;
    }

    public static List<Long> splitHexIntoBlocks(String text, int blockSize) {
        List<Long> ret = new ArrayList<>();

        int size = text.length();
        int hexBlockSize = blockSize * 2;

        for (int i = 0; i < text.length(); i += hexBlockSize) {
            String cipherBlockHex = text.substring(i, Math.min(i + hexBlockSize, size));
            ret.add(Long.parseUnsignedLong(cipherBlockHex, 16));
        }

        return ret;
    }

    public static String blockToHex(long block, int blockSize) {
        StringBuilder ret = new StringBuilder();

        for (int i = blockSize * 2 - 1; i >= 0; --i) {
            long x = (block >>> (i << 2)) & 0xF;

            if (x > 9) {
                ret.append((char) ('a' + x - 10));
            } else {
                ret.append((char) ('0' + x));
            }
        }

        return ret.toString();
    }

    public static String blockToStr(long block, int blockSize) {
        StringBuilder ret = new StringBuilder();

        for (int i = 0; i < blockSize; ++i) {
            long x = block & 0xFF;
            block >>>= 8;
            ret.append((char) x);
        }

        return ret.toString();
    }
}
