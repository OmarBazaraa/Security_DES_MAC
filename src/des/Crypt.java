package des;

import mac.MAC;
import utils.Constants;
import utils.Utils;

import java.security.NoSuchAlgorithmException;
import java.util.List;


public class Crypt extends DES {

    /**
     * Encrypts the given message using the given mode of DES algorithm
     * with the given private key.
     *
     * @param message a string of characters to encrypt.
     * @param config  DES configurations object
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encrypt(String message, DESConfig config) throws NoSuchAlgorithmException {
        message = message + MAC.authenticate(message, Constants.MAC_PRIVATE_KEY);

        switch (config.mode) {
            case ELECTRONIC_CODEBOOK:
                return encryptECB(message, config.privateKey);
            case CIPHER_BLOCK_CHAINING:
                return encryptCBC(message, config.privateKey, config.getInitialVector());
            case CIPHER_FEEDBACK:
                return encryptCFB(message, config.privateKey, config.getInitialVector(), config.blockSize);
            case OUTPUT_FEEDBACK:
                return encryptOFB(message, config.privateKey, config.getInitialVector());
            case COUNTER:
                return encryptCTR(message, config.privateKey);
        }

        return "";
    }

    /**
     * Decrypts the given ciphered message using the given mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param config     DES configurations object
     *
     * @return the decrypted message.
     */
    public static String decrypt(String ciphertext, DESConfig config) throws NoSuchAlgorithmException {
        String message = "";

        switch (config.mode) {
            case ELECTRONIC_CODEBOOK:
                message = decryptECB(ciphertext, config.privateKey);
                break;
            case CIPHER_BLOCK_CHAINING:
                message = decryptCBC(ciphertext, config.privateKey, config.getInitialVector());
                break;
            case CIPHER_FEEDBACK:
                message = decryptCFB(ciphertext, config.privateKey, config.getInitialVector(), config.blockSize);
                break;
            case OUTPUT_FEEDBACK:
                message = decryptOFB(ciphertext, config.privateKey, config.getInitialVector());
                break;
            case COUNTER:
                message = decryptCTR(ciphertext, config.privateKey);
                break;
        }

        if (MAC.verify(message, Constants.MAC_PRIVATE_KEY)) {
            return message.substring(0, message.length() - Constants.MAC_BLOCK_SIZE);
        } else {
            return "Invalid MAC!";
        }
    }

    // ==============================================================================================

    /**
     * Encrypts the given message using Electronic Codebook mode of DES algorithm
     * with the given private key.
     *
     * @param message a string of characters to encrypt.
     * @param key     a 64-bit private key.
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encryptECB(String message, long key) {
        StringBuilder ret = new StringBuilder();
        List<Long> blocks = Utils.splitTextIntoBlocks(message, 8);

        for (long block : blocks) {
            long cipherBlock = encrypt(block, key);
            ret.append(Utils.blockToHex(cipherBlock, 8));
        }

        return ret.toString();
    }

    /**
     * Decrypts the given ciphered message using Electronic Codebook mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param key        a 64-bit private key.
     *
     * @return the decrypted message.
     */
    public static String decryptECB(String ciphertext, long key) {
        StringBuilder ret = new StringBuilder();
        List<Long> cipherBlocks = Utils.splitHexIntoBlocks(ciphertext, 8);

        for (long cipherBlock : cipherBlocks) {
            long block = decrypt(cipherBlock, key);
            ret.append(Utils.blockToStr(block, 8));
        }

        return ret.toString().trim();
    }

    // ==============================================================================================

    /**
     * Encrypts the given message using Cipher Block Chaining mode of DES algorithm
     * with the given private key.
     *
     * @param message a string of characters to encrypt.
     * @param key     a 64-bit private key.
     * @param IV      a 64-bit initial vector.
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encryptCBC(String message, long key, long IV) {
        StringBuilder ret = new StringBuilder();
        List<Long> blocks = Utils.splitTextIntoBlocks(message, 8);

        long vec = IV;

        for (long block : blocks) {
            long cipherBlock = encrypt(block ^ vec, key);
            vec = cipherBlock;
            ret.append(Utils.blockToHex(cipherBlock, 8));
        }

        return ret.toString();
    }

    /**
     * Decrypts the given ciphered message using Cipher Block Chaining mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param key        a 64-bit private key.
     * @param IV         a 64-bit initial vector.
     *
     * @return the decrypted message.
     */
    public static String decryptCBC(String ciphertext, long key, long IV) {
        StringBuilder ret = new StringBuilder();
        List<Long> cipherBlocks = Utils.splitHexIntoBlocks(ciphertext, 8);

        long vec = IV;

        for (long cipherBlock : cipherBlocks) {
            long block = decrypt(cipherBlock, key) ^ vec;
            vec = cipherBlock;
            ret.append(Utils.blockToStr(block, 8));
        }

        return ret.toString().trim();
    }

    // ==============================================================================================

    /**
     * Encrypts the given message using Cipher Feedback mode of DES algorithm
     * with the given private key.
     *
     * @param message   a string of characters to encrypt.
     * @param key       a 64-bit private key.
     * @param IV        a 64-bit initial vector.
     * @param blockSize the block size (in bytes).
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encryptCFB(String message, long key, long IV, int blockSize) {
        StringBuilder ret = new StringBuilder();
        List<Long> blocks = Utils.splitTextIntoBlocks(message, blockSize);

        long vec = IV;

        for (long block : blocks) {
            long enc = encrypt(vec, key) >>> ((8 - blockSize) * 8);
            long cipherBlock = block ^ enc;
            ret.append(Utils.blockToHex(cipherBlock, blockSize));
            vec = (vec << (blockSize * 8)) | cipherBlock;
        }

        return ret.toString();
    }

    /**
     * Decrypts the given ciphered message using Cipher Feedback mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param key        a 64-bit private key.
     * @param IV         a 64-bit initial vector.
     * @param blockSize  the block size (in bytes).
     *
     * @return the decrypted message.
     */
    public static String decryptCFB(String ciphertext, long key, long IV, int blockSize) {
        StringBuilder ret = new StringBuilder();
        List<Long> cipherBlocks = Utils.splitHexIntoBlocks(ciphertext, blockSize);

        long vec = IV;

        for (long cipherBlock : cipherBlocks) {
            long enc = encrypt(vec, key) >>> ((8 - blockSize) * 8);
            long block = cipherBlock ^ enc;
            ret.append(Utils.blockToStr(block, blockSize));
            vec = (vec << (blockSize * 8)) | cipherBlock;
        }

        return ret.toString();
    }

    // ==============================================================================================

    /**
     * Encrypts the given message using Output Feedback mode of DES algorithm
     * with the given private key.
     *
     * @param message a string of characters to encrypt.
     * @param key     a 64-bit private key.
     * @param nonce   a 64-bit nonce used as initial vector in OFB mode.
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encryptOFB(String message, long key, long nonce) {
        StringBuilder ret = new StringBuilder();
        List<Long> blocks = Utils.splitTextIntoBlocks(message, 8);

        long vec = nonce;

        for (long block : blocks) {
            vec = encrypt(vec, key);
            ret.append(Utils.blockToHex(block ^ vec, 8));
        }

        return ret.toString();
    }

    /**
     * Decrypts the given ciphered message using Output Feedback mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param key        a 64-bit private key.
     * @param nonce      a 64-bit nonce used as initial vector in OFB mode.
     *
     * @return the decrypted message.
     */
    public static String decryptOFB(String ciphertext, long key, long nonce) {
        StringBuilder ret = new StringBuilder();
        List<Long> cipherBlocks = Utils.splitHexIntoBlocks(ciphertext, 8);

        long vec = nonce;

        for (long cipherBlock : cipherBlocks) {
            vec = encrypt(vec, key);
            ret.append(Utils.blockToStr(cipherBlock ^ vec, 8));
        }

        return ret.toString().trim();
    }

    // ==============================================================================================

    /**
     * Encrypts the given message using Counter mode of DES algorithm
     * with the given private key.
     *
     * @param message a string of characters to encrypt.
     * @param key     a 64-bit private key.
     *
     * @return the encrypted message in hexadecimal format.
     */
    public static String encryptCTR(String message, long key) {
        StringBuilder ret = new StringBuilder();
        List<Long> blocks = Utils.splitTextIntoBlocks(message, 8);

        for (int i = 0; i < blocks.size(); ++i) {
            long cipherBlock = blocks.get(i) ^ encrypt(i, key);
            ret.append(Utils.blockToHex(cipherBlock, 8));
        }

        return ret.toString();
    }

    /**
     * Decrypts the given ciphered message using Counter mode of DES algorithm
     * with the given private key.
     *
     * @param ciphertext a string of encrypted message in hexadecimal format to decrypt.
     * @param key        a 64-bit private key.
     *
     * @return the decrypted message.
     */
    public static String decryptCTR(String ciphertext, long key) {
        StringBuilder ret = new StringBuilder();
        List<Long> cipherBlocks = Utils.splitHexIntoBlocks(ciphertext, 8);

        for (int i = 0; i < cipherBlocks.size(); ++i) {
            long block = cipherBlocks.get(i) ^ encrypt(i, key);
            ret.append(Utils.blockToStr(block, 8));
        }

        return ret.toString().trim();
    }
}
