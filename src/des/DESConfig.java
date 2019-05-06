package des;

import utils.Constants;
import utils.Constants.*;

import java.io.PrintWriter;
import java.util.Random;
import java.util.Scanner;


public class DESConfig {

    /**
     * The mode of operation of DES.
     */
    public DESMode mode = DESMode.UNKNOWN;

    /**
     * The private key used for DES encryption/decryption.
     */
    public long privateKey = Constants.PRIVATE_KEY;

    /**
     * The private seed used to generate initial vectors and nonce for various DES modes.
     */
    public long privateSeed = 54655152;

    /**
     * The block size used in DES Cipher Feedback Mode (CFB), measured in number of bytes.
     * Must be a number between [1, 8].
     */
    public int blockSize = 8;

    /**
     * Random number generator.
     */
    private Random random;

    /**
     * Constructs a new DES configuration object.
     */
    public DESConfig() {

    }

    /**
     * Constructs a new DES configuration object.
     *
     * @param mode the mode of operation of DES.
     */
    public DESConfig(DESMode mode) {
        this.mode = mode;
    }

    /**
     * Calculates a random initial vector.
     * Note: each time you call this function it returns a new random IV.
     *
     * @return a 64-bit initial vector.
     */
    public long getInitialVector() {
        if (random == null) {
            random = new Random(privateSeed);
        }
        return random.nextLong();
    }

    /**
     * Reads DES configuration from the user through given input stream.
     *
     * @param scanner the scanner to read from.
     */
    public void read(Scanner scanner) throws Exception {
        System.out.println("Please choose encryption mode:");
        System.out.println("    1. EBC - Electronic Codebook");
        System.out.println("    2. CBC - Cipher Block Chaining");
        System.out.println("    3. CFB - Cipher Feedback");
        System.out.println("    4. OFB - Output Feedback");
        System.out.println("    5. CTR - Counter");

        int opt = Integer.parseInt(scanner.nextLine()) - 1;

        if (opt < 0 || opt > 4) {
            throw new Exception("Invalid mode...\n");
        }

        mode = DESMode.values()[opt];

        System.out.println("Please enter the private key:");
        privateKey = Long.parseLong(scanner.nextLine());

        if (mode == DESMode.ELECTRONIC_CODEBOOK) {
            return;
        }

        System.out.println("Please enter the private random seed:");
        privateSeed = Long.parseLong(scanner.nextLine());

        if (mode != DESMode.CIPHER_FEEDBACK) {
            return;
        }

        System.out.println("Please enter the block size (in bytes) in range [1, 8]:");
        blockSize = Integer.parseInt(scanner.nextLine());

        if (blockSize < 1 || blockSize > 8) {
            mode = DESMode.UNKNOWN;
            throw new Exception("Invalid block size...\n");
        }
    }

    /**
     * Sends this configuration object using the given writer.
     *
     * @param out the writer object to send through.
     */
    public void send(PrintWriter out) {
        out.println(mode.ordinal());
        out.println(privateKey);
        out.println(privateSeed);
        out.println(blockSize);
    }

    /**
     * Receives the configuration object using the given reader.
     *
     * @param scanner the reader object to receive from.
     */
    public void receive(Scanner scanner) throws Exception {
        int opt = Integer.parseInt(scanner.nextLine());

        if (opt < 0 || opt > 4) {
            throw new Exception("Received invalid encryption mode!\n");
        }

        mode = DESMode.values()[opt];

        privateKey = Long.parseLong(scanner.nextLine());
        privateSeed = Long.parseLong(scanner.nextLine());
        blockSize = Integer.parseInt(scanner.nextLine());

        if (blockSize < 1 || blockSize > 8) {
            throw new Exception("Invalid block size!\n");
        }
    }
}
