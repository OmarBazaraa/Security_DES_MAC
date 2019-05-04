package utils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import static des.Crypt.*;
import static des.Crypt.encryptCTR;
import static des.Crypt.encryptOFB;
import static utils.Constants.DESMode.*;


public class Analyzer {

    public static void main(String[] args) throws IOException {
        analyze();
    }

    public static void analyze() throws IOException {
        //
        // Different messages with different lengths.
        //
        List<String> messages = new ArrayList<>();
        List<Integer> messagesLengths = new ArrayList<>();

        BufferedReader reader = new BufferedReader(new FileReader("in/msgs.txt"));
        String line = reader.readLine();
        while (line != null) {
            messages.add(line.trim());

            // read next line
            line = reader.readLine();
        }
        reader.close();

        BufferedWriter outputWriter = null;
        outputWriter = new BufferedWriter(new FileWriter("out/vals.txt"));

        //
        // Get Messages lengths.
        //
        for (String msg : messages) {
            messagesLengths.add(messages.get(0).length());
            Integer s = messages.get(0).length();
            outputWriter.write(s.toString() + ' ');
        }
        outputWriter.newLine();

        //
        // Run Analysis.
        //
        int[] blockSizes = new int[]{1, 8, 16, 32, 64, 128, 512};

        List<Long> ecb = new ArrayList<>();
        List<Long> cbc = new ArrayList<>();
        List<Long> cfb = new ArrayList<>();
        List<Long> ofb = new ArrayList<>();
        List<Long> cnt = new ArrayList<>();

        for (int bs : blockSizes) {
            for (Constants.DESMode mode : Constants.DESMode.values()) {
                if (mode == UNKNOWN) {
                    continue;
                }

                Long s = System.currentTimeMillis();

                if (mode == ELECTRONIC_CODEBOOK) {
                    encryptECB(messages.get(0), Constants.PRIVATE_KEY);
                    s = System.currentTimeMillis() - s;
                    ecb.add(s);
                } else if (mode == CIPHER_BLOCK_CHAINING) {
                    encryptCBC(messages.get(0), Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR);
                    s = System.currentTimeMillis() - s;
                    cbc.add(s);
                } else if (mode == CIPHER_FEEDBACK) {
                    encryptCFB(messages.get(0), Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR, bs);
                    s = System.currentTimeMillis() - s;
                    cfb.add(s);
                } else if (mode == OUTPUT_FEEDBACK) {
                    encryptOFB(messages.get(0), Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR);
                    s = System.currentTimeMillis() - s;
                    ofb.add(s);
                } else if (mode == COUNTER) {
                    encryptCTR(messages.get(0), Constants.PRIVATE_KEY);
                    s = System.currentTimeMillis() - s;
                    cnt.add(s);
                }

                outputWriter.write(s.toString() + ' ');
            }
            outputWriter.newLine();
        }

        outputWriter.flush();
        outputWriter.close();
    }
}
