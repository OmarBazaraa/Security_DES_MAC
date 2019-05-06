package utils;

import des.Crypt;
import des.DESConfig;

import java.io.*;
import java.lang.module.Configuration;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static des.Crypt.*;
import static des.Crypt.encryptCTR;
import static des.Crypt.encryptOFB;
import static utils.Constants.DESMode.*;


public class Analyzer {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        analyze();
    }

    public static void analyze() throws IOException, NoSuchAlgorithmException {
        //
        // Different messages with different lengths.
        //
        List<String> messages = new ArrayList<>();

        BufferedReader reader = new BufferedReader(new FileReader("in/msgs.txt"));
        String line = reader.readLine();
        while (line != null) {
            messages.add(line.trim());
            line = reader.readLine();
        }
        reader.close();


        // Open text file to write statistics into.
        BufferedWriter outputWriter = null;
        outputWriter = new BufferedWriter(new FileWriter("out/DES_BLOCK_MODES.txt"));

        // Write messages lengths.
        for (String msg : messages) {
            outputWriter.write(Long.toString(msg.length()) + ' ');
        }
        outputWriter.newLine();

        //
        // Run Analysis.
        //
        for (String msg : messages) {
            for (Constants.DESMode mode : Constants.DESMode.values()) {
                if (mode == UNKNOWN) {
                    continue;
                }

                long s = System.currentTimeMillis();

                switch (mode) {
                    case ELECTRONIC_CODEBOOK:
                        encryptECB(msg, Constants.PRIVATE_KEY);
                        break;
                    case CIPHER_BLOCK_CHAINING:
                        encryptCBC(msg, Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR);
                        break;
                    case CIPHER_FEEDBACK:
                        encryptCFB(msg, Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR, 4);
                        break;
                    case OUTPUT_FEEDBACK:
                        encryptOFB(msg, Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR);
                        break;
                    case COUNTER:
                        encryptCTR(msg, Constants.PRIVATE_KEY);
                        break;
                }

                s = System.currentTimeMillis() - s;
                outputWriter.write(Long.toString(s) + ' ');
            }
            outputWriter.newLine();
        }

        outputWriter.flush();
        outputWriter.close();


        //
        // Cipher feedback graph points generation.
        //
        int[] blockSizes = new int[]{1, 2, 3, 4, 5, 6, 7, 8};
        outputWriter = new BufferedWriter(new FileWriter("out/CIPHER_FEEDBACK.txt"));

        for (int bs : blockSizes) {
            outputWriter.write(Long.toString(bs) + ' ');
        }
        outputWriter.newLine();

        for (int bs : blockSizes) {
            long s = System.currentTimeMillis();

            encryptCFB(messages.get(5), Constants.PRIVATE_KEY, Constants.INITIAL_VECTOR, bs);

            s = System.currentTimeMillis() - s;
            outputWriter.write(Long.toString(s) + ' ');
        }
        outputWriter.newLine();

        outputWriter.flush();
        outputWriter.close();
    }
}
