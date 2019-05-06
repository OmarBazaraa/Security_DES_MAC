package utils;

import des.Crypt;
import des.DESConfig;

import java.io.*;
import java.lang.module.Configuration;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

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

            // read next line
            line = reader.readLine();
        }
        reader.close();

        BufferedWriter outputWriter = null;
        outputWriter = new BufferedWriter(new FileWriter("out/DES_BLOCK_MODES.txt"));

        //
        // Run Analysis.
        //
        for (String msg : messages)
            outputWriter.write(Long.toString(msg.length()) + ' ');
        outputWriter.newLine();

        DESConfig config = new DESConfig();

        for (String msg : messages) {
            for (Constants.DESMode mode : Constants.DESMode.values()) {
                if (mode == UNKNOWN)
                    continue;

                config.mode = mode;

                long s = System.currentTimeMillis();

                Crypt.encrypt(msg, config);

                s = System.currentTimeMillis() - s;
                outputWriter.write(Long.toString(s) + ' ');
            }
            outputWriter.newLine();
        }

        outputWriter.flush();
        outputWriter.close();
    }
}
