package client;

import des.Crypt;
import utils.Constants;
import utils.Constants.*;

import java.io.*;
import java.net.*;
import java.util.Scanner;


public class Client {

    public static Socket socket;

    public static Scanner scanner;

    public static Scanner in;
    public static PrintWriter out;

    public static DESMode mode = DESMode.UNKNOWN;


    public static void main(String[] args) {
        try {
            init();
            chooseEncryptionMode();
            communicate();
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException ex) {
                System.out.println("Could not close the socket with the server!");
            }

            System.out.println("Connection with the server is closed");
        }
    }

    public static void init() throws Exception {
        // Connect to server
        socket = new Socket(Constants.SERVER_HOST, Constants.SERVER_PORT);

        // Prepare input scanner from the console
        scanner = new Scanner(System.in);

        // Prepare input and output streams with the server
        in = new Scanner(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);

        // Consume the initial welcoming messages from the server
        System.out.println(in.nextLine());
        System.out.println();
    }

    public static void communicate() throws Exception {
        while (true) {
            // Get message from user to send
            System.out.print("Enter a message to send (Q to quit): ");
            String message = scanner.nextLine();

            // Check terminating condition
            if (message.equals("q") || message.equals("Q")) {
                break;
            }

            // Encrypt the message
            String ciphertext = Crypt.encrypt(message, Constants.PRIVATE_KEY, mode);

            // Print plain and ciphered message
            System.out.println("     Plaintext: " + message);
            System.out.println("    Ciphertext: " + ciphertext);
            System.out.println();

            // Send ciphertext to server
            out.println(ciphertext);
        }
    }

    public static void chooseEncryptionMode() {
        mode = DESMode.UNKNOWN;

        // Ask the user to choose encryption mode
        do {
            System.out.println("Please choose encryption mode:");
            System.out.println("    1. EBC - Electronic Codebook");
            System.out.println("    2. CBC - Cipher Block Chaining");
            System.out.println("    3. CFB - Cipher Feedback");
            System.out.println("    4. OFB - Output Feedback");
            System.out.println("    5. CTR - Counter");

            try {
                int opt = Integer.parseInt(scanner.nextLine()) - 1;

                if (opt < 0 || opt > 4) {
                    throw new Exception();
                }

                mode = DESMode.values()[opt];
                out.println(opt);
            } catch (Exception ex) {
                System.out.println("Invalid encryption mode...\n");
            }
        } while (mode == DESMode.UNKNOWN);
    }
}
