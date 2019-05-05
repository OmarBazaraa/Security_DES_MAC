package client;

import des.Crypt;
import des.DESConfig;
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

    public static DESConfig config = new DESConfig();


    public static void main(String[] args) {
        try {
            init();
            chooseEncryptionConfig();
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
            String ciphertext = Crypt.encrypt(message, config);

            // Print plain and ciphered message
            System.out.println("     Plaintext: " + message);
            System.out.println("    Ciphertext: " + ciphertext);
            System.out.println();

            // Send ciphertext to server
            out.println(ciphertext);
        }
    }

    public static void chooseEncryptionConfig() {
        DESMode mode = DESMode.UNKNOWN;

        // Ask the user to choose encryption mode
        do {


            try {
                config = new DESConfig(mode);
                config.read(scanner);
                config.send(out);
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
            }
        } while (config.mode == DESMode.UNKNOWN);
    }
}
