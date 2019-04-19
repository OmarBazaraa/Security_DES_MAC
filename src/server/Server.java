package server;

import des.Crypt;
import utils.Constants;
import utils.Constants.*;

import java.io.*;
import java.net.*;
import java.util.Scanner;


public class Server {

    public static void main(String[] args) throws Exception {
        System.out.println("The server is running on port " + Constants.SERVER_PORT + "...\n");

        int clientNumber = 0;

        try (ServerSocket listener = new ServerSocket(Constants.SERVER_PORT)) {
            while (true) {
                try {
                    ServerThread thread = new ServerThread(listener.accept(), clientNumber++);
                    thread.start();
                } catch (Exception ex) {
                    System.err.println(ex.getMessage());
                }
            }
        }
    }

    private static class ServerThread extends Thread {

        private Socket socket;
        private int clientNumber;

        private Scanner in;
        private PrintWriter out;

        public static DESMode mode = DESMode.UNKNOWN;


        public ServerThread(Socket socket, int clientNumber) throws IOException {
            // Assign member variables
            this.socket = socket;
            this.clientNumber = clientNumber;

            // Prepare input and output streams with the client
            this.in = new Scanner(new InputStreamReader(socket.getInputStream()));
            this.out = new PrintWriter(socket.getOutputStream(), true);

            // Send a welcome message to the client.
            out.println("Hello, you are client #" + clientNumber + ".\n");
        }

        public void run() {
            try {
                receiveEncryptionMode();
                communicate();
            } catch (Exception ex) {
                System.out.println("Error handling client #" + clientNumber + ": " + ex.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException ex) {
                    System.out.println("Could not close the socket with client #" + clientNumber + "!");
                }

                System.out.println("Connection with client #" + clientNumber + " is closed.\n");
            }
        }

        private void communicate() throws Exception {
            while (in.hasNext()) {
                // Receive and decrypt the message from the client
                String ciphertext = in.nextLine();
                String message = Crypt.decrypt(ciphertext, Constants.PRIVATE_KEY, mode);

                // Print plain and ciphered message
                System.out.println("Received from Client #" + clientNumber + ":");
                System.out.println("    Ciphertext: " + ciphertext);
                System.out.println("     Plaintext: " + message);
                System.out.println();
            }
        }

        private void receiveEncryptionMode() throws Exception {
            try {
                int opt = Integer.parseInt(in.nextLine());

                if (opt < 0 || opt > 4) {
                    throw new Exception();
                }

                mode = DESMode.values()[opt];
            } catch (Exception ex) {
                throw new Exception("Received invalid encryption mode!");
            }

            switch (mode) {
                case ELECTRONIC_CODEBOOK:
                    System.out.println("Connected with client #" + clientNumber + " in ECB mode.\n");
                    break;
                case CIPHER_BLOCK_CHAINING:
                    System.out.println("Connected with client #" + clientNumber + " in CBC mode.\n");
                    break;
                case CIPHER_FEEDBACK:
                    System.out.println("Connected with client #" + clientNumber + " in CFB mode.\n");
                    break;
                case OUTPUT_FEEDBACK:
                    System.out.println("Connected with client #" + clientNumber + " in OFB mode.\n");
                    break;
                case COUNTER:
                    System.out.println("Connected with client #" + clientNumber + " in CTR mode.\n");
                    break;
            }
        }
    }
}