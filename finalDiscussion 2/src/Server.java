import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This is a TCP Server. It has a built-in firewall to increase ressillience
 * against cyber attacks
 */

public class Server {

    // Using TLS version 1.3
    private static final String[] protocols = new String[] { "TLSv1.3" };

    // Ephemeral Diffie-Hellman algorithm will be used for the key exchange process
    private static final String[] cipher_suites = new String[] { "TLS_AES_128_GCM_SHA256" };

    // Respnsible for listening to incoming connections
    private SSLServerSocket serverSocket = null;
    private static final int port = 1234;

    // Below variables are used to enable firewall logics
    private final int maxRequests = 10;
    private HashMap<String, Integer> requestCounts = new HashMap<>();
    long currentTime = System.currentTimeMillis();
    private HashMap<String, Long> lastRequestTime = new HashMap<>();

    /**
     * Constructur for the Server class
     */
    public Server(SSLServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    // GAP:https://www.baeldung.com/java-initialize-hashset
    /**
     * List of malicious IP's that the firewall bill Intelligence obtained from
     * https://www.maxmind.com/en/high-risk-ip-sample-list
     */
    private static final Set<String> ALLOWED_IP_ADDRESSES = new HashSet<>(Arrays.asList("103.251.167.20",
            "108.77.13.78", "109.70.100.6", "109.70.100.67", "109.70.100.70", "109.70.100.71", "136.34.129.71",
            "185.220.101.24", "185.243.218.202", "192.42.116.173", "192.42.116.179", "192.42.116.184", "192.42.116.185",
            "192.42.116.187", "192.42.116.188", "192.42.116.192", "192.42.116.198", "192.42.116.200", "198.251.88.70",
            "199.172.47.13", "23.137.251.61", "2a0b:f4c2:1::1", "38.97.116.244", "47.185.81.143", "47.196.190.73",
            "50.203.7.250", "50.225.7.154", "50.232.69.26", "68.185.212.57", "69.162.231.243", "69.245.177.224",
            "70.23.242.94", "71.207.162.163", "71.230.25.169", "72.204.184.234", "76.8.187.168", "98.53.226.84",
            "99.9.223.72"));

    public static void main(String[] args) {

        /**
         * Initializing the ServerSocket to get the server to start listening on the
         * port specified above.
         */
        try {
            System.out.println("Server Started");

            // Configure key store that stores crypto keys to enable correct TLS
            // implementation
            System.setProperty("javax.net.ssl.keyStore", "myKeyStore.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "<TOGGrepublicANADOLUatak>");

            // System.setProperty("javax.net.debug","all");
            // Create the server socket
            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);

            // Specify TLS protocols and cipher_suites
            serverSocket.setEnabledProtocols(protocols);
            serverSocket.setEnabledCipherSuites(cipher_suites);

            // Creates and runs the server indefinitely.
            Server server = new Server(serverSocket);
            server.startServer();

        } catch (IOException e) {
            System.err.println("IO Exception: " + e.getMessage());

        }

    }

    /**
     * Method responsible for keeping the server running Also implements a fire wall
     * that employs: IP blacklisting, rate limiting, and connection blacklisting
     * 
     * @return void
     */
    public void startServer() {
        try {

            // Runs the server indefinitely
            while (!serverSocket.isClosed()) {

                // A blocking method that waits for a client, returns a socket object used to
                // communicate with the client
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept();

                // Will be used for rate limiting countermeasure below
                currentTime = System.currentTimeMillis();

                /* Firewall for the Server */
                String clientIP = sslSocket.getInetAddress().getHostAddress();
                requestCounts.putIfAbsent(clientIP, 0);

                /* Firewall logic #1 */
                // Check the time difference from the last connection attempt, if the last
                // connection attempt was made < 0.5 seconds ago
                // Treat that socket as a potentially dangerous attack vector and terminate that
                // socket;
                // Defend against DDOS
                if (lastRequestTime.containsKey(clientIP) && (currentTime - lastRequestTime.get(clientIP) < 500)) {
                    System.out.println("FIREWALL WARNING: Rate limiting in place " + clientIP + " rejected.");
                    sslSocket.close();
                    continue;
                }
                /* Firewall logic #2 */
                // Check the ip address of the socket isn't a known malicious ip address
                // Defend against DDOS
                if (ALLOWED_IP_ADDRESSES.contains(clientIP)) {
                    System.out.println("FIREWALL WARNING: Connection from " + clientIP + " rejected.");
                    sslSocket.close();
                    continue;
                }

                /* Firewall logic #3 */
                // Check that a single client isn't launching too many sockets
                // Defend against DOS attacks
                if (requestCounts.get(clientIP) > maxRequests) {
                    System.out.println("FIREWALL WARNING: Possible DOS attack from " + clientIP
                            + ". Protection mechanism activated");
                    sslSocket.close();
                    continue;
                }

                System.out.println("A new client has connected from " + clientIP);

                lastRequestTime.put(clientIP, currentTime);
                requestCounts.put(clientIP, requestCounts.getOrDefault(clientIP, 0) + 1);
                // Each clientHandler object is responsible for communicating with one specific
                // client.
                ClientHandler clientHandler = new ClientHandler(sslSocket, clientIP);
                // ClientHandler implements runnable, we need to create a new thread and pass
                // the clienthandler to this thread
                Thread thread = new Thread(clientHandler);
                // Runs the client handler
                thread.start();
                System.out.println("Thread Started");
            }

        } catch (IOException E) {
            System.out.println("An error occured at connection establishment, client might have been disconnected");
            closeServerSocket();
        }

    }

    /**
     * Graceful termination
     */
    public void closeServerSocket() {
        /**
         * Closing the streams.
         */
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }

        } catch (IOException e) {
            System.out.println("An error happened while trying to close the streams");
            e.printStackTrace();
        }
    }

}

