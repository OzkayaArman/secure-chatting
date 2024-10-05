import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * This is a TCP client
 */

public class Client {
  // Using TLS version 1.3
  private static final String[] protocols = new String[] { "TLSv1.3" };
  // Ephemeral Diffie-Hellman algorithm will be used for the key exchange process
  private static final String[] cipher_suites = new String[] { "TLS_AES_128_GCM_SHA256" };

  private SSLSocket clientSocket = null;
  private BufferedReader bufferedReader = null;
  private BufferedWriter bufferedWriter = null;
  private String loginOrSignup = null;
  private boolean serverMessage = false;
  private SecretKey secretKey;
  private final int KEY_SIZE = 128;
  private Cipher encryptionCipher;
  private final int T_LEN = 128;

  public Client(SSLSocket clientSocketIn, String request) {
    try {

      clientSocket = clientSocketIn;
      this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
      this.bufferedReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
      this.loginOrSignup = request;

    } catch (IOException e) {
      closeEverything(clientSocket, bufferedReader, bufferedWriter);
    }
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    System.setProperty("javax.net.ssl.trustStore", "myTrustStore.jts");
    System.setProperty("javax.net.ssl.trustStorePassword", "<TOGGrepublicANADOLUatak>");
    System.setProperty("javax.net.ssl.keyStore", "myKeyStore.jks");
    System.setProperty("javax.net.ssl.keyStorePassword", "<TOGGrepublicANADOLUatak>");
    // System.setProperty("javax.net.debug","all");
    // System. out. println("Current JVM version - " + System.
    // getProperty("java.version"));
    Scanner scanner = new Scanner(System.in);
    System.out.println("Welcome to chatSec, please type \"LOGIN\" to login or \"SIGNUP\" to signup");
    String request = scanner.nextLine();

    // Avoid high server load by pushing the inital request handling to client side.
    // Part of DOS attack avoidance strategy
    while (!request.equals("LOGIN") && !request.equals("SIGNUP")) {
      System.out.println(request + " is an invalid input, please type \"LOGIN\" to login or \"SIGNUP\" to signup");
      request = scanner.nextLine();
    }
    SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    SSLSocket clientSocket = (SSLSocket) factory.createSocket("localhost", 1234);
    clientSocket.setEnabledProtocols(protocols);
    clientSocket.setEnabledCipherSuites(cipher_suites);
    clientSocket.startHandshake();

    Client client = new Client(clientSocket, request);
    client.secretKey = client.generateKey();
    client.listenForMessage();
    client.sendMessage();

  }

  /*
   * GAP: The generate key, encrypt and decrypt functions' implementation were
   * taken from this tutorial
   * https://www.baeldung.com/java-aes-encryption-decryption
   */

  /**
   * Generates the keys that will be used for encrypting messages
   * 
   * @return
   * @throws NoSuchAlgorithmException
   */
  public SecretKey generateKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(KEY_SIZE);
    SecretKey createdSecretKey = keyGenerator.generateKey();
    System.out.println(createdSecretKey);
    return createdSecretKey;
  }

  /**
   * Encrpyts messages with a given key and message
   * 
   * @param message
   * @param secretKey
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InvalidAlgorithmParameterException
   */
  public String encrypt(String message, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    byte[] iv = new byte[16]; // AES block size
    new SecureRandom().nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    byte[] encrypted = cipher.doFinal(message.getBytes());
    byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
    System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length);
    System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length);
    return Base64.getEncoder().encodeToString(encryptedIVAndText);
  }

  /**
   * Decrypts messages with a given message and key
   * 
   * @param cipherText
   * @param secretKey
   * @return
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public String decrypt(String cipherText, SecretKey secretKey)
      throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
      IllegalBlockSizeException, BadPaddingException {
    byte[] encryptedIVAndText = Base64.getDecoder().decode(cipherText);
    IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOfRange(encryptedIVAndText, 0, 16));
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    byte[] decrypted = cipher.doFinal(Arrays.copyOfRange(encryptedIVAndText, 16, encryptedIVAndText.length));
    return new String(decrypted);
  }

  /**
   * This function helps client bypass the server and directly connect to the
   * other client in order to distribute the key. The key is distributed over a
   * TLS (tunneling) in order to prevent attackers from gaining access to the key.
   * The administrator of the discussion group generates and distributes this key.
   * The key is symettric
   * 
   * @param input
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public void sendKey(String input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
      IllegalBlockSizeException, BadPaddingException {
    String prefix = "SERVER:JOIN_AUTHENTICATED";
    String ip = null;
    if (input.startsWith(prefix)) {
      ip = input.substring(prefix.length());
    }
    System.out.println(ip);
    try {
      SSLSocketFactory factory2 = (SSLSocketFactory) SSLSocketFactory.getDefault();
      SSLSocket keySendingSocket = (SSLSocket) factory2.createSocket(ip, 2345);
      BufferedWriter keySender = new BufferedWriter(new OutputStreamWriter(keySendingSocket.getOutputStream()));
      keySendingSocket.setEnabledProtocols(protocols);
      keySendingSocket.setEnabledCipherSuites(cipher_suites);
      keySendingSocket.startHandshake();
      String keyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());
      keySender.write(keyString);
      keySender.newLine();
      keySender.flush();
      System.out.println("Key Sharing Initiated!");
      encrypt("message", secretKey);
      serverMessage = false;
    } catch (IOException e) {
      System.out.println("Unable to connect to server: " + e.getMessage());
    } catch (InvalidAlgorithmParameterException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }

  /**
   * This function receives the key from the chat administrator and saves it in
   * order to be able to decrypt messages in the discussion group.
   * GAP reference: this method logic is taken from a tutorial here https://www.youtube.com/watch?v=gLfuZrrfKes&t=1441s
   * @throws IOException
   */
  public void receiveKey() throws IOException {
    new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
          SSLServerSocket clientServerSocket = (SSLServerSocket) factory.createServerSocket(2345);
          clientServerSocket.setEnabledProtocols(protocols);
          clientServerSocket.setEnabledCipherSuites(cipher_suites);
          // Runs the server indefinitely
          while (!clientServerSocket.isClosed()) {
            try {
              SSLSocket sslSocket = (SSLSocket) clientServerSocket.accept();
              BufferedReader keyReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
              String keyAsStringIn = keyReader.readLine();
              byte[] decodedKey = Base64.getDecoder().decode(keyAsStringIn);
              secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
              System.out.println(secretKey);
              System.out.println("Key Sharing Complete!");
              encrypt("message", secretKey);
              serverMessage = false;
              sslSocket.close();
              clientServerSocket.close();
            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {

              e.printStackTrace();
            }
          }
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  /**
   * This method is responsible for sending messsages to client handler It has
   * logic to encrypt messages if the intended message is for another client If
   * this client is talking to the server, the messages aren't encrypted again,
   * however it is still secure as it uses the tls mechanism This is because the
   * server is a 0 knowledge server which doesn't have keys to decrypt messages
   * 
   * 
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   */
  public void sendMessage() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
      IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    try {
      bufferedWriter.write(loginOrSignup);
      bufferedWriter.newLine();
      bufferedWriter.flush();
      Scanner scanner = new Scanner(System.in);
      while (clientSocket.isConnected()) {
        String messageToSend = scanner.nextLine();
        if (messageToSend.equals("E")) {
          receiveKey();
        }
        if (!serverMessage) {
          String encryptedText = encrypt(messageToSend, secretKey);
          bufferedWriter.write(encryptedText);
          bufferedWriter.newLine();
          bufferedWriter.flush();
        } else {
          bufferedWriter.write(messageToSend);
          bufferedWriter.newLine();
          bufferedWriter.flush();
        }
      }
      scanner.close();
    } catch (IOException e) {
      closeEverything(clientSocket, bufferedReader, bufferedWriter);
      // TODO Auto-generated catch block
      e.printStackTrace();

    }

  }

  /**
   * This method is listening for messages from the server. Listening messages is
   * a blocking operation, therefore, it should be implemented on a seperate
   * thread. It has logic to decrypt messages if the message is coming from
   * another client which will be encrypted
   */
  public void listenForMessage() {
    new Thread(new Runnable() {
      @Override
      public void run() {
        String msgFromGroupChat;
        while (clientSocket.isConnected()) {
          try {
            msgFromGroupChat = bufferedReader.readLine();

            if (!msgFromGroupChat.contains("SERVER:")) {
              String[] parts = msgFromGroupChat.split(": ", 2);
              String username = parts[0];
              String message = parts[1];

              if (parts.length == 2) {
                username = parts[0];
                message = parts[1];
              }

        
              String decryptedText = decrypt(message, secretKey);
      
              System.out.println(decryptedText);
              serverMessage = false;
            } else if (msgFromGroupChat.contains("SERVER:JOIN_AUTHENTICATED")) {
              sendKey(msgFromGroupChat);
              serverMessage = true;
            } else if (msgFromGroupChat.contains("has entered the chat")) {
              System.out.println(msgFromGroupChat);
              serverMessage = false;
            } else {
              System.out.println(msgFromGroupChat);
              serverMessage = true;
            }
          } catch (IOException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
              | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            closeEverything(clientSocket, bufferedReader, bufferedWriter);

          }
        }
      }
    }).start();
  }

  /**
   * For graceful termination
   * 
   * @param clientSocket
   * @param bufferedReader
   * @param bufferedWriter
   */
  public void closeEverything(SSLSocket clientSocket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
    try {
      if (bufferedReader != null) {
        bufferedReader.close();
      }
      if (bufferedWriter != null) {
        bufferedWriter.close();
      }
      if (clientSocket != null) {
        clientSocket.close();
      }

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
