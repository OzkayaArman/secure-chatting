import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Random;
import java.security.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLSocket;

//Implements the runnable class to instantiate instances of this class on a seperate thread
public class ClientHandler implements Runnable {

    // Keep track of each client in discussion group 1, allow broadcasting of
    // messages to all clients
    public static ArrayList<ClientHandler> clientHandler = new ArrayList<>();

    // Keep track of each client in discussion group 2, allow broadcasting of
    // messages to all clients
    public static ArrayList<ClientHandler> clientHandler2 = new ArrayList<>();

    // Keep track of each logged client
    public static ArrayList<String> loggedInUsers = new ArrayList<>();

    // 2FA mechanism variables
    protected static String groupJoinCode;

    protected static String groupJoinCode2;

    // Socket that is passed from the server class
    private SSLSocket sslSocket;

    // To read messages sent from a client
    private BufferedReader bufferedReader;

    // To send messages to another client
    private BufferedWriter bufferedWriter;

    // Represents each client
    private String clientUsername;

    // Client's IP
    private String clientIP;

    // Which group the client joins 1 or 2
    private int groupNumber;

    // Represents password regex pattern
    private String passWordCheckRegex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{10,}$";

    /**
     * Constructor for the ClientHandler class, accepts the socket from client
     */
    public ClientHandler(SSLSocket sslSocketIn, String clientIPin) {
        try {

            String request;
            sslSocket = sslSocketIn;

            // Wrapping the byte stream to a character stream
            // BufferedWriter is used to increase efficiency of the server
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
            request = bufferedReader.readLine();
            this.clientIP = clientIPin;

            // Redirect a client either to login or signup page depending on their input
            if (request.equals("SIGNUP")) {
                bufferedWriter.write("SERVER: Signing you up!");
                bufferedWriter.newLine();
                bufferedWriter.flush();
                handleSignup();
            } else if (request.equals("LOGIN")) {
                bufferedWriter.write("SERVER: Logging you in!");
                bufferedWriter.newLine();
                bufferedWriter.flush();
                handleLogin();
            } else {
                System.out.println("SERVER: ERROR AT LANDING PAGE");
            }
        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }
    }

    @Override
    // What is run on a seperate thread will be waiting for messages which is a
    // blocking operation
    public void run() {
        String messageFromClient;

        while (sslSocket.isConnected()) {
            try {
                // Read a message from the client, blocking operation
                messageFromClient = bufferedReader.readLine();
                broadcastMessage(messageFromClient, this.groupNumber);
            } catch (IOException e) {
                closeEverything(sslSocket, bufferedReader, bufferedWriter);
                break;
            }
        }

    }

    /**
     * Responsible for looping through the arraylist and send a message to each
     * client
     * 
     * @param messageToSend
     */
    public void broadcastMessage(String messageToSend, int groupNumberIn) {
        if (groupNumberIn == 1) {
            for (int i = 0; i < clientHandler.size(); i++) {
                try {

                    if (!clientHandler.get(i).clientUsername.equals(clientUsername)) {

                        clientHandler.get(i).bufferedWriter.write(this.clientUsername + ": " + messageToSend);
                        /*
                         * The buffered reader implemented in run() uses the new line character to
                         * recognize the end of a message. Therefore, we have to explicitly write the
                         * new line character
                         */
                        clientHandler.get(i).bufferedWriter.newLine();
                        // Buffer won't be send unless it is full
                        clientHandler.get(i).bufferedWriter.flush();
                    }
                } catch (IOException e) {
                    closeEverything(sslSocket, bufferedReader, bufferedWriter);
                }

            }
        } else {
            for (int i = 0; i < clientHandler2.size(); i++) {
                try {

                    if (!clientHandler2.get(i).clientUsername.equals(clientUsername)) {
                        if (messageToSend.contains("SERVER")) {
                            clientHandler2.get(i).bufferedWriter.write(messageToSend);
                        } else {
                            clientHandler2.get(i).bufferedWriter.write(this.clientUsername + ": " + messageToSend);
                        }
                        /*
                         * The buffered reader implemented in run() uses the new line character to
                         * recognize the end of a message. Therefore, we have to explicitly write the
                         * new line character
                         */
                        clientHandler2.get(i).bufferedWriter.newLine();
                        // Buffer won't be send unless it is full
                        clientHandler2.get(i).bufferedWriter.flush();
                    }
                } catch (IOException e) {
                    closeEverything(sslSocket, bufferedReader, bufferedWriter);
                }

            }
        }
    }

    public void handleLogin() {
        String username = null;
        String password = null;
        Boolean searching = true;
        Boolean signupRequest = false;
        int usernameTryLimit = 3;
        int passwordTryLimit = 3;

        try {
            bufferedWriter.write("SERVER: Please enter your username");
            bufferedWriter.newLine();
            bufferedWriter.flush();
            username = bufferedReader.readLine();
            while (loggedInUsers.contains(username)) {
                if (usernameTryLimit == 0) {
                    closeEverything(sslSocket, bufferedReader, bufferedWriter);
                }
                bufferedWriter.write("SERVER: This user is already logged in, try again");
                bufferedWriter.newLine();
                bufferedWriter.flush();
                usernameTryLimit--;
                username = bufferedReader.readLine();
            }
        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }

        // Record the username if the username is allowed, otherwise prompt the user
        // again.
        // The user has 3 tries allowed to realize a username
        try {

            while (searching) {
                BufferedReader br = new BufferedReader(new FileReader("database.txt"));
                String line;

                while ((line = br.readLine()) != null) {
                    String[] values = line.split(",");

                    // Username Check
                    if (values[0].equals(username)) {
                        searching = false;
                        bufferedWriter.write("SERVER: Please enter your password");
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                        password = bufferedReader.readLine();

                        // Username Validated, Password Check
                        while (!password.equals(values[1])) {
                            // Check That The User Hasn't Gone Over The Limit Of Trials
                            if (passwordTryLimit == 0) {
                                bufferedWriter.write(
                                        "SERVER: Too many unsuccessful login attempts , please try again later!");
                                bufferedWriter.newLine();
                                bufferedWriter.flush();
                                closeEverything(sslSocket, bufferedReader, bufferedWriter);
                            }

                            // Prompt User To Enter Their Password Again If Not True
                            bufferedWriter.write("SERVER: Wrong password, please try again!");
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                            passwordTryLimit--;
                            password = bufferedReader.readLine();
                        }
                        // Password Validated, Login Authenticated
                        bufferedWriter.write("SERVER: Login Successful");
                        this.clientUsername = username;
                        loggedInUsers.add(this.clientUsername);
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                        createOrJoinSelection();

                    }

                }

                // If there isn't a username match in our system
                if (searching) {

                    // Check That The User Hasn't Gone Over The Limit Of Trials
                    usernameTryLimit--;
                    if (usernameTryLimit == 0) {
                        bufferedWriter.write("SERVER: Too many unsuccessful login attempts , please try again later!");
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                        closeEverything(sslSocket, bufferedReader, bufferedWriter);
                    }

                    // Prompt User To Enter Their Username Again or Redirect Them to Signup Page
                    bufferedWriter.write(
                            "SERVER: This user doesn't exist, either check your details and try again or type \"SIGNUP\" to signup!");
                    bufferedWriter.newLine();
                    bufferedWriter.flush();
                    String reply = bufferedReader.readLine();

                    // Note user request to switch to signup page
                    if (reply.equals("SIGNUP")) {
                        signupRequest = true;
                        br.close();
                        break;
                    } else {
                        username = reply;
                    }
                }
                br.close();
            }
            // Call signup method if user wants to redirect to signup
            if (signupRequest) {
                handleSignup();
            }
        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }

    }

    public void createOrJoinSelection() throws IOException {

        // Present Option To Join A Discussion or Create A New One (Max Discussion
        // Group: 3)
        if (findEmptyDiscussionGroup() != null) {
            bufferedWriter.write(
                    "SERVER: To create a new discussion group type \"C\" or to join an existing group type \"E\" ");
            bufferedWriter.newLine();
            bufferedWriter.flush();
            String joinOrCreateRequest = bufferedReader.readLine();
            while (!joinOrCreateRequest.equals("C") && !joinOrCreateRequest.equals("E")) {
                bufferedWriter.write(
                        "SERVER: Wrong input,to create a new discussion group type \"C\" or to join an existing group type \"E\"");
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
            if (joinOrCreateRequest.equals("C")) {
                createAGroup();
            } else if (joinOrCreateRequest.equals("E")) {
                joinAGroup();
            }

        } else {
            bufferedWriter.write("SERVER: All discussion rooms full, you can only join an existing group");
            bufferedWriter.newLine();
            bufferedWriter.flush();
            joinAGroup();
        }

    }

    public void joinAGroup() throws IOException {
        int passcodeTryLimit = 3;
        bufferedWriter.write("SERVER: Joining a discussion group!");
        bufferedWriter.newLine();
        bufferedWriter.write("SERVER: Please enter the discussion group code to join a group");
        bufferedWriter.newLine();
        bufferedWriter.flush();
        String challengedCode = bufferedReader.readLine();

        while (!challengedCode.equals(groupJoinCode) && !challengedCode.equals(groupJoinCode2)) {
            passcodeTryLimit--;
            if (passcodeTryLimit == 0) {
                bufferedWriter.write("SERVER: Too many unsuccessful join attempts , please try again later!");
                closeEverything(sslSocket, bufferedReader, bufferedWriter);
            }
        }
        bufferedWriter.write("SERVER: Code correct! Waiting final approval from group admin!");
        char first = challengedCode.charAt(0);
        this.groupNumber = Character.getNumericValue(first);
        bufferedWriter.newLine();
        bufferedWriter.flush();

        if (getApproval(this.clientUsername, this.groupNumber)) {
            bufferedWriter.write("SERVER: Approved!");
            bufferedWriter.newLine();
            bufferedWriter.flush();
            if (this.groupNumber == 1) {
                clientHandler.add(this);
            } else {
                clientHandler2.add(this);
            }
            broadcastMessage("SERVER: " + this.clientUsername + " has entered the chat", this.groupNumber);
        }

    }

    public void createAGroup() throws IOException {
        bufferedWriter.write("SERVER: Creating a new discussion group!");
        bufferedWriter.newLine();
        bufferedWriter.flush();
        ArrayList<ClientHandler> clientHandlerSelected = findEmptyDiscussionGroup();

        if (clientHandlerSelected.equals(clientHandler)) {
            groupJoinCode = getRandomNumberString(1);
            clientHandler.add(this);
            bufferedWriter
                    .write("SERVER: Share this code with your friends to enable them to join your discussion forum: "
                            + groupJoinCode);
            bufferedWriter.newLine();
            bufferedWriter.flush();
            this.groupNumber = 1;
        }
        if (clientHandlerSelected.equals(clientHandler2)) {
            groupJoinCode2 = getRandomNumberString(2);
            clientHandler2.add(this);
            bufferedWriter
                    .write("SERVER: Share this code with your friends to enable them to join your discussion forum: "
                            + groupJoinCode2);
            bufferedWriter.newLine();
            bufferedWriter.flush();
            this.groupNumber = 2;
        }

    }

    public ArrayList<ClientHandler> findEmptyDiscussionGroup() {
        if (clientHandler.isEmpty()) {
            return clientHandler;
        }
        if (clientHandler2.isEmpty()) {
            return clientHandler2;
        }
        return null;
    }

    public boolean getApproval(String clientUsernameIn, int groupCodeIn) throws IOException {
        System.out.println("In get approval");
        if (groupCodeIn == 1) {
            clientHandler.get(0).bufferedWriter.write("SERVER:JOIN_AUTHENTICATED" + this.clientIP);
            clientHandler.get(0).bufferedWriter.newLine();
            clientHandler.get(0).bufferedWriter.flush();

        } else if (groupCodeIn == 2) {
            clientHandler2.get(0).bufferedWriter.write("SERVER:JOIN_AUTHENTICATED" + this.clientIP);
            clientHandler2.get(0).bufferedWriter.newLine();
            clientHandler2.get(0).bufferedWriter.flush();

        }
        return true;

    }

    // GAP reference:
    // https://stackoverflow.com/questions/51322750/generate-6-digit-random-number
    public static String getRandomNumberString(int firstDigit) {
        // It will generate 6 digit random Number.
        // from 0 to 999999 + 1
        Random rnd = new Random();
        int number = rnd.nextInt(100000);

        String fiveDigitString = String.format("%05d", number);

        // this will convert any number sequence into 6 character.
        return firstDigit + fiveDigitString;
    }

    // GAP reference for writing to
    // files:https://www.w3schools.com/java/java_files_create.asp
    private void handleSignup() {
        String username = null;
        String password = null;
        boolean usernameExists = true;

        try {

            bufferedWriter.write("SERVER: Please enter a username that is maximum 10 characters long");
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }

        // Record the username if the username is allowed, otherwise prompt the user
        // again.
        // The user has 3 tries allowed to realize a username
        try {
            // Will block here
            username = bufferedReader.readLine();
            while (usernameExists) {
                boolean found = false;
                BufferedReader br = new BufferedReader(new FileReader("database.txt"));
                String line;
                while ((line = br.readLine()) != null) {
                    String[] values = line.split(",");

                    // Username Check
                    if (values[0].equals(username)) {
                        found = true;
                        break;
                    }
                }

                br.close();
                if (found) {
                    bufferedWriter.write("SERVER: This username already exists, please pick another username");
                    bufferedWriter.newLine();
                    bufferedWriter.flush();
                    username = bufferedReader.readLine();
                } else {
                    usernameExists = false;
                }
            }

            while (username.length() > 10) {
                bufferedWriter.write("SERVER: False input, please enter a username that is maximum 10 characters long");
                bufferedWriter.newLine();
                bufferedWriter.flush();
                username = bufferedReader.readLine();
            }
            bufferedWriter.write(
                    "SERVER: Please determine a password that is at least 10 characters long. The password should include numerals, special characters, upper and lower capitals.");
            bufferedWriter.newLine();
            bufferedWriter.flush();

        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }

        try {
            // Will block here
            password = bufferedReader.readLine();
            Pattern pattern = Pattern.compile(passWordCheckRegex);
            Matcher matcher = pattern.matcher(password);
            boolean matchFound = matcher.find();
            while (!matchFound) {
                bufferedWriter.write("SERVER: False input, try again with the specified format");
                bufferedWriter.newLine();
                bufferedWriter.flush();
                password = bufferedReader.readLine();
                matcher = pattern.matcher(password);
                matchFound = matcher.find();
            }

            bufferedWriter.write("SERVER: Signup successful");
            bufferedWriter.newLine();
            bufferedWriter.flush();
            FileWriter myWriter = new FileWriter("database.txt", true);
            // Writing the username to the file, will block here
            myWriter.write(username + ",");
            // Writing the password to the file
            myWriter.write(password);
            myWriter.write("\n");
            myWriter.close();

        } catch (IOException e) {
            closeEverything(sslSocket, bufferedReader, bufferedWriter);
        }

    }

    public void removeClientHandler() {
        if (this.groupNumber == 1) {
            clientHandler.remove(this);
        } else {
            clientHandler2.remove(this);
        }

        broadcastMessage("SERVER: " + clientUsername + " has left the chat!", this.groupNumber);
    }

    public void closeEverything(SSLSocket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        removeClientHandler();
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

