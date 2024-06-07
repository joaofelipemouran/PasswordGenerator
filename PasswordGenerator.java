import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class PasswordGenerator {

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=<>?{}|/;:";

    public static void main(String[] args) {
        for (int i = 0; i < 15; i++) {
            String password = generateRandomPassword(12);
            System.out.println("Generated Password: " + password);

            savePasswordToFile(password);

            String salt = generateSalt();
            System.out.println("Salt: " + salt);

            try {
                String hashedPassword = hashPassword(password, salt);
                System.out.println("Hashed Password: " + hashedPassword);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("Error hashing password: " + e.getMessage());
            }

            System.out.println();
        }
    }

    public static String generateRandomPassword(int length) {
        Random random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return password.toString();
    }

    public static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt.getBytes());
        byte[] hashedPassword = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedPassword);
    }

    public static void savePasswordToFile(String password) {
        try (FileWriter writer = new FileWriter("passwords.txt", true)) {
            writer.write(password + System.lineSeparator());
        } catch (IOException e) {
            System.err.println("Error writing password to file: " + e.getMessage());
        }
    }
}
