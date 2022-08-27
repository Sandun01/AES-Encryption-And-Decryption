import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AES_Encryption {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;

    // This method will create the encryption keys.
    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }

    // custom - generate key
    public void generate_custom_key(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        key = secret;
    }

    /*
     * Create an encrypt method and pass in the data that is to be encrypted as
     * parameter.
     * Guess the byte array from this message create an encryption cipher and get
     * its instance.
     * Initialize the encryption cipher with the init method and pass the generated
     * key
     * Finally, we create a method encryptionCipher that will return a byte array of
     * the encrypted data.
     */
    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    /*
     * Create the decrypt method and pass in the encrypted data as parameters.( need
     * to convert our data to a byte array again and decode it since we encoded it
     * during encryption)
     * 
     * Then create a decryption cipher and get its instance of the AES
     * algorithm.then initialize the decryption cipher with the init method using
     * the decrypt mode. This takes the same key that was used in encryption as
     * parameters.
     * 
     * Afterwards, we can get our bytes array from the decrypted bytes from the
     * decryptionCipher.doFinal() method, and return the new string of the decrypted
     * bytes
     */

    public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    /*
     * 
     * To convert our data into a string, we will use a private method called encode
     * and decode that will take in the bytes array and returns to BASE64. We will
     * use the code below for both encoding and decoding:
     * 
     */
    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    /*
     * In main method, we will put everything in the try…catch block. In this
     * method, we will initialize our algorithm, initialize the variable that will
     * be used to hold the encrypted message and the decrypted data, and pass in the
     * data to be decrypted.
     */

    public static void main(String[] args) {
        try {
            Scanner scan = new Scanner(System.in);

            // get Key
            System.out.print("Please enter the encryption key:");
            String encryption_key = scan.nextLine();
            // System.out.println(encryption_key);

            // get string
            System.out.print("Please enter the value to encrypt:");
            String encryption_string = scan.nextLine();
            // System.out.println(encryption_string);

            // press to encrypt
            System.out.println("Press \"ENTER\" to continue encryption...");
            Scanner scanner_enter1 = new Scanner(System.in);
            scanner_enter1.nextLine();

            // encryption
            AES_Encryption aes_encryption = new AES_Encryption();
            aes_encryption.generate_custom_key(encryption_key, "2022");
            String encryptedData = aes_encryption.encrypt(encryption_string);

            // display encrypted string
            System.out.println("Encrypted Data : " + encryptedData);

            // Pass data and display
            Display_Data pass_data = new Display_Data(encryptedData);
            pass_data.displayData();

            // Get key to decrypt data
            String decryption_key = "";
            while (true) {
                System.out.print("Please enter the decryption key:");
                decryption_key = scan.nextLine();
                if (decryption_key.equals(encryption_key)) {
                    break;
                } else {
                    System.out.println("Please try again!");
                }
            }

            // press to encrypt
            System.out.println("Press \"ENTER\" to decrypt data...");
            Scanner scanner_enter2 = new Scanner(System.in);
            scanner_enter2.nextLine();

            // decrypt
            String decryptedData = aes_encryption.decrypt(encryptedData);

            // display decrypted data
            System.out.println("Original Message: " + decryptedData);

        } catch (Exception exception) {
            System.out.println("Exception: " + exception);
        }
    }

}