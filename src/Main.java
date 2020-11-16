/*
 * Date: 2020.09.22
 * Author: hktaskin
 */
package hkt.javacrypt;

public class Main {

    private static final String KEY_ALIAS = "Secret1";
    private static final String KEY_PASSWORD = "314159265359";
    private static final String KEYSTORE_FILE_PATH = "KEYSTORE_" + KEY_ALIAS + ".jceks";
    private static final String KEYSTORE_PASSWORD = "271828182846";

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        System.out.println("HKT.me");

        // Run once and store the KeyStore file.
        if (!new java.io.File(KEYSTORE_FILE_PATH).exists()) {
            HKTJavaCrypt.generateKeyStoreAndKey(KEYSTORE_FILE_PATH, KEYSTORE_PASSWORD, KEY_ALIAS, KEY_PASSWORD);
            System.out.println("Created new KeyStore.");
        }

        // Load the key store file and the key.
        HKTJavaCrypt s = new HKTJavaCrypt(KEYSTORE_FILE_PATH, KEYSTORE_PASSWORD, KEY_ALIAS, KEY_PASSWORD);

        System.out.println("KEYSTORE  : " + KEYSTORE_FILE_PATH);
        System.out.println("KEY ALIAS : " + KEY_ALIAS);
        System.out.println("RAW KEY   : " + s.showKey());
        System.out.println();

        // File encryption example 
        String plainfile = "plainfile.txt";
        String cipherfile = "cipherfile.txt.enc";
        String decryptedfile = "decrypted.txt";
        s.encryptFile(plainfile, cipherfile);
        s.decryptFile(cipherfile, decryptedfile);
        System.out.println("Completed file encryption and decryption");
        System.out.println();

        // String encryption example
        for (int i = 0; i < 10; i++) {
            System.out.println("Iteration : " + i);
            String p = "SomePlaintext";
            String c = s.encryptString(p);
            String d = s.decryptString(c);
            System.out.println("Plaintext : " + p);
            System.out.println("Ciphertext: " + c);
            System.out.println("Decrypted : " + d);
            System.out.println();
        }
    }
}
