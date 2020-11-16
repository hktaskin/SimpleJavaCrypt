/*
 * Date: 2020.09.22
 * Author: hktaskin
 */
package hkt.javacrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class HKTJavaCrypt {

    private static final SecureRandom SEC_RANDOM = new SecureRandom();
    private Key _key;
    private String _keyAlias;

    public HKTJavaCrypt(String keyStoreFilePath, String keyStorePassword, String keyAlias, String keyPassword) throws Exception {
        _loadKeyStore(new FileInputStream(keyStoreFilePath), keyStorePassword, keyAlias, keyPassword);
    }

    private void _loadKeyStore(FileInputStream keyStoreFileStream, String keyStorePassword, String keyAlias, String keyPassword) throws Exception {
        // Create keystore object and load file stream
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(keyStoreFileStream, keyStorePassword.toCharArray());

        _key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
        _keyAlias = keyAlias;
    }

    public static void generateKeyStoreAndKey(String keyStoreFilePath, String keyStorePassword, String keyAlias, String keyPassword) throws Exception {

        // Create keystore object
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        // We have an empty keystore
        keyStore.load(null, null);

        // Create keygen
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, SEC_RANDOM);

        // Generate the key
        Key key = keyGen.generateKey();

        /*
        alias - the alias name
        key - the key to be associated with the alias
        password - the password to protect the key
        chain - the certificate chain for the corresponding public key (only required if the given key is of type java.security.PrivateKey).
         */
        // Store the key in the keystore
        keyStore.setKeyEntry(keyAlias, key, keyPassword.toCharArray(), null);

        /*
        stream - the output stream to which this keystore is written.
        password - the password to generate the keystore integrity check
         */
        // Save keystore to the file
        keyStore.store(new java.io.FileOutputStream(keyStoreFilePath), keyStorePassword.toCharArray());

        // Set file permissions to 400
        File f = new File(keyStoreFilePath);
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        Files.setPosixFilePermissions(Paths.get(f.getPath()), perms);
    }

    public String encryptString(String plaintext) throws Exception {
        byte[] iv = new byte[16];
        SEC_RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, _key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        return _keyAlias + "." + toHexString(cipher.getIV()) + "." + toHexString(ciphertext);
    }

    public String decryptString(String ciphertext) throws Exception {

        String[] cipherdata = ciphertext.trim().split("\\.");
        if (cipherdata[0].compareTo(_keyAlias) != 0) {
            throw new Exception("Key Alias does not match.");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] recovered_iv = toByteArray(cipherdata[1]);
        cipher.init(Cipher.DECRYPT_MODE, _key, new GCMParameterSpec(128, recovered_iv));
        byte[] plaintext = cipher.doFinal(toByteArray(cipherdata[2]));
        return new String(plaintext);
    }

    private void _processFile(boolean encrypting, String inFile, String outFile) throws Exception {

        try (FileInputStream in = new FileInputStream(inFile);
                FileOutputStream out = new FileOutputStream(outFile)) {
            byte[] iv = new byte[16];
            if (encrypting) {
                SEC_RANDOM.nextBytes(iv);
                // Write IV first without encryption
                out.write(iv);
            } else {
                // We are decrypting, read IV from the file.
                in.read(iv);
            }
            // Init the Cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, _key, new GCMParameterSpec(128, iv));
            // Process the file
            byte[] inbuf = new byte[1024];
            int len;
            while ((len = in.read(inbuf)) != -1) {
                byte[] outbuf = cipher.update(inbuf, 0, len);
                if (outbuf != null) {
                    out.write(outbuf);
                }
            }
            byte[] outbuf = cipher.doFinal();
            if (outbuf != null) {
                out.write(outbuf);
            }
        }
    }

    public void encryptFile(String inFile, String outFile) throws Exception {
        _processFile(true, inFile, outFile);
    }

    public void decryptFile(String inFile, String outFile) throws Exception {
        _processFile(false, inFile, outFile);
    }

    public String showKey() {
        return toHexString(_key.getEncoded());
    }

    private String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    private byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
}
