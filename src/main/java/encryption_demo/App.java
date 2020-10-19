package encryption_demo;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class App {
    public static void main(String[] args) throws Exception {
        String jsonToEncrypt = "{\"message\": \"ok\", \"value\": true}";
        byte[] aesKey = generateAesKey();
        SecretKeySpec aes = new SecretKeySpec(aesKey, "AES");

        // encrypt JSON
        byte[] encryptedJson = encryptContent(jsonToEncrypt, aes);
        System.out.println(Base64.getEncoder().encodeToString(encryptedJson));

        // encrypt file
        byte[] fileInBytes = Files.readAllBytes(Path.of("sample_driving_licence_to_encrypt.png"));
        byte[] encryptedFile = encryptContent(fileInBytes, aes);
        saveEncryptedFile(encryptedFile, "encrypted.png");

        // decrypt file
        InputStream decryptedFileStream = decryptFile("encrypted.png", aes);

        // save decrypted file
        saveDecryptedFile(decryptedFileStream, "decrypted.png");

        // encrypt AES key with public RSA key
        String encryptedAesKey = encryptAesKey(aesKey, TEST_RSA_PUBLIC_KEY_PEM);
        System.out.println(encryptedAesKey);
    }

    private static InputStream decryptFile(String filepath, SecretKeySpec aes) throws Exception {
        File source = new File(filepath);
        //convert source into array of bytes
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(source));

        //Cipher and encrypting
        return decrypt(bufferedInputStream, aes);
    }

    private static byte[] generateAesKey() throws NoSuchAlgorithmException {
        final SecureRandom rng = new SecureRandom();
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, rng);
        SecretKey aesKey = keyGenerator.generateKey();
        return aesKey.getEncoded();
    }

    private static byte[] encryptContent(String content, SecretKeySpec aesKey) throws Exception {
        return encryptContent(content.getBytes(), aesKey);
    }

    private static byte[] encryptContent(byte[] content, SecretKeySpec aesKey) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final IvParameterSpec ivForCBC = createIV(aesCBC.getBlockSize());
        aesCBC.init(Cipher.ENCRYPT_MODE, aesKey, ivForCBC);
        outputStream.write(ivForCBC.getIV());
        CipherOutputStream cos = new CipherOutputStream(outputStream, aesCBC);
        cos.write(content);
        cos.close();
        return outputStream.toByteArray();
    }

    private static IvParameterSpec createIV(final int ivSizeBytes) {
        final SecureRandom rng = new SecureRandom();
        final byte[] iv = new byte[ivSizeBytes];
        rng.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static String encryptAesKey(byte[] aesKey, String testRsaPublicKeyPem) throws GeneralSecurityException {
        String rsaKey = testRsaPublicKeyPem
                .replace("\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] encodedPublicKey = Base64.getDecoder().decode(rsaKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicRsaKey = keyFactory.generatePublic(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicRsaKey);
        byte[] doFinal = cipher.doFinal(aesKey);
        return new String(Base64.getEncoder().encode(doFinal));
    }

    private static void saveEncryptedFile(byte[] sourceFile, String newFilepath) throws IOException {
        File targetFile = new File(newFilepath);
        FileOutputStream os = new FileOutputStream(targetFile);
        os.write(sourceFile);
        os.flush();
        os.close();
    }

    private static InputStream decrypt(BufferedInputStream encryptedFile, SecretKeySpec aes) throws Exception {
        final Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final IvParameterSpec ivForCBC = readIV(aesCBC.getBlockSize(), encryptedFile);
        aesCBC.init(Cipher.DECRYPT_MODE, aes, ivForCBC);

        return new CipherInputStream(encryptedFile, aesCBC);
    }

    private static IvParameterSpec readIV(final int ivSizeBytes, final InputStream is) throws IOException {
        final byte[] iv = new byte[ivSizeBytes];
        int offset = 0;
        while (offset < ivSizeBytes) {
            final int read = is.read(iv, offset, ivSizeBytes - offset);
            if (read == -1) {
                throw new IOException("Too few bytes for IV in input stream");
            }
            offset += read;
        }
        return new IvParameterSpec(iv);
    }

    private static void saveDecryptedFile(InputStream decryptedFileStream, String filepath) throws IOException {
        File decryptedFile = new File(filepath);
        OutputStream outStream = new FileOutputStream(decryptedFile);
        outStream.write(decryptedFileStream.readAllBytes());
        outStream.flush();
        outStream.close();
    }

    public static final String TEST_RSA_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsTDahIYK1G4oubeLi3YR\n" +
            "91IBWtX1OWrhDYmYMn0bbH1ZR+sdik2Cp7SL2v/E1Sq0f/extXDIL2syPUywXu7O\n" +
            "fc0hhRLPGjFYIAE2U9JrW2Nt66rg+6om+oEUUFg6E/Tjq7bYrmabif7LDLxitIZy\n" +
            "kvfNqRCVT48fkO8rgxhLrBcPCEjmmv1iuedsrYH2hrys+CtSb9v6hzEYPM6/An2K\n" +
            "bs1HQXb6qvmvVxjDzOF3pHhqy2MLLdLPP6SyXZVX3Ki3O73AbEy9rXDFQMqlBqCD\n" +
            "A1TaA6n5g/jM1tMC/5LzyWO2i9Jct0BB2/wFu0ZwhlHOGMAb8bBYV3UvkA01tbzA\n" +
            "VQIDAQAB\n" +
            "-----END PUBLIC KEY-----";
}
