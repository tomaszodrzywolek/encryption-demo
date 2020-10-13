package encryption_demo;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class App {
    public static void main(String[] args) throws Exception {
        String jsonToEncrypt = "{\"message\": \"ok\", \"value\": true}";
        byte[] aesKey = generateAesKey();
        byte[] encryptedJson = encryptContent(jsonToEncrypt, new SecretKeySpec(aesKey, "AES"));
        String encryptedAesKey = encryptAesKey(aesKey, TEST_RSA_PUBLIC_KEY_PEM);
        String encryptedJsonToSendInHttp = Base64.getEncoder().encodeToString(encryptedJson);

        String aesKeyString = Base64.getEncoder().encodeToString(aesKey);
        System.out.println(aesKeyString);

        // This should be included in Key header
        System.out.println(encryptedAesKey);

        // This should be included in request body
        System.out.println(encryptedJsonToSendInHttp);
    }

    private static byte[] generateAesKey() throws NoSuchAlgorithmException {
        final SecureRandom rng = new SecureRandom();
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, rng);
        SecretKey aesKey = keyGenerator.generateKey();
        return aesKey.getEncoded();
    }

    private static byte[] encryptContent(String content, SecretKeySpec aesKey) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final IvParameterSpec ivForCBC = createIV(aesCBC.getBlockSize());
        aesCBC.init(Cipher.ENCRYPT_MODE, aesKey, ivForCBC);
        outputStream.write(ivForCBC.getIV());
        CipherOutputStream cos = new CipherOutputStream(outputStream, aesCBC);
        cos.write(content.getBytes());
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
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "");
        byte[] encodedPublicKey = Base64.getDecoder().decode(rsaKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicRsaKey = keyFactory.generatePublic(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicRsaKey);
        byte[] doFinal = cipher.doFinal(aesKey);
        return new String(Base64.getEncoder().encode(doFinal));
    }


    private static final String TEST_RSA_PUBLIC_KEY_PEM =
            "-----BEGIN RSA PUBLIC KEY-----\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/YmAcTIa8rPD0qzUQFO\n" +
                    "XQjbNdvQQWhdSC8w49roTgiLDngdGWDGqvRmyFfZStY9t2OO21S+3sJyZb2wCqpo\n" +
                    "uVXnK0fxjHxGlmXhV7W/fyzBxXriKae9R8EPxcW/KiQiBgscLI0S3AAVZXTHvjz2\n" +
                    "JZnyO+zG2RTrTyhJx5DzpE/sR2CnHlsuI1joo4BaRinC6T2ds+VBfMpySGt8G9Ka\n" +
                    "yiNT9I5n3plQA9SvlAXZO/FpS4CBS3jaMp/ef8X6Mqy6QeWbCbQO66ekwpGMXyMj\n" +
                    "k4crBSI+FXbfriQd3CPdWE+/PfPxRiZu/G6zYqwcMYYpOFXSikXHntAdVE37ugyE\n" +
                    "pwIDAQAB\n" +
                    "-----END RSA PUBLIC KEY-----";

    private static final String TEST_RSA_PRIVATE_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEowIBAAKCAQEA1/YmAcTIa8rPD0qzUQFOXQjbNdvQQWhdSC8w49roTgiLDngd\n" +
                    "GWDGqvRmyFfZStY9t2OO21S+3sJyZb2wCqpouVXnK0fxjHxGlmXhV7W/fyzBxXri\n" +
                    "Kae9R8EPxcW/KiQiBgscLI0S3AAVZXTHvjz2JZnyO+zG2RTrTyhJx5DzpE/sR2Cn\n" +
                    "HlsuI1joo4BaRinC6T2ds+VBfMpySGt8G9KayiNT9I5n3plQA9SvlAXZO/FpS4CB\n" +
                    "S3jaMp/ef8X6Mqy6QeWbCbQO66ekwpGMXyMjk4crBSI+FXbfriQd3CPdWE+/PfPx\n" +
                    "RiZu/G6zYqwcMYYpOFXSikXHntAdVE37ugyEpwIDAQABAoIBABOH8GICkPmmqtlA\n" +
                    "MT1nN9YUIfcZ/RidPqpzkiFZP98myKSzWjZcWTtGxTDjOQSaoZQ/TcEqReTRgxUO\n" +
                    "dahRRw1T5oc0h3TkHGInrpyHFF2FB7U7as7Hm8esfyesvaArCmSvhonE7Gq3GzhE\n" +
                    "unfK/Zvi81RWEpm5WZqcEygYROCcK0OdWDuTnuHs7iahRrBoaBti2QPof15s5WiT\n" +
                    "WKJ2Mi399qCcyvegPNh/ncHsW+l9GvNw2fQzU1EfqlfQfd1ZJax5j2PgCEvEp3pv\n" +
                    "tFSQSxAbQ+BAuPdhN2BLyj353fZ3EG+vOU12vfQtXGwy46E+6W1DG60auNRVswj7\n" +
                    "hk+G9zkCgYEA6zPnsU1cn7LT5khUKNLIq10R+fmhcsJy0d2Froj4oaxY8FU+2qkU\n" +
                    "mDIln0ikJYYDKokEkpimVmpbg6IHNh30nFnlPw2qICBH9X3WwOUeIKkq692MBi+a\n" +
                    "EtIGNkN41AUHFcmHNsRGioeKBGxEIEJNV4iLGpptnRl0QaGPnd13t6sCgYEA6w6x\n" +
                    "7/IV/Wt5YyAnV4RDZY/B40YZVnDndrd87GDBf6bgWOLCPrX2jV9gnZiPn1SeMOok\n" +
                    "n72x1tJJ0fgvmQZ3HJVoakModlcPNPzOizHytsspUuoOJ07EtaS8vgMs3+7RU4Ni\n" +
                    "Rs8Zql3bt32KgIdSRf7lljHTKJ429MNvT/OXOvUCgYAPSdxxpfmzV8h2W5U84hax\n" +
                    "LOeSPCvGbeVQxvl9kuG2gKF3XdMsG3l/OyM+61XgKoniJe3qKYoGa/tu3wVg+yl/\n" +
                    "UEiahKTeWbrTtk5TU5FVxilIE6qabFWzi3tj45bjEUCYpfToFnIPZygNiYwUHLsy\n" +
                    "SWnhXNBrOdBYw8u2E0NI6QKBgQCTX/lMWdpTs4i+D7Da/EBNcx67Yn4MZmmZU13t\n" +
                    "zpRDdtt+n13ud6QH617mMHsMCL/OJ1+jEApqiBpknVkqdpVDxKFczpKV7+vG6yKM\n" +
                    "v1pQJXzZUYpiNs66nHkCIXeHR3LTC7MYdky/Nm3F0958y1tYK4LC8qZT9y65s7cc\n" +
                    "x7tv6QKBgC3IfM+yoPFvgkmE2+TZRiJw2XDsR7/QZ+J19VGDsklwl8wb41AwSGIx\n" +
                    "pIpRfkhljAozJzK3lk7XRGTQOPij8fnBd15HjqgYyR0B9OVnKpL2kDGEYgl/cqDS\n" +
                    "gj5FqQltw/tJrMq6M4gtWdLZ6072h3AunfaHvIfDhEPMnzx7XI/F\n" +
                    "-----END RSA PRIVATE KEY-----";
}
