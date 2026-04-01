import java.security.*;
import javax.crypto.*;

public class CryptoMisuseVulnerable {

    // Matches: java-md5-digest
    public MessageDigest vulnerableMd5() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    // Matches: java-sha1-digest
    public MessageDigest vulnerableSha1() throws Exception {
        return MessageDigest.getInstance("SHA-1");
    }

    // Matches: java-des-cipher
    public Cipher vulnerableDes() throws Exception {
        return Cipher.getInstance("DES");
    }

    // Matches: java-ecb-mode (pattern-regex)
    public Cipher vulnerableEcb() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // Matches: java-securerandom-seed
    public SecureRandom vulnerableSeed() {
        byte[] seed = {1, 2, 3, 4};
        return new SecureRandom(seed);
    }

    // Safe: AES-GCM with proper random
    public Cipher safeCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
