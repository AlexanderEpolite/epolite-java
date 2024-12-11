package net.epolite;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyPairGeneratorSpi;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

/**
 * This is an implementation of a public/private keypair using Kyber for encryption and FALCON for signing.
 * <p>
 * This is meant for educational  use ONLY, use outside of institutions or at-home  testing is not allowed,
 * due to the untested nature of this software.  This program is  tested to work, but has not been audited
 * by any security firm.  It is NOT endorsed by any university, institution, government agency, or company.
 * 
 * @author Alexander Ryan Epolite <aepolite@asu.edu>
 */
public class EPOLITE {
    private static final String EPOLITE_PUBLIC_KEY_LABEL = "----------BEGIN EPOLITE PUBLIC KEY----------";
    private static final String EPOLITE_PRIVATE_KEY_LABEL = "----------BEGIN EPOLITE PRIVATE KEY----------";
    private static final String KEY_END_LABEL = "----------END EPOLITE KEY----------";
    
    static {
        System.err.printf("You are running the EPOLITE encryption library.%nThis library is meant for educational uses only, and not yet ready for production programs.%nuse outside of institutions or testing is not allowed at this time.%n");
        
        if(Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    //create a keypair for kyber, used for encryption
    private static Map<String, byte[]> generateKyberKeyPair() {
        var generator = new KyberKeyPairGeneratorSpi.Kyber512();
        var kp = generator.generateKeyPair();
        
        var publicKey = kp.getPublic();
        var privateKey = kp.getPrivate();

        Map<String, byte[]> keyPair = new HashMap<>();
        keyPair.put("publicKey", publicKey.getEncoded());
        keyPair.put("privateKey", privateKey.getEncoded());
        
        return keyPair;
    }

    
    //create a keypair for falcon, used for signing
    private static Map<String, byte[]> generateFalconKeyPair() throws Exception {
        Map<String, byte[]> keyPair = new HashMap<>();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Falcon", "BCPQC");
        KeyPair kp = keyGen.generateKeyPair();
        
        keyPair.put("publicKey", kp.getPublic().getEncoded());
        keyPair.put("privateKey", kp.getPrivate().getEncoded());
        
        return keyPair;
    }

    /**
     * Create a new EPOLITE keypair, containing both a private key and public key.
     * <p>
     * The private key can be used for Signing and Decrypting operations, whereas
     * the public key can be used for Verifying and Encrypting options.
     * <p>
     * The public key should be given to other users or put in an online database
     * attached to an email or name, the private key should always be kept hidden,
     * and even encrypted.
     * 
     * @return {@link EPOLITEKeypair} the keypair
     */
    public static EPOLITEKeypair createEpoliteKeypair() throws Exception {
        Map<String, byte[]> kyberKeys = generateKyberKeyPair();
        Map<String, byte[]> falconKeys = generateFalconKeyPair();
        
        //convert to bigints for storing in the json object
        byte[] kyberPublicKeyBInt = new BigInteger(kyberKeys.get("publicKey")).toString().getBytes(StandardCharsets.UTF_8);
        byte[] falconPublicKeyBInt = new BigInteger(falconKeys.get("publicKey")).toString().getBytes(StandardCharsets.UTF_8);
        byte[] kyberPrivateKeyBInt = new BigInteger(kyberKeys.get("privateKey")).toString().getBytes(StandardCharsets.UTF_8);
        byte[] falconPrivateKeyBInt = new BigInteger(falconKeys.get("privateKey")).toString().getBytes(StandardCharsets.UTF_8);

        //handle as bytes for security
        ByteArrayOutputStream publicJsonOS = new ByteArrayOutputStream();
        publicJsonOS.write("{\"version\":6,\"kyberPublicKey\":\"".getBytes(StandardCharsets.UTF_8));
        publicJsonOS.write(kyberPublicKeyBInt);
        publicJsonOS.write("\",\"falconPublicKey\":\"".getBytes(StandardCharsets.UTF_8));
        publicJsonOS.write(falconPublicKeyBInt);
        publicJsonOS.write("\"}".getBytes(StandardCharsets.UTF_8));
        byte[] publicKeyJsonBytes = publicJsonOS.toByteArray();

        //since org.json mostly deals with strings, private key will need to be handled as bytes
        ByteArrayOutputStream privateJsonOS = new ByteArrayOutputStream();
        privateJsonOS.write("{\"version\":6,\"kyberPrivateKey\":\"".getBytes(StandardCharsets.UTF_8));
        privateJsonOS.write(kyberPrivateKeyBInt);
        privateJsonOS.write("\",\"falconPrivateKey\":\"".getBytes(StandardCharsets.UTF_8));
        privateJsonOS.write(falconPrivateKeyBInt);
        privateJsonOS.write("\"}".getBytes(StandardCharsets.UTF_8));
        byte[] privateKeyJsonBytes = privateJsonOS.toByteArray();

        //full pubkey
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream();
        publicOut.write(publicKeyJsonBytes);
        byte[] publicKeyFinalBytes = publicOut.toByteArray();

        //full privkey
        ByteArrayOutputStream privateOut = new ByteArrayOutputStream();
        privateOut.write(privateKeyJsonBytes);
        byte[] privateKeyFinalBytes = privateOut.toByteArray();

        return new EPOLITEKeypair(Base64.encode(privateKeyFinalBytes), Base64.encode(publicKeyFinalBytes));
    }
    
    //encrypt data
    private static byte[] aesGcmEncrypt(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, skey, spec);
        byte[] encrypted = cipher.doFinal(data);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(iv);
        out.write(encrypted);
        return out.toByteArray();
    }
    
    //decrypt byte[], iv is inside the key on the first 12 bytes
    private static byte[] aesGcmDecrypt(byte[] key, byte[] encryptedData) throws Exception {
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 12);
        byte[] actualCiphertext = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, skey, spec);
        return cipher.doFinal(actualCiphertext);
    }

    //from the BouncyCastle docs
    private static SecretKeyWithEncapsulation getKyberEncapsulationSending(PublicKey publicKey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("KYBER", "BCPQC");
        
        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, "Secret");
        
        keyGenerator.init(kemGenerateSpec);
        
        return  (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }

    //from the BouncyCastle docs
    private static SecretKeyWithEncapsulation getKyberEncapsulationReceiving(PrivateKey privateKey, byte[] encapsulation) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, "Secret");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("KYBER", "BCPQC");
        
        keyGenerator.init(kemExtractSpec);

        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }
    
    //load kyber private key to BC object instead of byte[]
    private static BCKyberPublicKey loadKyberPublicKey(byte[] publicKeyBytes) throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyBytes);
        
        return new BCKyberPublicKey(publicKeyInfo);
    }

    //load kyber public key to BC object instead of byte[]
    private static BCKyberPrivateKey loadKyberPrivateKey(byte[] privateKeyBytes) throws Exception {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyBytes);
        
        return new BCKyberPrivateKey(privateKeyInfo);
    }

    /**
     * Encrypt a message using the recipients public key.
     * 
     * While the encrypted message is encrypted with a symmetric key, the recipient
     * will receive the encrypted message and can decrypt it at any time with their
     * private key.
     * 
     * @see #decrypt(byte[], byte[])
     * @param data {byte[]} the data to encrypt
     * @param epolitePublicKey {byte[]} the public key of the recipient
     * @return {byte[]} a byte[] representation of the encrypted data, which can be sent to the recipient.
     */
    public static byte[] encrypt(byte[] data, byte[] epolitePublicKey) throws Exception {
        JSONObject o = new JSONObject(new String(Base64.decode((epolitePublicKey))));
        
        var bi = o.getBigInteger("kyberPublicKey");
        
        var pub = loadKyberPublicKey(bi.toByteArray());
        
        var shared_key = getKyberEncapsulationSending(pub);
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        var encrypted = aesGcmEncrypt(shared_key.getEncoded(), data, iv);
        
        JSONObject jo = new JSONObject();
        
        jo.put("cipherText", new String(Base64.encode(shared_key.getEncapsulation())));
        jo.put("encryptedData", new String(Base64.encode(encrypted)));
        jo.put("iv", iv);
        jo.put("version", 6);
        
        return Base64.encode(jo.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt a message given the raw encrypted message and the private key.
     * @param encryptedMessage {byte[]} the encrypted message to decrypt
     * @param epolitePrivateKey {byte[]} the private key to use for decrypting
     * @return {byte[]} the byte[] representation of the decrypted data, which could be converted back
     *                  into a {@link String}, depending on your use case and security.
     * @throws Exception if the private key or data are wrong
     */
    public static byte[] decrypt(byte[] encryptedMessage, byte[] epolitePrivateKey) throws Exception {
        JSONObject privkey = new JSONObject(new String(Base64.decode((epolitePrivateKey))));

        var bi = privkey.getBigInteger("kyberPrivateKey");
        
        JSONObject encJSON = new JSONObject(new String(Base64.decode(encryptedMessage)));
        
        var cipherText = Base64.decode(encJSON.getString("cipherText"));
        var encryptedData = Base64.decode(encJSON.getString("encryptedData"));
        
        var secret = getKyberEncapsulationReceiving(loadKyberPrivateKey(bi.toByteArray()), cipherText);
        
        return aesGcmDecrypt(secret.getEncoded(), encryptedData);
    }

    //load FALCON public key to BC object instead of byte[]
    private static BCFalconPublicKey loadFalconPublicKey(byte[] publicKeyBytes) throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyBytes);
        
        return new BCFalconPublicKey(publicKeyInfo);
    }

    //load FALCON private key to BC object instead of byte[]
    private static BCFalconPrivateKey loadFalconPrivateKey(byte[] privateKeyBytes) throws Exception {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyBytes);
        
        return new BCFalconPrivateKey(privateKeyInfo);
    }

    /**
     * Signs a message given the sender's private key.
     * 
     * Warning: signed messages contain the raw message inside of them!  After signing,
     * messages should be encrypted for security, otherwise they act as an unsealed letter.
     * 
     * @see #verify(byte[], byte[])
     * @param rawMessage {byte[]} the raw message to sign
     * @param epolitePrivateKey {byte[]} the private key to sign with
     * @return {byte[]} the byte representation of the signed message.
     */
    public static byte[] sign(byte[] rawMessage, byte[] epolitePrivateKey) throws Exception {
        JSONObject joPrivateKey = new JSONObject(new String(Base64.decode((epolitePrivateKey))));

        var bi = joPrivateKey.getBigInteger("falconPrivateKey");
        
        var privateKey = bi.toByteArray();
        
        var s = Signature.getInstance("Falcon");
        s.initSign(loadFalconPrivateKey(privateKey));
        s.update(rawMessage);
        
        var signed = s.sign();
        
        JSONObject o = new JSONObject();
        
        o.put("sig", Base64.toBase64String((signed)));
        o.put("raw", new String(rawMessage));
        o.put("version", 6);
        
        return Base64.encode(o.toString().getBytes());
    }

    /**
     * Verifies a message with the signer's public key.  Returns the raw message and boolean on if the signature is valid.
     * 
     * @see #sign(byte[], byte[])
     * @param signedMessageRaw {byte[]} the signed message to be verified
     * @param signerPublicKey {byte[]} the public key of the signer
     * @return {{@link VerifiedState}} the verified state of the message
     */
    public static VerifiedState verify(byte[] signedMessageRaw, byte[] signerPublicKey) throws Exception {
        JSONObject joPublicKey = new JSONObject(new String(Base64.decode(signerPublicKey)));
        
        var bi = joPublicKey.getBigInteger("falconPublicKey");
        
        var publicKey = bi.toByteArray();
        
        var s = Signature.getInstance("Falcon");
        s.initVerify(loadFalconPublicKey(publicKey));
        
        var smJSON = new JSONObject(new String(Base64.decode(signedMessageRaw)));

        String raw = smJSON.getString("raw");
        String sigBase64 = smJSON.getString("sig");
        
        byte[] signatureBytes = Base64.decode(sigBase64);
        
        s.initVerify(loadFalconPublicKey(publicKey));
        s.update(raw.getBytes(StandardCharsets.UTF_8));
        
        boolean verified = s.verify(signatureBytes);
        
        return new VerifiedState(verified, raw.getBytes());
    }
    
    //for testing
    private static void main(String[] args) throws Exception {
        EPOLITEKeypair epoliteKeyPair = createEpoliteKeypair();
        
        byte[] b = "qwerty".getBytes();
        
        var e = encrypt(b, epoliteKeyPair.publicKey);
        
        var d = decrypt(e, epoliteKeyPair.privateKey);

        System.out.printf("decrypted: %s\n", new String(d));
        
        var s = sign(b, epoliteKeyPair.privateKey);

        System.out.printf("signed: %s\n", Arrays.toString(s));
        
        var v = verify(s, epoliteKeyPair.publicKey);

        System.out.printf("verified: %b; raw: %s\n", v.verified, new String(v.signedMessage));
    }
    
    public static class VerifiedState {
        public boolean verified;
        public byte[] signedMessage;
        
        public VerifiedState(boolean verified, byte[] signedMessage) {
            this.verified = verified;
            this.signedMessage = signedMessage;
        }
    }

    public record EPOLITEKeypair(byte[] privateKey, byte[] publicKey) {}
}
