package secureSocket.cryptography;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class AbstractCryptography implements Cryptography {

	private static final String OUTER_MAC_CIPHERSUITE = "outer-mac-ciphersuite";
	private static final String INNER_MAC_CIPHERSUITE = "inner-mac-ciphersuite";
	private static final String SESSION_CIPHERSUITE = "session-ciphersuite";
	private static final String OUTER_MAC_KEY = "outer-mac-key";
	private static final String INNER_MAC_KEY = "inner-mac-key";
	private static final String SESSION_KEY = "session-key";
	private static final String KEYSTORE = "keystore";
	private static final String KEYSTORE_PASSWORD = "keystore-password";
	private static final String KEYSTORE_TYPE = "keystore-type";

	private static final byte[] ivBytes = new byte[] {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
	};
	
	private Cipher cipher;
	private Mac innerMac;
	private Mac outerMac;
	
	// TODO: arranjar nome melhor
	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException { 
		Cipher cipher =	Cipher.getInstance(cipherAlgorithm);
		
		if( iv != null )
			cipher.init(cipherMode, key, new IvParameterSpec(iv));
		else
			cipher.init(cipherMode, key);
		
		return cipher;
	}
	
	// TODO: arranjar nome melhor
	public static Mac buildMac(String macAlgorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(macAlgorithm);
		mac.init(key);
		return mac;
	}
	
	public static AbstractCryptography loadFromConfig(String path, int cipherMode) throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);
		
		// Load KeyStore
		KeyStore key_store = KeyStore.getInstance(ciphersuit_properties.getProperty(KEYSTORE_TYPE)); // TODO: passar estas strings todas para constatnes
		char[] password = ciphersuit_properties.getProperty(KEYSTORE_PASSWORD).toCharArray();
		//String ks_path = path.substring(0, path.lastIndexOf('/')+1) + ciphersuit_properties.getProperty(KEYSTORE);
		//System.out.println(ks_path);
		//key_store.load(new FileInputStream(ks_path), password);
		key_store.load(new FileInputStream(ciphersuit_properties.getProperty(KEYSTORE)), password);
		KeyStore.PasswordProtection  ks_pp = new KeyStore.PasswordProtection(password);

		// Load Keys from KeyStore
		SecretKey ks = readKey(key_store, ks_pp, ciphersuit_properties.getProperty(SESSION_KEY));
		SecretKey kim = readKey(key_store, ks_pp, ciphersuit_properties.getProperty(INNER_MAC_KEY));
		SecretKey kom = readKey(key_store, ks_pp, ciphersuit_properties.getProperty(OUTER_MAC_KEY));
		
		// Build ciphersuits
		Cipher cipher = buildCipher(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), cipherMode, ks, ivBytes); // TODO: o que fazer com o IV ?
		Mac innerMac = buildMac(ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE), kim);
		Mac outerMac = buildMac(ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE), kom);
		
		return new AbstractCryptography(cipher, innerMac, outerMac);
	}
	
	private static SecretKey readKey(KeyStore ks, KeyStore.PasswordProtection ks_pp, String alias) throws
	NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
	CertificateException, FileNotFoundException, IOException {
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(alias, ks_pp);
		return entry.getSecretKey();
	}
		
	public AbstractCryptography(Cipher cipher, Mac innerMac, Mac outerMac) {
		this.cipher = cipher;
		this.innerMac = innerMac;
		this.outerMac = outerMac;
	}
	
	@Override
	public Cipher getCipher() {
		return cipher;
	}

	public Mac getInnerMac() {
		return innerMac;
	}

	public Mac getOuterMac() {
		return outerMac;
	}

	@Override
	public byte[] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
		byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
		cipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		cipher.doFinal();
		return cipherText;
	}

	@Override
	public byte[] decrypt(byte[] cipherText) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		return plainText;
	}

	public byte[] computeOuterMac(byte[] payload) throws InvalidKeyException {
		return computeMac(outerMac, payload);
	}

	public byte[] computeInnerMac(byte[] payload) throws InvalidKeyException {
		return computeMac(innerMac, payload);
	}
	
	private byte[] computeMac(Mac mac, byte[] payload) throws InvalidKeyException {
		mac.update(payload);
		return mac.doFinal();
	}

	//TODO: What to do when mac is invalid
	public boolean validateOuterMac(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(outerMac, message, expectedMac);
	}
	
	public boolean validadeInnerMac(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(innerMac, message, expectedMac);
	}
	
	public boolean validateMac(Mac mac, byte[] message, byte[] expectedMac) throws InvalidKeyException {
		byte[] inboundMessageMac = computeMac(mac, message);
		return MessageDigest.isEqual(inboundMessageMac, expectedMac);
	}
	
	public byte[][] splitOuterMac(byte[] plainText){
		return splitMac(outerMac, plainText);
	}
	
	public byte[][] splitInnerMac(byte[] plainText){
		return splitMac(innerMac, plainText);
	}
	
	private byte[][] splitMac(Mac mac, byte[] plainText){
		byte[][] messageParts = new byte[2][]; 

		int macLength = mac.getMacLength();
		int messageLength = plainText.length - macLength;

		messageParts[0] = new byte[messageLength];
		System.arraycopy(plainText, 0, messageParts[0], 0, messageLength);

		messageParts[1] = new byte[macLength];
		System.arraycopy(plainText, messageLength, messageParts[1], 0, macLength);

		return messageParts;
	}
	
}
