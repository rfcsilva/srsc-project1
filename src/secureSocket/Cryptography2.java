package secureSocket;

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

public class Cryptography2 {

	private static final String CIPHERSUITE_CONFIG_PATH = "configs/server/ciphersuite.conf";
	private static final String TYPE_OF_KEYSTORE = "PKCS12";
	private static final String PATH_TO_KEYSTORE = "configs/keystore.p12";
	private static final String AES_256_KEY_ALIAS = "aes256-key";
	private static final String AES_256_MAC_KEY_ALIAS = "mac256-key";
	private static final String AES_128_MAC_KEY_ALIAS = "mac128-key";
	private static final String PASSWORD = "SRSC1819";

	private static final byte[] ivBytes = new byte[] {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
	};
	
	//private Properties ciphersuit_properties;
	private Cipher cipher;
	//private Cipher decryptCipher; // é preciso as duas ou passamos o modo no cosntrutor?
	private Mac innerMac;
	private Mac outerMac;
	/*private SecretKey ks; // é preciso guardar as chaves?
	private SecretKey km;
	private SecretKey ka;*/
	
	/*public Cryptography2(String cipherAlgorithm, String cipherMode, SecretKey ks, byte[] iv, String innerMacAlgorithm) {
		
	}*/
	
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
	
	public static Cryptography2 loadFromConfig(String path) throws IOException {
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);
		
		// Load keystore
		KeyStore key_store = KeyStore.getInstance(TYPE_OF_KEYSTORE);
		key_store.load(new FileInputStream(PATH_TO_KEYSTORE), PASSWORD.toCharArray());

		SecretKey ks = readKey(key_store, AES_256_KEY_ALIAS);
		SecretKey km = readKey(key_store, AES_256_MAC_KEY_ALIAS);
		SecretKey ka = readKey(key_store, AES_128_MAC_KEY_ALIAS);

		return null;
	}
	
	private static SecretKey readKey(KeyStore ks, KeyStore.PasswordProtection password, String alias) throws
	NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
	CertificateException, FileNotFoundException, IOException {
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(alias, password);
		return entry.getSecretKey();
	}
	
	//TODO: handle exceptions gracefully
	
	public Cryptography2(Cipher cipher, Mac innerMac, Mac outerMac) {
		this.cipher = cipher;
		this.innerMac = innerMac;
		this.outerMac = outerMac;
	}

	
	public Cryptography2( int cypherMode ) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

		loadCipherSuitConfig();
		loadCipherSuit();
		cipher.init(cypherMode, ks, new IvParameterSpec(ivBytes));
		innerMac.init(km);
		outerMac.init(ka);
	}

	public byte[] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {

		byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
		cipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		cipher.doFinal();
		return cipherText;
	}


	//TODO: What to do when mac is invalid
	public byte[] decrypt(byte[] cipherText) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {


		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);

		return plainText;
	}

	public byte[] computeMacDoS(byte[] payload) throws InvalidKeyException {
		return computeMac(outerMac, payload);
	}

	public byte[] computeMac(byte[] payload) throws InvalidKeyException {
		return computeMac(innerMac, payload);
	}

	public boolean validateMacDos(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(outerMac, message, expectedMac);
	}
	
	public boolean validadeInnerMac(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(innerMac, message, expectedMac);
	}
	
	
	private boolean validateMac(Mac mac, byte[] message, byte[] expectedMac) throws InvalidKeyException {
		byte[] inboundMessageMac = computeMac(mac, message);
		return MessageDigest.isEqual(inboundMessageMac, expectedMac);
	}
	
	public byte[][] splitHeader(byte[] plainText){
		
		return getMessageParts(outerMac, plainText);
	}
	
	public byte[][] splitPayload(byte[] plainText){
		
		return getMessageParts(innerMac, plainText);
	}
	
	private byte[][] getMessageParts( Mac mac, byte[] plainText ){

		byte[][] messageParts = new byte[2][]; 

		int  messageLength = plainText.length - mac.getMacLength();

		byte[] aux = new byte[messageLength];
		System.arraycopy(plainText, 0, aux, 0, messageLength);
		messageParts[0] = aux;

		aux = new byte[mac.getMacLength()];
		System.arraycopy(plainText, messageLength, aux, 0, aux.length);
		messageParts[1] = aux;

		return messageParts;

	}

	private byte[] computeMac(Mac mac, byte[] payload) throws InvalidKeyException {
		mac.update(payload);
		return mac.doFinal();
	}
	
	// Porque estás a retornar bool?
	private boolean loadCipherSuitConfig() {
		try {
			InputStream inputStream = new FileInputStream(CIPHERSUITE_CONFIG_PATH);
			ciphersuit_properties = new Properties();
			ciphersuit_properties.load(inputStream);
			return true;
		} catch (IOException e) {	
			e.printStackTrace();
			return false;
		}
	}

	private void loadCipherSuit() throws
	InvalidKeyException, InvalidAlgorithmParameterException,
	NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException,
	KeyStoreException, CertificateException, FileNotFoundException, IOException {

		// Load keystore
		KeyStore key_store = KeyStore.getInstance(TYPE_OF_KEYSTORE);
		key_store.load(new FileInputStream(PATH_TO_KEYSTORE), PASSWORD.toCharArray());

		ks = readKey(key_store, AES_256_KEY_ALIAS);
		km = readKey(key_store, AES_256_MAC_KEY_ALIAS);
		ka = readKey(key_store, AES_128_MAC_KEY_ALIAS);

		// Load Ciphersuit
		cipher = Cipher.getInstance(ciphersuit_properties.getProperty("session-ciphersuite"));

		// Load HMAC
		innerMac = Mac.getInstance(ciphersuit_properties.getProperty("mac-ciphersuite"));

		//load MAC to mitigate DOS
		outerMac = Mac.getInstance(ciphersuit_properties.getProperty("mac-ciphersuite"));
	}

		
}
