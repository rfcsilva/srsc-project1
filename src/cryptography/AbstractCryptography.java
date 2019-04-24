package cryptography;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import util.ArrayUtils;

public abstract class AbstractCryptography implements Cryptography {

	private static final String SECURE_RANDOM = "secure-random";
	private static final String HASH_CIPHERSUITE = "hash-ciphersuite";
	private static final String OUTER_MAC_CIPHERSUITE = "outer-mac-ciphersuite";
	private static final String INNER_MAC_CIPHERSUITE = "inner-mac-ciphersuite";
	private static final String SESSION_CIPHERSUITE = "session-ciphersuite";
	private static final String OUTER_MAC_KEY = "outer-mac-key";
	private static final String INNER_MAC_KEY = "inner-mac-key";
	private static final String SESSION_KEY = "session-key";
	private static final String KEYSTORE = "keystore";
	private static final String KEYSTORE_PASSWORD = "keystore-password";
	private static final String KEYSTORE_TYPE = "keystore-type";

	private Cipher encryptCipher;
	private Cipher decryptCipher;
	private Mac outerMac;
	private SecureRandom secureRandom;

	// TODO: arranjar nome melhor
	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);

		if (iv != null && iv.length > 0)
			cipher.init(cipherMode, key, new IvParameterSpec(iv));
		else
			cipher.init(cipherMode, key);

		return cipher;
	}
	
	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv, int tagSize)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		
		System.out.println(cipherAlgorithm);
		System.out.println(tagSize);
		System.out.println(key.getEncoded().length*8);
		
		if (iv != null && iv.length > 0) {
			if(tagSize > 0 && cipherAlgorithm.contains("GCM")) {
				cipher.init(cipherMode, key, new GCMParameterSpec(tagSize, iv));
			} else
				cipher.init(cipherMode, key, new IvParameterSpec(iv));
		} else
			cipher.init(cipherMode, key);

		return cipher;
	}
	
	public static Cipher buildGCMCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv, int tagSize)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		cipher.init(cipherMode, key, new GCMParameterSpec(tagSize, iv));
		return cipher;
	}
	
	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);

		cipher.init(cipherMode, key);

		return cipher;
	}

	// TODO: arranjar nome melhor
	public static Mac buildMac(String macAlgorithm, SecretKey key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(macAlgorithm);
		mac.init(key);
		return mac;
	}

	public static MessageDigest buildHash(String hashAlgorithm) throws NoSuchAlgorithmException {
		return MessageDigest.getInstance(hashAlgorithm);
	}

	public static SecureRandom buildSecureRandom(String secureRandomAlgorithm) throws NoSuchAlgorithmException {
		return SecureRandom.getInstance(secureRandomAlgorithm);
	}

	public static Cryptography loadFromConfig(String path)
			throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			CertificateException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);

		// Load KeyStore
		String password = ciphersuit_properties.getProperty(KEYSTORE_PASSWORD);
		KeyStore key_store = CryptographyUtils.loadKeyStrore(ciphersuit_properties.getProperty(KEYSTORE), password,
				ciphersuit_properties.getProperty(KEYSTORE_TYPE));

		// Load Keys from KeyStore
		SecretKey ks = null, kim = null, kom = null;
		if (ciphersuit_properties.getProperty(SESSION_KEY) != null)
			ks = CryptographyUtils.getKey(key_store, password, ciphersuit_properties.getProperty(SESSION_KEY));
		if (ciphersuit_properties.getProperty(INNER_MAC_KEY) != null)
			kim = CryptographyUtils.getKey(key_store, password, ciphersuit_properties.getProperty(INNER_MAC_KEY));

		if (ciphersuit_properties.getProperty(OUTER_MAC_KEY) != null)
			kom = CryptographyUtils.getKey(key_store, password, ciphersuit_properties.getProperty(OUTER_MAC_KEY));

		// Build ciphersuits
		byte[] iv = ArrayUtils.unparse(ciphersuit_properties.getProperty("iv"));
		Cipher encryptCipher = null, decryptCipher = null;
		if (ciphersuit_properties.getProperty(SESSION_KEY) != null) {
			encryptCipher = buildCipher(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), Cipher.ENCRYPT_MODE, ks, iv);
			decryptCipher = buildCipher(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), Cipher.DECRYPT_MODE, ks, iv);
		}
		
		Mac outerMac = null;
		if (ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE) != null)
			outerMac = buildMac(ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE), kom);

		SecureRandom secureRandom = buildSecureRandom(ciphersuit_properties.getProperty(SECURE_RANDOM));

		String hashAlgorithm = ciphersuit_properties.getProperty(HASH_CIPHERSUITE);
		if (hashAlgorithm != null) {
			MessageDigest innerHash = buildHash(hashAlgorithm);
			return new CryptographyHash(encryptCipher, decryptCipher, secureRandom, innerHash, outerMac);
		} else {
			Mac innerMac = null;
			if (kim != null && ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE) != null)
				innerMac = buildMac(ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE), kim);

			return new CryptographyDoubleMac(encryptCipher, decryptCipher, secureRandom, innerMac, outerMac);
		}
	}

	public AbstractCryptography(Cipher encryptCipher, Cipher decryptCipher, Mac outerMac, SecureRandom sr) {
		this.encryptCipher = encryptCipher;
		this.decryptCipher = decryptCipher;
		this.secureRandom = sr;
		this.outerMac = outerMac;
	}

	@Override
	public Cipher getEncryptCipher() {
		return encryptCipher;
	}

	@Override
	public Cipher getDecryptCipher() {
		return decryptCipher;
	}

	@Override
	public SecureRandom getSecureRandom() {
		return secureRandom;
	}

	@Override
	public Mac getOuterMac() {
		return outerMac;
	}

	@Override
	public byte[] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, ShortBufferException {
		byte[] cipherText = new byte[encryptCipher.getOutputSize(plaintext.length)];
		int ctLength = encryptCipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		ctLength += encryptCipher.doFinal(cipherText, ctLength);	
		return cipherText;
	}

	@Override
	public byte[] decrypt(byte[] cipherText)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		byte[] plainText = new byte[decryptCipher.getOutputSize(cipherText.length)];
		int ptLength = decryptCipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += decryptCipher.doFinal(plainText, ptLength);
		
		
		return Arrays.copyOfRange(plainText, 0, ptLength);
		
		//return plainText;
	}

	@Override
	public byte[] computeOuterMac(byte[] payload) throws InvalidKeyException {
		return computeMac(outerMac, payload);
	}

	public abstract byte[] computeIntegrityProof(byte[] payload) throws InvalidKeyException;

	@Override
	public boolean validateOuterMac(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(outerMac, message, expectedMac);
	}

	public boolean validateMac(Mac mac, byte[] message, byte[] expectedMac) throws InvalidKeyException {
		byte[] inboundMessageMac = computeMac(mac, message);
		return MessageDigest.isEqual(inboundMessageMac, expectedMac);
	}

	@Override
	public abstract boolean validateIntegrityProof(byte[] message, byte[] expectedMac) throws InvalidKeyException;

	@Override
	public byte[][] splitOuterMac(byte[] plainText) {
		return splitMessage(outerMac.getMacLength(), plainText);
	}

	@Override
	public abstract byte[][] splitIntegrityProof(byte[] plainText);

	protected byte[][] splitMessage(int offset, byte[] plainText) {
		byte[][] messageParts = new byte[2][];

		int messageLength = plainText.length - offset;

		messageParts[0] = new byte[messageLength];
		System.arraycopy(plainText, 0, messageParts[0], 0, messageLength);

		messageParts[1] = new byte[offset];
		System.arraycopy(plainText, messageLength, messageParts[1], 0, offset);

		return messageParts;
	}

	protected byte[] computeMac(Mac mac, byte[] payload) throws InvalidKeyException {
		mac.update(payload);
		return mac.doFinal();
	}

}
