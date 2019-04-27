package cryptography;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
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
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import util.CryptographyUtils;
import util.Utils;

public class CryptoFactory {

	private static final String CIPHER_PROVIDER = "cipher-provider";
	private static final String OUTTER_MAC_PROVIDER = "outter-mac-provider";
	private static final String INNER_MAC_PROVIDER = "inner-mac-provider";
	private static final String HASH_PROVIDER = "hash-provider";
	private static final String SECURE_RANDOM_PROVIDER = "secure-random-provider";

	private static final int INITIAL_MSG_NUMBER = 1;
	private static final String IV = "iv";
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
	private static final String SECURE_RANDOM = "secure-random";
	private static final String IV_SIZE = "iv-size";

	private static final String SESSION_KEY_GEN_ALGORITHM =  "session-key-gen-alg";
	private static final String SESSION_KEY_SIZE = "session-key-size";
	private static final String OUTTER_MAC_KEY_GEN_ALGORITHM = "outer-mac-key-gen-alg";
	private static final String OUTTER_MAC_KEY_SIZE = "outer-mac-key-size";
	private static final String INNER_MAC_KEY_GEN_ALGORITHM = "inner-mac-key-gen-alg";
	private static final String INNER_MAC_KEY_SIZE = "inner-mac-key-size";
	private static final String USE_HASH = "use-hash";
	private static final String HASH_CIPHER_SUITE = "hash-ciphersuite";
	private static final String TAG_SIZE = "tag-size";


	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv, int tagSize)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);

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

	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv, String provider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {

		if(provider != null) {
			Cipher cipher = Cipher.getInstance(cipherAlgorithm, provider);
			if(iv != null) {
				cipher.init(cipherMode, key, new IvParameterSpec(iv));
			}else
				cipher.init(cipherMode, key);

			return cipher;
		}else 
			return buildCipher(cipherAlgorithm, cipherMode, key, iv);

	}

	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException { 

		Cipher cipher =	Cipher.getInstance(cipherAlgorithm);
		if( iv != null )
			cipher.init(cipherMode, key, new IvParameterSpec(iv));
		else
			cipher.init(cipherMode, key);

		return cipher;
	}

	public static Mac initMac(String macAlgorithm, SecretKey key, String provider) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Mac mac;
		if(provider== null) 
			mac = Mac.getInstance(macAlgorithm);
		else {
			mac = Mac.getInstance(macAlgorithm, provider);
		}
		mac.init(key);
		return mac;
	}

	public static MessageDigest buildHash(String hashAlgorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {

		if(provider==null)
			return MessageDigest.getInstance(hashAlgorithm);
		else {
			return MessageDigest.getInstance(hashAlgorithm, provider);
		}
	}

	public static Cryptography loadFromConfig(String path) throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {

		//Load file
		Properties ciphersuit_properties = loadFile(path);

		//Create Secure Random
		SecureRandom sr = generateRandom(ciphersuit_properties.getProperty(SECURE_RANDOM), ciphersuit_properties.getProperty(SECURE_RANDOM_PROVIDER));

		//load keys
		SecretKey[] keys = loadKeys(ciphersuit_properties.getProperty(KEYSTORE_TYPE), ciphersuit_properties.getProperty(KEYSTORE_PASSWORD),
				ciphersuit_properties.getProperty(KEYSTORE), ciphersuit_properties.getProperty(SESSION_KEY), ciphersuit_properties.getProperty(INNER_MAC_KEY),
				ciphersuit_properties.getProperty(OUTER_MAC_KEY));


		//Generate IV
		String ivString = ciphersuit_properties.getProperty(IV);
		int ivSize = Integer.parseInt(ciphersuit_properties.getProperty(IV_SIZE));
		byte[] iv = null;
		if(ivSize > 0 ) {
			if(ivString != null)
				iv = Utils.unparse(ivString);
			else
				iv = generateIv(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), ivSize, sr);
		}
		//Build encrypt Cipher 
		Cipher encryptCipher = null, decryptCipher = null;
		if (keys[0] != null) {
			encryptCipher = buildCipher(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), Cipher.ENCRYPT_MODE, keys[0], iv, ciphersuit_properties.getProperty(CIPHER_PROVIDER));
			decryptCipher = buildCipher(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), Cipher.DECRYPT_MODE, keys[0], iv, ciphersuit_properties.getProperty(CIPHER_PROVIDER));
		}

		Mac outerMac = null;
		if(ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE)!=null)
			outerMac = initMac(ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE), keys[2], ciphersuit_properties.getProperty(OUTTER_MAC_PROVIDER));

		String hashAlgorithm = ciphersuit_properties.getProperty(HASH_CIPHERSUITE);
		if(hashAlgorithm != null) {
			MessageDigest innerHash = buildHash(hashAlgorithm, ciphersuit_properties.getProperty(HASH_PROVIDER));
			return new CryptographyHash(encryptCipher, decryptCipher,innerHash, outerMac, sr);
		} else {
			Mac innerMac = null;
			if(keys[1] != null && ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE) != null )
				innerMac = initMac(ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE), keys[1], ciphersuit_properties.getProperty(INNER_MAC_PROVIDER));

			return new CryptographyDoubleMac(encryptCipher, decryptCipher, innerMac, outerMac, sr);
		}
	}


	private static byte[] generateIv(String cipherAlgorithm, int size, SecureRandom sr ) {

		byte[] iv = null;
		if(cipherAlgorithm.contains("CTR")) {
			iv = CryptographyUtils.createCtrIvForAES(INITIAL_MSG_NUMBER, sr).getIV();
		} else if( size > 0 ) {
			iv = CryptographyUtils.createGenericIvForAES(size).getIV();
		} else
			iv = new byte[0];

		return iv;
	}

	private static SecureRandom generateRandom(String secureRandomAlgorithm, String provider ) throws NoSuchAlgorithmException, NoSuchProviderException {

		if(provider == null)
			return java.security.SecureRandom.getInstance(secureRandomAlgorithm);
		else {
			System.out.println(SECURE_RANDOM_PROVIDER + ": " + provider);
			return java.security.SecureRandom.getInstance(secureRandomAlgorithm, provider);
		}
	}

	private static Properties loadFile(String path) throws IOException {
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);
		return ciphersuit_properties;
	}

	public byte[] serialize(String path) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

		//Load file
		Properties ciphersuit_properties = loadFile(path);

		//Create Secure Random
		SecureRandom sr = generateRandom(ciphersuit_properties.getProperty(SECURE_RANDOM), ciphersuit_properties.getProperty(SECURE_RANDOM_PROVIDER));

		boolean useHash = Boolean.parseBoolean(ciphersuit_properties.getProperty(USE_HASH));
		SecretKey[] keys = generateKeys(ciphersuit_properties.getProperty(SESSION_KEY_GEN_ALGORITHM), Integer.parseInt(ciphersuit_properties.getProperty(SESSION_KEY_SIZE)),
				ciphersuit_properties.getProperty(OUTTER_MAC_KEY_GEN_ALGORITHM), Integer.parseInt(ciphersuit_properties.getProperty(OUTTER_MAC_KEY_SIZE)),
				ciphersuit_properties.getProperty(INNER_MAC_KEY_GEN_ALGORITHM), Integer.parseInt( ciphersuit_properties.getProperty(INNER_MAC_KEY_SIZE)),
				useHash);


		//Generate IV
		byte[] iv = generateIv(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE), Integer.parseInt(ciphersuit_properties.getProperty(IV_SIZE)), sr);


		// Tag -> GCM
		String aux = ciphersuit_properties.getProperty(TAG_SIZE);
		int tagSize = (aux == null) ? 0 : Integer.parseInt(aux);


		// Hash Suite
		String hashAlgorithm = ciphersuit_properties.getProperty(HASH_CIPHER_SUITE);

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(ciphersuit_properties.getProperty(SECURE_RANDOM));

		dataOut.writeUTF(ciphersuit_properties.getProperty(SESSION_CIPHERSUITE));
		dataOut.writeUTF(ciphersuit_properties.getProperty(SESSION_KEY_GEN_ALGORITHM));
		byte[] session_key_encoded = keys[0].getEncoded();
		dataOut.writeInt(session_key_encoded.length);
		dataOut.write(session_key_encoded, 0, session_key_encoded.length);

		dataOut.writeInt(iv.length);
		dataOut.write(iv, 0, iv.length);

		dataOut.writeInt(tagSize);

		dataOut.writeUTF(ciphersuit_properties.getProperty(OUTER_MAC_CIPHERSUITE));
		dataOut.writeUTF(ciphersuit_properties.getProperty(OUTTER_MAC_KEY_GEN_ALGORITHM));
		byte[] outer_mac_key_encoded = keys[2].getEncoded();
		dataOut.writeInt(outer_mac_key_encoded.length);
		dataOut.write(outer_mac_key_encoded, 0, outer_mac_key_encoded.length);

		dataOut.writeBoolean(useHash);

		if(useHash) {
			dataOut.writeUTF(hashAlgorithm);
		} else {
			dataOut.writeUTF(ciphersuit_properties.getProperty(INNER_MAC_CIPHERSUITE));
			dataOut.writeUTF(ciphersuit_properties.getProperty(INNER_MAC_KEY_GEN_ALGORITHM));
			byte[] inner_mac_key_encoded = keys[1].getEncoded();
			dataOut.writeInt(inner_mac_key_encoded.length);
			dataOut.write(inner_mac_key_encoded, 0, inner_mac_key_encoded.length);
		}

		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return data;
	}


	private static SecretKey[] generateKeys(String session_key_gen_alg, int session_key_size, String outer_key_gen_alg,int outer_mac_key_size, String inner_key_gen_alg, int inner_mac_key_size, boolean useHash ) throws NoSuchAlgorithmException {

		SecretKey ks = CryptographyUtils.generateKey(session_key_gen_alg, session_key_size); // Session key
		SecretKey kms = useHash ? null : CryptographyUtils.generateKey(inner_key_gen_alg, inner_mac_key_size); // inner mac key
		SecretKey kms2 = CryptographyUtils.generateKey(outer_key_gen_alg, outer_mac_key_size); // outer mac key

		return new SecretKey[]{ks, kms, kms2};
	}

	private static SecretKey readKey(KeyStore ks, KeyStore.PasswordProtection ks_pp, String alias) throws
	NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
	CertificateException, FileNotFoundException, IOException {
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(alias, ks_pp);
		return entry.getSecretKey();
	}


	private static SecretKey[] loadKeys(String keyStoreType, String password, String keystore, String sessionKey, String innerMacKey, String outterMacKey) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

		// Load KeyStore
		KeyStore key_store = KeyStore.getInstance(keyStoreType);
		char[] password_arr = password.toCharArray();
		key_store.load(new FileInputStream(keystore), password_arr);
		KeyStore.PasswordProtection  ks_pp = new KeyStore.PasswordProtection(password_arr);

		// Load Keys from KeyStore
		SecretKey ks = null, kim = null, kom = null;
		if(sessionKey != null)
			ks = readKey(key_store, ks_pp, sessionKey);

		if(innerMacKey!= null)
			kim = readKey(key_store, ks_pp, innerMacKey);

		if(outterMacKey!=null)
			kom = readKey(key_store, ks_pp, outterMacKey);

		return new SecretKey[]{ks, kim, kom};
	}

}
