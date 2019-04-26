package keyEstablishmentProtocol.needhamSchroeder;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import cryptography.AbstractCryptography;
import cryptography.CryptoFactory;
import cryptography.Cryptography;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import util.Utils;
import util.arKeyStore;

public class CryptographyNS extends AbstractCryptography implements Cryptography {

	private static final String K = "K";
	private static final String KM = "Km";
	private String password;	
	private String macAlgorithm;
	private arKeyStore key_store;
	private byte[] iv;
	private String cipherAlgorithm;
	private String cipherProvider;
	private String outMacProvider;
	
	public CryptographyNS(SecureRandom sr, String password, arKeyStore keyStore ,String macAlgorithm, byte[] iv, String cipherAlgorithm, String cipherProvider, String outerMacProvider) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		super(null, null, null, sr); 
		this.password = password;
		key_store = keyStore;
		this.macAlgorithm = macAlgorithm;
		this.iv = iv;
		this.cipherAlgorithm = cipherAlgorithm;
		this.cipherProvider = cipherProvider;
		this.outMacProvider = outerMacProvider;
	}

	@Override
	public byte[] computeIntegrityProof(byte[] payload) throws InvalidKeyException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validateIntegrityProof(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[][] splitIntegrityProof(byte[] plainText) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
	public AbstractCryptography getCryptographyFromId(String id) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, UnkonwnIdException {
		
		if( !(key_store.contains(KM + id) || key_store.contains(K + id)) )
			throw new UnkonwnIdException(id);
		
		SecretKey km = key_store.getKey(KM + id);
		Mac outerMac = CryptoFactory.initMac(macAlgorithm, km, outMacProvider);
		SecretKey k = key_store.getKey(K + id);
		Cipher encryptCipher = CryptoFactory.buildCipher(cipherAlgorithm, Cipher.ENCRYPT_MODE, k, iv, cipherProvider);
		Cipher decryptCipher = CryptoFactory.buildCipher(cipherAlgorithm, Cipher.DECRYPT_MODE, k, iv, cipherProvider);
		
		return new AbstractCryptography(encryptCipher, decryptCipher, outerMac, this.getSecureRandom()) {
			
			@Override
			public boolean validateIntegrityProof(byte[] message, byte[] expectedMac) throws InvalidKeyException {
				return true;
			}
			
			@Override
			public byte[][] splitIntegrityProof(byte[] plainText) {
				return null;
			}
			
			@Override
			public byte[] computeIntegrityProof(byte[] payload) throws InvalidKeyException {
				return null;
			}
		};
	}
	
	public static CryptographyNS loadFromprops(Properties  props) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		
		SecureRandom sr = CryptoFactory.generateRandom(props.getProperty(CryptoFactory.SECURE_RANDOM), props.getProperty(CryptoFactory.SECURE_RANDOM_PROVIDER));
		String path = props.getProperty(CryptoFactory.KEYSTORE);
		String password = props.getProperty(CryptoFactory.KEYSTORE_PASSWORD);
		String type = props.getProperty(CryptoFactory.KEYSTORE_TYPE);
		String macAlgorithm = props.getProperty(CryptoFactory.OUTER_MAC_CIPHERSUITE);
		String ivString = props.getProperty(CryptoFactory.IV);
		byte[] iv = Utils.unparse(ivString);
		String cipherAlgorithm = props.getProperty(CryptoFactory.SESSION_CIPHERSUITE);
		String cipherProvider = props.getProperty(CryptoFactory.CIPHER_PROVIDER);
		String outerMacProvider = props.getProperty(CryptoFactory.OUTER_MAC_PROVIDER);
		
		//KeyStore keyStore = arKeyStore.loadKeyStore(path, password, type);
		
		arKeyStore keyStore = new arKeyStore(path, password, type);
		return new CryptographyNS(sr, password, keyStore, macAlgorithm, iv, cipherAlgorithm, cipherProvider, outerMacProvider);
		
		
	}
	
}
