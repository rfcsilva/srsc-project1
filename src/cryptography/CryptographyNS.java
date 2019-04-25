package cryptography;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CryptographyNS extends AbstractCryptography implements Cryptography {

	private static final String K = "K";
	private static final String KM = "Km";
	private String password;	
	private String macAlgorithm;
	private KeyStore key_store;
	private byte[] iv;
	private String cipherAlgorithm;
	
	public CryptographyNS(SecureRandom sr, String password, KeyStore keyStore ,String macAlgorithm, byte[] iv, String cipherAlgorithm) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		super(null, null, null, sr);
		this.password = password;
		key_store = keyStore;
		this.macAlgorithm = macAlgorithm;
		this.iv = iv;
		this.cipherAlgorithm = cipherAlgorithm;
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
	
	
	public AbstractCryptography getCryptographyFromId(String id) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		SecretKey km = CryptographyUtils.getKey(key_store, password, KM + id);
		Mac outerMac = CryptoFactory.buildMac(macAlgorithm, km);
		SecretKey ka = CryptographyUtils.getKey(key_store, password, K + id);
		Cipher encryptCipher = CryptoFactory.buildCipher(cipherAlgorithm, Cipher.ENCRYPT_MODE, ka, iv);
		Cipher decryptCipher = CryptoFactory.buildCipher(cipherAlgorithm, Cipher.DECRYPT_MODE, ka, iv);
		
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
	

}
