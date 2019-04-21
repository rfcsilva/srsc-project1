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

public class CryptographyHash extends AbstractCryptography {

	private Mac outerMac;
	private MessageDigest innerHash;
	
	
	
	//TODO: handle exceptions gracefully
	
	public CryptographyHash(Cipher cipher, MessageDigest innerHash, Mac outerMac) {
		super(cipher, outerMac);
		this.innerHash = innerHash;
		this.outerMac = outerMac;
	}

	public MessageDigest getInnerHash() {
		return innerHash;
	}

	public Mac getOuterMac() {
		return outerMac;
	}

	public byte[] computeInnerHash(byte[] payload) {
		innerHash.update(payload);
		return innerHash.digest();
	}
	
	public boolean validadeInnerHash(byte[] message, byte[] expectedHash) throws InvalidKeyException {
		byte[] h = computeInnerHash(message);
		return MessageDigest.isEqual(h, expectedHash);
	}
	
	public byte[][] splitInnerHash(byte[] plainText){
		return splitMessage(innerHash.getDigestLength(), plainText);
	}
	
}
