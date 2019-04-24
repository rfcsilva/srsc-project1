package cryptography;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

public abstract class AbstractCryptography implements Cryptography {

	private Cipher encryptCipher;
	private Cipher decryptCipher;
	private Mac outerMac;
	private SecureRandom secureRandom;


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
	public Mac getOuterMac() {
		return outerMac;
	}
	
	@Override
	public SecureRandom getSecureRandom() {
		return secureRandom;
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
	public byte[][] splitOuterMac(byte[] plainText){
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