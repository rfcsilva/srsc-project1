package cryptography;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

public interface Cryptography {

	public Cipher getCipher();
	
	public byte[] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException;
	
	public byte[] decrypt(byte[] cipherText) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException;
	
	public byte[] computeOuterMac(byte[] payload) throws InvalidKeyException;
	
	public boolean validateOuterMac(byte[] message, byte[] expectedMac) throws InvalidKeyException;
	
	public byte[] computeIntegrityProof(byte[] payload) throws InvalidKeyException;
	
	public boolean validateIntegrityProof(byte[] message, byte[] expected) throws InvalidKeyException;

	public byte[][] splitOuterMac(byte[] plainText);

	public byte[][] splitIntegrityProof(byte[] plainText);
	
	public Mac getOuterMac();
}

