package secureSocket.cryptography;

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
	
	public byte[] decrypt(byte[] cipherText) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException ;
	
	public byte[] computeMac(byte[] payload) throws InvalidKeyException;
	
	public boolean validateMac(byte[] message, byte[] expectedMac) throws InvalidKeyException;
	
	public byte[] computeIntegrityProof(byte[] payload)  throws InvalidKeyException;
	
	public boolean validateIntegrityProof(byte[] message, byte[] expectedMac) throws InvalidKeyException;

	public byte[][] splitMac(byte[] plainText);

	public byte[][] splitIntegrityProof(byte[] plainText);
	
	public Mac getMac();
}

