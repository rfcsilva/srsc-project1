package cryptography;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

/**
 * Encapsulates several cryptography primitives: an encrypt cipher, a decrypt
 * cipher (with the same parameters), an outer MAC and an additional integrity
 * proof that can be either a MAC or an HASH
 */
public interface Cryptography {

	/**
	 * @return the encrypt cipher object
	 */
	public Cipher getEncryptCipher();

	/**
	 * @return the decrypt cipher object
	 */
	public Cipher getDecryptCipher();

	/**
	 * @return outer MAC object
	 */
	public Mac getOuterMac();

	/**
	 * @return secure random object
	 */
	public SecureRandom getSecureRandom();

	/**
	 * encrypts the plain text using the encrypt cipher
	 * 
	 * @return the encrypted cipher text
	 */
	public byte[] encrypt(byte[] plainText) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
	InvalidAlgorithmParameterException, ShortBufferException;

	/**
	 * decrypts the cipher text using the decrypt cipher
	 * 
	 * @return the encrypted cipher text
	 */
	public byte[] decrypt(byte[] cipherText)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException;

	/**
	 * computes the MAC for payload using the outerMac configurations
	 * 
	 * @return the computed MAC
	 */
	public byte[] computeOuterMac(byte[] message) throws InvalidKeyException;

	/**
	 * validates the MAC for message, comparing with expectedMac, using the outerMac
	 * configurations
	 * 
	 * @return true if the MAC is valid or false otherwise
	 */
	public boolean validateOuterMac(byte[] message, byte[] expectedMac) throws InvalidKeyException;

	/**
	 * computes an integrity proof, either a MAC or an HASH, depending on the
	 * underlying implementation
	 * 
	 * @return the computed integrity proof
	 */
	public byte[] computeIntegrityProof(byte[] message) throws InvalidKeyException;

	/**
	 * validates the integrity proof for message, comparing with expected
	 * 
	 * @return true if the integrity proof is valid or false otherwise
	 */
	public boolean validateIntegrityProof(byte[] message, byte[] expected) throws InvalidKeyException;

	/**
	 * splits the outer MAC from the message
	 * 
	 * @return an array of byte[], where the first corresponds to the message and
	 *         the second to the MAC
	 */
	public byte[][] splitOuterMac(byte[] messageWithMac);

	/**
	 * splits the integrity proof from the message
	 * 
	 * @return an array of byte[], where the first corresponds to the message and
	 *         the second to the integrity proof
	 */
	public byte[][] splitIntegrityProof(byte[] message);

}
