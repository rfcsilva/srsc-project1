package cryptography;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class CryptographyNS extends AbstractCryptography implements Cryptography {

	public CryptographyNS(Cipher encryptCipher, Cipher decryptCipher, Mac outerMac, SecureRandom sr) {
		super(encryptCipher, decryptCipher, outerMac, sr);
		// TODO Auto-generated constructor stub
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

}
