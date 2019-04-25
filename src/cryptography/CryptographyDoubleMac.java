package cryptography;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class CryptographyDoubleMac extends AbstractCryptography {
	
	private Mac innerMac;
			
	public CryptographyDoubleMac(Cipher encryptCipher, Cipher decryptCipher, Mac outerMac, Mac innerMac, SecureRandom secureRandom) {
		super(encryptCipher, decryptCipher, outerMac, secureRandom);
		this.innerMac = innerMac;
	}
	
	public Mac getInnerMac() {
		return innerMac;
	}
		
	@Override
	public byte[] computeIntegrityProof(byte[] payload) throws InvalidKeyException {
		return computeMac(innerMac, payload);
	}

	@Override
	public boolean validateIntegrityProof(byte[] message, byte[] expectedMac) throws InvalidKeyException {
		return validateMac(innerMac, message, expectedMac);
	}

	@Override
	public byte[][] splitIntegrityProof(byte[] plainText) {
		return splitMessage(innerMac.getMacLength(), plainText);
	}
		
}

