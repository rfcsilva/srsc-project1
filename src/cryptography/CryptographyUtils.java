package cryptography;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptographyUtils {

    /**
     * Criar um IV para usar em AES e modo CTR
     * <p>
     * IV composto por 4 bytes (numero de emensagem)
     * 4 bytes de random e um contador de 8 bytes.
     * 
     * @param messageNumber - Numero da mensagem
     * @param random - source ou seed para random
     * @return Vector IvParameterSpec inicializado
     */
    public static IvParameterSpec createCtrIvForAES(
        int             messageNumber,
        SecureRandom    random)
    {
        byte[]          ivBytes = new byte[16];
        
        // initially randomize
        
        random.nextBytes(ivBytes);
        
        // set the message number bytes
        
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        
        // set the counter bytes to 1
        
        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }
        
        ivBytes[15] = 1;
               
        return new IvParameterSpec(ivBytes);
    }
	
	public static IvParameterSpec createGenericIvForAES(int blockSize) {
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[blockSize];
		randomSecureRandom.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	public static long getNonce() throws NoSuchAlgorithmException {
		
		java.security.SecureRandom sr;

		//TODO: Change Algorithm
		sr = java.security.SecureRandom.getInstance("sha1PRNG");

		int size = Long.BYTES + 1;
		byte[] tmp = new byte[size];
		sr.nextBytes(tmp);

		ByteBuffer buffer = ByteBuffer.wrap(tmp);
		return buffer.getLong();

	}

	public static SecretKey generateKey(String algorithm, int size) throws NoSuchAlgorithmException {
		
		KeyGenerator    generator = KeyGenerator.getInstance(algorithm);
        generator.init(size);
        return generator.generateKey();
		
	}
	
	public static SecretKey deserialize(byte[] keyBytes, String algorithm ) {
		
		return new SecretKeySpec(keyBytes, algorithm);
		
	}
	
}
