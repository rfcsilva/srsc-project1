package cryptography;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateException;

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
	
	public static long getNonce(SecureRandom sr) throws NoSuchAlgorithmException {
		int size = Long.BYTES + 1;
		byte[] tmp = new byte[size];
		sr.nextBytes(tmp);

		ByteBuffer buffer = ByteBuffer.wrap(tmp);
		return buffer.getLong();
	}
	
	
	// TODO: Substituir este nonce pelo de cima
	public static long getNonce() throws NoSuchAlgorithmException {
		
		SecureRandom sr = SecureRandom.getInstance("sha1PRNG");
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
	
	public static KeyStore loadKeyStrore(String path, String password, String keyStore_type) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		KeyStore key_store = KeyStore.getInstance(keyStore_type);
		key_store.load(new FileInputStream(path), password.toCharArray());
		return key_store;
	}
	
	public static SecretKey getKey(KeyStore ks, String password, String alias) throws
	NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
	CertificateException, FileNotFoundException, IOException {
		KeyStore.PasswordProtection  ks_pp = new KeyStore.PasswordProtection(password.toCharArray());
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(alias, ks_pp);
		return entry.getSecretKey();
	}
	
}
