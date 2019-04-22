import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import cryptography.CryptographyUtils;

public class Test {

	public static void main(String[] args) throws Exception {
		Cipher cipher =	Cipher.getInstance("AES/ECB/NoPadding");
		SecretKey ks = CryptographyUtils.generateKey("AES", 256);
		cipher.init(Cipher.ENCRYPT_MODE, ks);
		
		System.out.println(Base64.getEncoder().encodeToString(ks.getEncoded()));
		System.out.println(Base64.getEncoder().encodeToString(CryptographyUtils.generateKey("AES", 128).getEncoded()));
		
		System.out.println(cipher.getBlockSize());
		
		//byte[] plaintext = "Olá".getBytes();
		byte[] plaintext = new byte[16];
		System.arraycopy("Ola".getBytes(), 0, plaintext, 0, "Ola".length());
		
		byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
		cipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		cipher.doFinal();
		
		System.out.println( Base64.getEncoder().encodeToString(cipherText) );
		
		////////////////////////////////////////////////////////////////////
		
		cipher.init(Cipher.DECRYPT_MODE, ks);
		
		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		
		System.out.println(new String(plainText));
	}

}
