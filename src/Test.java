import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import cryptography.CryptographyUtils;
import util.ArrayUtils;

public class Test {

	public static void main(String[] args) throws Exception {
		//Cipher cipher =	Cipher.getInstance("AES/ECB/NoPadding");
		Cipher cipher =	Cipher.getInstance("RC5");
		SecretKey ks = CryptographyUtils.generateKey("AES", 256);
		byte[] iv = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
		
		cipher.init(Cipher.ENCRYPT_MODE, ks/*, new IvParameterSpec(iv)*/);
		
		System.out.println(Base64.getEncoder().encodeToString(ks.getEncoded()));
		System.out.println(Base64.getEncoder().encodeToString(CryptographyUtils.generateKey("AES", 128).getEncoded()));
		
		System.out.println(cipher.getBlockSize());
		
		byte[] plaintext = "Olá".getBytes();
		/*byte[] plaintext = new byte[16];
		System.arraycopy("Ola".getBytes(), 0, plaintext, 0, "Ola".length());*/
		
		byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
		cipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		cipher.doFinal();
		
		System.out.println( Base64.getEncoder().encodeToString(cipherText) );
		
		////////////////////////////////////////////////////////////////////
		
		cipher.init(Cipher.DECRYPT_MODE, ks/*, new IvParameterSpec(iv)*/);
		
		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		
		System.out.println(new String(plainText));
		
		int size = 33;
		
		byte[] length = new byte[0];
		try {
			ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
			DataOutputStream dataOut = new DataOutputStream(byteOut);
			dataOut.writeInt(size);

			dataOut.flush();
			byteOut.flush();

			length = byteOut.toByteArray(); // TODO: renomear de msg para outra coisa

			dataOut.close();
			byteOut.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		System.out.println(MessageDigest.isEqual(length, ArrayUtils.intToByteArray(size)));
		
	}

}
