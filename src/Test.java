import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import cryptography.CryptographyUtils;
import util.ArrayUtils;

public class Test {

	public static void main(String[] args) throws Exception {
		//Cipher cipher =	Cipher.getInstance("AES/ECB/NoPadding");
		/*Cipher cipher =	Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		SecretKey ks = CryptographyUtils.generateKey("AES", 192);
		byte[] iv = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
		
		*//*byte[]		    iv = new byte[] { 
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };*//*
		
		cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
		
		System.out.println(Base64.getEncoder().encodeToString(ks.getEncoded()));
		
		byte[]          input = new byte[] { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
		
		//byte[] plaintext = "Olá".getBytes();
		byte[] plaintext = input;

		/*byte[] plaintext = new byte[16];
		System.arraycopy("Ola".getBytes(), 0, plaintext, 0, "Ola".length());*//*

		//byte[] plaintext = new byte[16];
		//System.arraycopy("Ola".getBytes(), 0, plaintext, 0, "Ola".length());
		
		byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
		cipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		cipher.doFinal();
		
		System.out.println( Base64.getEncoder().encodeToString(cipherText) );
		
		////////////////////////////////////////////////////////////////////
		
		Key	decryptionKey = new SecretKeySpec(ks.getEncoded(), ks.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(iv));
		
		//cipher.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
		
		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
	/*
		
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
		
		System.out.println(MessageDigest.isEqual(length, ArrayUtils.intToByteArray(size)));*/
		
		
		// A utilizacao da classe SecretKeySpec permite criar chaves
		// simetricas, que depois sao passadas para o passo de cifra
		// usando Cipher.init() 
		// Por outro lado atraves da geracao de vectores de inicializacao
		// pode perceber-se que sera possivel gerar chaves simplesmente gerando 
		// um array de bytes random e passando esses bytes a SecretKeySpec
		// Mas um modo mais preferivel em ultima instancia para gerar chaves
		// simetricas consiste em usar a classe KeyGenerator, como se pode
		// discutir com este exemplo.

		        byte[]          input = new byte[] { 
		                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

		        byte[]		    ivBytes = new byte[] { 
		                            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
		                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
		        
		        // Vamos usar AES, modo CTR sem padding com o provedor indicado

		        //Cipher          cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		        //Cipher          cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		        Cipher          cipher = Cipher.getInstance("AES/CCM/NoPadding");
		        
		        Key encryptionKey = CryptographyUtils.generateKey("AES", 192); // Geração de chaves está correta
		        SecureRandom rand = new SecureRandom();
				byte[] nonce = new byte[12];
				rand.nextBytes(nonce);


		        
		        // Cifrar com a chave gerada
		        
		        //cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
		        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(nonce));
		        //cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(128, nonce));
		        //cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
		        
		        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		        ctLength += cipher.doFinal(cipherText, ctLength);
		        //cipher.doFinal();
		        
		        //encryptCipher.update(plaintext, 0, plaintext.length, cipherText, 0);
				//encryptCipher.doFinal();
		        
		        // Decifrar com a chave gerada
		        
		        Key	decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
		        //cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
		        //cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new GCMParameterSpec(128, nonce));
		        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(nonce));
		        
		       // cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
		        
		        byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		        int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
		        ptLength += cipher.doFinal(plainText, ptLength);
		        System.out.println("plain : " + toHex(plainText, ptLength) + " bytes: " + ptLength);
		    }
	
	 private static String	digits = "0123456789abcdef";
	
	 public static String toHex(byte[] data, int length)
	    {
	        StringBuffer	buf = new StringBuffer();
	        
	        for (int i = 0; i != length; i++)
	        {
	            int	v = data[i] & 0xff;
	            
	            buf.append(digits.charAt(v >> 4));
	            buf.append(digits.charAt(v & 0xf));
	        }
	        
	        return buf.toString();
	    }
	    
	    /**
	     * Retorna dados passados como byte array numa string hexadecimal
	     * 
	     * @param data : bytes a serem convertidos
	     * @return : representacao hexadecimal dos dados.
	     */
	    public static String toHex(byte[] data)
	    {
	        return toHex(data, data.length);
	    }

	
}
