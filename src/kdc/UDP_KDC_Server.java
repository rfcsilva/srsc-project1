package kdc;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import cryptography.CryptographyUtils;
import kdc.needhamSchroeder.NS1;
import kdc.needhamSchroeder.NeedhamSchroederKDC;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

//TODO: renomear?
public class UDP_KDC_Server {

	public static void main(String[] args) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		if(args.length < 2) {
			System.out.println("usage: kdc <ip> <port>");
		}
		//InputStream inputStream = new FileInputStream("configs/kdc/ciphersuite.conf");
		
		InetSocketAddress my_addr = new InetSocketAddress( args[0], Integer.parseInt(args[1]) );
		
		KDC kdc_server = new NeedhamSchroederKDC(my_addr);
		
		System.out.println("KDC Server ready to receive...");
		
		while(true) {
			// recebe pedidos -> não deveria bloquear infintamente? ou isto lança uma excepção? eu acho que lança ...
			SecureMessage sm = new SecureMessageImplementation();
			InetSocketAddress client_addr = kdc_server.receiveRequest(sm);
			
			String a = new String(((NS1)sm.getPayload()).getA());
			String b = new String(((NS1)sm.getPayload()).getB());
			System.out.println(a + " " + b + " " + ((NS1)sm.getPayload()).getNa());
			
			System.out.println(client_addr.toString());
			
			// gera cenas e faz o mambo
			String path = "./configs/kdc/session-ciphersuite.conf";
			byte[] params = buildSessionParameters(path);
			
			System.out.println(Base64.getEncoder().encodeToString(params));
			
			// TODO: FALTA FAZER DINHEIRO
			
			// envia replys
			kdc_server.sendReply(((NS1)sm.getPayload()), params, client_addr);
		}
	}
	
	private static byte[] buildSessionParameters(String path) throws NoSuchAlgorithmException, IOException { // TODO: passar para outra class ou assim
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);
		
		// Secure Random
		String secureRandomAlgorithm = ciphersuit_properties.getProperty("secure-random");
		
		SecureRandom sr = java.security.SecureRandom.getInstance(secureRandomAlgorithm);
		
		int messageNumber = 1; // TODO : Descobrir o que é isto
		
		// Cipher Suite
		String cipherAlgorithm = ciphersuit_properties.getProperty("session-ciphersuite"); 
		String session_key_gen_alg = ciphersuit_properties.getProperty("session-key-gen-alg"); 
		int session_key_size = Integer.parseInt(ciphersuit_properties.getProperty("session-key-size"));
		SecretKey ks = CryptographyUtils.generateKey(session_key_gen_alg, session_key_size); // Session key
		boolean useIv = Boolean.parseBoolean(ciphersuit_properties.getProperty("use-iv"));
		byte[] iv = useIv ? CryptographyUtils.createCtrIvForAES(messageNumber, sr).getIV() : null; // null?
		
		// Outer Mac Suite
		String outerMacAlgorithm = ciphersuit_properties.getProperty("outer-mac-ciphersuite");
		String outer_key_gen_alg = ciphersuit_properties.getProperty("outer-mac-key-gen-alg");
		int outer_mac_key_size = Integer.parseInt(ciphersuit_properties.getProperty("outer-mac-key-size"));
		SecretKey kms = CryptographyUtils.generateKey(outer_key_gen_alg, outer_mac_key_size); // outer Mac Session Key
		
		boolean useHash = Boolean.parseBoolean(ciphersuit_properties.getProperty("use-hash")); 
		
		// Inner Mac Suite
		String innerMacAlgorithm = ciphersuit_properties.getProperty("inner-mac-ciphersuite");
		String inner_key_gen_alg = ciphersuit_properties.getProperty("inner-mac-key-gen-alg");
		int inner_mac_key_size = Integer.parseInt(ciphersuit_properties.getProperty("inner-mac-key-size"));
		SecretKey kms2 = useHash ? null : CryptographyUtils.generateKey(inner_key_gen_alg, inner_mac_key_size);  // inner Mac Session Key -> ver se é preciso
		
		// Hash Suite
		String hashAlgorithm = ciphersuit_properties.getProperty("hash-ciphersuite");
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeChars(cipherAlgorithm);
		byte[] session_key_encoded = ks.getEncoded();
		dataOut.writeInt(session_key_encoded.length);
		dataOut.write(session_key_encoded, 0, session_key_encoded.length);
		
		dataOut.writeInt(iv.length);
		dataOut.write(iv, 0, iv.length);
		
		dataOut.writeChars(outerMacAlgorithm);
		byte[] outer_mac_key_encoded = kms.getEncoded();
		dataOut.writeInt(outer_mac_key_encoded.length);
		dataOut.write(outer_mac_key_encoded, 0, outer_mac_key_encoded.length);
		
		dataOut.writeBoolean(useHash);
		
		if(useHash) {
			dataOut.writeChars(hashAlgorithm);
		} else {
			dataOut.writeChars(innerMacAlgorithm);
			byte[] inner_mac_key_encoded = kms2.getEncoded();
			dataOut.writeInt(inner_mac_key_encoded.length);
			dataOut.write(inner_mac_key_encoded, 0, inner_mac_key_encoded.length);
		}
		
		dataOut.writeChars(secureRandomAlgorithm);
		
		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray(); // TODO: renomear

		dataOut.close();
		byteOut.close();
		
		return msg;
	}
	
}
