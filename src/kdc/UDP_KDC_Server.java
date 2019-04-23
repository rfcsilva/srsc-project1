package kdc;

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
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

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
			SocketAddress client_addr = kdc_server.receiveRequest(sm);
			
			String a = new String(((NS1)sm.getPayload()).getA());
			String b = new String(((NS1)sm.getPayload()).getB());
			System.out.println(a + " " + b + " " + ((NS1)sm.getPayload()).getNa());
			
			System.out.println(client_addr.toString());
			
			// gera cenas e faz o mambo
			String cipherAlgorithm = ""; 
			String outerMacAlgorithm = "";
			String innerIntegrityProofAlgorithm = "";
			boolean useHash = false; 
			SecretKey ks = CryptographyUtils.generateKey(algorithm, size); // Session key
			SecretKey kms = CryptographyUtils.generateKey(algorithm, size); // outer Mac Session Key
			SecretKey kms2 = CryptographyUtils.generateKey(algorithm, size); // inner Mac Session Key -> ver se é preciso
			byte[] iv = CryptographyUtils.createCtrIvForAES(messageNumber, random); // ver se é preciso?
			String aux = ""; // cenas sobre o dinheiro virtual
			
			// envia replys
			kdc_server.sendReply();
		}
	}
	
}
