package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyUtils;
import kdc.KDCClient;
import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.ClearPayload;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;


public class NeedhamSchroederClient implements KDCClient {
	
	private static final String PATH_TO_CONFIG = "./configs/server/ciphersuite.conf";
	
	private Cryptography cryptoManager;
	private InetSocketAddress kdc_addr;
	private InetSocketAddress b_addr;
	private SecureDatagramSocket socket;
	
	public NeedhamSchroederClient(InetSocketAddress kdc_addr, InetSocketAddress b_addr) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		this.kdc_addr = kdc_addr;
		this.b_addr = b_addr;
		cryptoManager = AbstractCryptography.loadFromConfig(PATH_TO_CONFIG, Cipher.ENCRYPT_MODE);
		socket = new SecureDatagramSocket(cryptoManager);
	}
	
	private int max_tries = 3;
	
	@Override
	public Cryptography getSessionParameters() throws NoSuchAlgorithmException, IOException {
		
		socket.setTimeout(30*1000); // 30 s -> passar a constante
		
		for(int i=0; i < max_tries; i++) {
		    try {
		    	long Na = CryptographyUtils.getNonce();
		    	
		    	System.out.println("Requesting keys...");
				NS2 kdc_reply = requestKeys(kdc_addr, Na);
				
				System.out.println("Sharing keys...");
				shareKeys(b_addr, kdc_reply);
				
				// TODO: Falta o resto         
				
				return null;
		    } catch (SocketTimeoutException e) {
		        // Try again
		    }
		}
		
		// TODO: Too many tries -> O que fazer?
		
		return null;
	}
	
	private NS2 requestKeys(InetSocketAddress kdc_addr, long Na) throws IOException {
		try {
						
			//SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
			byte[] buff = new byte[65000];
			DatagramPacket p = new DatagramPacket(buff, buff.length, kdc_addr );
			
			/*Payload ns1 = new NS1(socket.getLocalAddress().getAddress(),
					b_addr.getAddress().getAddress(), Na, cryptoManager);*/
			
			//TODO: Change ID and load IDs from a config file
			Payload ns1 = new NS1("a".getBytes(), "b".getBytes(), Na, cryptoManager);

			socket.send(p, ns1);
			
			// Receive reply from KDC
			SecureMessage sm = new SecureMessageImplementation();
			socket.receive(sm); // TODO: comparar os IPs de onde enviei e de onde veio?
			
			NS2 reply = (NS2) sm.getPayload();
			
			System.out.println(reply.getNa_1() + " "
						     + reply.getNc() + " "
						     + new String(reply.getB())  + " \n"
						     + Base64.getEncoder().encodeToString(reply.getKs()) + " \n"
						     + Base64.getEncoder().encodeToString(reply.getTicket()));
			
			// Receive reply from KDC
			/*socket.receive(p);
			byte[] reply = Arrays.copyOfRange(p.getData(), 0, p.getLength());
			
			// TODO : como fazer deserialize?
			System.out.println(new String(reply)); // temp*/
			
			return reply;
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}  
	
	private void shareKeys(InetSocketAddress b_addr, NS2 kdc_reply) {
		try {
			
			
			
			
			// Trocar este cryptoManager pelo crytpo manager que é construído no métod anteiroro para usar a chave dos macs definida pelo kdc uma vez que o a não partilha nenhuma chave com o b e depois nem o a nem o b conseguem validar as merdas.
			
			/*SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
			byte[] buff = new byte[65000];
			DatagramPacket p = new DatagramPacket(buff, buff.length, b_addr );
			
			//byte[] request = "To Chaves!".getBytes();
			
			p.setData(keys, 0, keys.length );
			p.setSocketAddress( b_addr );
			socket.send(p, ClearPayload.TYPE);*/
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IOException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}  
	
	// KDC Client returns CriptoMananger
	// Alterar construtor do SecureSocket para receber CriptoManager

	// A -> KDC : A, B, Na
	// KDC -> A : {Na+1, Nc, Ks , B, {Nc, A, B, Ks}KB }KA 
	
	// A -> B : {Nc, A, B, Ks }KB
	// B -> A : {Nb }Ks
	// A -> B : {Nb+1 }Ks
		
}
