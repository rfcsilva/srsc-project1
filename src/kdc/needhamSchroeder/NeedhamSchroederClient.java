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
import kdc.UDP_KDC_Server;
import kdc.needhamSchroeder.exceptions.InvalidChallangeReplyException;
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
		cryptoManager = AbstractCryptography.loadFromConfig(PATH_TO_CONFIG);
		socket = new SecureDatagramSocket(cryptoManager);
	}
	
	private int max_tries = 3;
	
	private static final int TIMEOUT = 30*1000;
	
	@Override
	public Cryptography getSessionParameters() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidChallangeReplyException {
		
		
		
		for(int i=0; i < max_tries; i++) { // TODO: se algum nonce for replay ou mau, repetir?
		    try {
		    	long Na = CryptographyUtils.getNonce();
		    	
		    	System.out.println("Requesting keys...");
				NS2 kdc_reply = requestKeys(kdc_addr, Na);
				System.out.println("Received Keys.");
				
				// Build a criptoManager
				Cryptography session_cryptoManager = UDP_KDC_Server.deserializeSessionParameters(kdc_reply.getKs());
				
				System.out.println("Sharing keys...");
				shareKeys(b_addr, kdc_reply.getTicket(), session_cryptoManager);
				
				System.out.println("Finished key establishment.");
				
				return cryptoManager;
		    } catch (SocketTimeoutException e) {
		        // Try again
		    }
		}
		
		// TODO: Too many tries -> O que fazer?
		
		return null;
	}
	
	private NS2 requestKeys(InetSocketAddress kdc_addr, long Na) throws IOException, InvalidChallangeReplyException {
		try {
			SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
			socket.setTimeout(TIMEOUT); // 30 s -> passar a constante
						
			//TODO: Change ID and load IDs from a config file
			Payload ns1 = new NS1("a".getBytes(), "b".getBytes(), Na, cryptoManager);
			SecureMessage sm = new SecureMessageImplementation(ns1);
			socket.send(sm, kdc_addr);
			
			// Receive reply from KDC
			socket.receive(sm); // TODO: comparar os IPs de onde enviei e de onde veio?
			
			NS2 reply = (NS2) sm.getPayload();
			
			if(reply.getNa_1() != Na+1) throw new InvalidChallangeReplyException("Na recieved diffent from the expected.");
			
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
	
	private void shareKeys(InetSocketAddress b_addr, byte[] ticket, Cryptography session_cryptoManager) throws IOException {
		try {
			SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
			new_socket.setTimeout(TIMEOUT);
			
			Payload ns3 = new NS3(ticket, session_cryptoManager);
			
			System.out.println("Sending Ticket to B ...");
			SecureMessage sm = new SecureMessageImplementation(ns3);
			new_socket.send(sm, b_addr);
			
			// Receive Challenge
			InetSocketAddress addr = new_socket.receive(sm); // TODO: trocar a função de Na+1 e assim para uma chamada a uma funçção challenge que pode ter difenets implemneações
			System.out.println("Received Challenge.");
			
			NS4 ns4 = ((NS4)sm.getPayload());
			long Nb_1 = ns4.getNb() + 1;
			
			System.out.println("Sending Challenge result ...");
			ns4 = new NS4(Nb_1, session_cryptoManager);
			sm = new SecureMessageImplementation(ns4);
			new_socket.send(sm, addr);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}  
	
	// KDC Client returns CriptoMananger
	// Alterar construtor do SecureSocket para receber CriptoManager

	// A -> KDC : A, B, Na
	// KDC -> A : {Na+1, Nc, Ks , B, { {Nc, A, B, Ks}KB, MacTiket Kb}  }KA + MAC Ka	 
	
	// A -> B : {Nc, A, B, Ks }KB
	// B -> A : {Nb }Ks
	// A -> B : {Nb+1 }Ks
		
}

