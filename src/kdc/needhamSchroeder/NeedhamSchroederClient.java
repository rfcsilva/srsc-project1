package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.CryptographyUtils;
import cryptography.nonce.NonceManager;
import cryptography.nonce.WindowNonceManager;
import kdc.KDCClient;
import kdc.needhamSchroeder.exceptions.InvalidChallangeReplyException;
import kdc.needhamSchroeder.exceptions.TooManyTriesException;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;
import stream.UDP_KDC_Server;

public class NeedhamSchroederClient implements KDCClient {

	private static final int TIMEOUT = 30*1000;

	private static final int WINDOW_SIZE = 100;
	
	private Cryptography master_cryptoManager;
	private InetSocketAddress kdc_addr;
	private String a;

	private int max_tries = 3;

	public NeedhamSchroederClient(InetSocketAddress kdc_addr, String a, Cryptography master_cryptoManager) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		this.kdc_addr = kdc_addr;
		this.master_cryptoManager = master_cryptoManager;
		this.a = a;
	}

	public void setMaxTries(int tries) {
		this.max_tries = tries;
	}
	
	@Override
	public Cryptography getSessionParameters(String b, InetSocketAddress b_addr) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, TooManyTriesException {

		NonceManager nonceManager = new WindowNonceManager(WINDOW_SIZE, master_cryptoManager.getSecureRandom());

		for(int i=0; i < max_tries; i++) {
			try {
				long Na = nonceManager.generateNonce();

				NS2 kdc_reply = requestKeys(kdc_addr, Na, nonceManager, a, b);

				// Build the session cryptoManager
				Cryptography session_cryptoManager =  CryptoFactory.deserialize(kdc_reply.getKs()); //UDP_KDC_Server.deserializeSessionParameters(kdc_reply.getKs()); //TODO : Trocar para o método certo

				shareKeys(b_addr, kdc_reply.getTicket(), session_cryptoManager, nonceManager);

				System.out.println("Finished key establishment.");

				return session_cryptoManager;
			} catch (SocketTimeoutException e) {
				// Try again
			} catch (ReplayedNonceException e) {
				System.err.println(e.getMessage());
			} catch (InvalidChallangeReplyException e) {
				System.err.println(e.getMessage());
			}
		}

		throw new TooManyTriesException("" + max_tries);
	}

	private NS2 requestKeys(InetSocketAddress kdc_addr, long Na, NonceManager nonceManager, String a, String b) throws IOException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, ReplayedNonceException {
		try {
			SecureDatagramSocket socket = new SecureDatagramSocket(master_cryptoManager);
			socket.setTimeout(TIMEOUT); // 30 s -> passar a constante

			//TODO: Change ID and load IDs from a config file
			//Payload ns1 = new NS1("a".getBytes(), "b".getBytes(), Na, master_cryptoManager); // TODO: Isto não pode estar martelado
			
			System.out.println("Requesting keys... " + Na);
			Payload ns1 = new NS1(a, b, Na, master_cryptoManager); 
			SecureMessage sm = new SecureMessageImplementation(ns1);
			socket.send(sm, kdc_addr);

			// Receive reply from KDC
			socket.receive(sm); // TODO: comparar os IPs de onde enviei e de onde veio?

			NS2 reply = (NS2) sm.getPayload();

			if( nonceManager.verifyReplay(reply.getNc()) ) {
				throw new ReplayedNonceException("KDC nonce (Nc) was replayed: " + reply.getNc());
			} else if(reply.getNa_1() != Na+1) {
				throw new InvalidChallangeReplyException("KDC challenge answer is wrong. " + reply.getNa_1());
			} else
				System.out.println("Received Keys. " + (Na+1));
			
			return reply;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}  

	private void shareKeys(InetSocketAddress b_addr, byte[] ticket, Cryptography session_cryptoManager, NonceManager nonceManager) throws IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, ReplayedNonceException {
		try {
			SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
			new_socket.setTimeout(TIMEOUT);

			Payload ns3 = new NS3(ticket, session_cryptoManager);

			System.out.println("Sending Ticket to B ...");
			SecureMessage sm = new SecureMessageImplementation(ns3);
			new_socket.send(sm, b_addr);

			// Receive Challenge
			sm = new SecureMessageImplementation();
			InetSocketAddress addr = new_socket.receive(sm); // TODO: trocar a função de Na+1 e assim para uma chamada a uma funçção challenge que pode ter difenets implemneações
			long Nb =((NS4)sm.getPayload()).getNb();

			System.out.println("Received Challenge. " + Nb);

			if(nonceManager.verifyReplay(Nb)) {
				// Compute Reply
				long Nb_1 = (Nb + 1);

				// Update last seen nonce
				nonceManager.verifyReplay(Nb_1);

				System.out.println("Sending Challenge result ... " + Nb_1);
				NS4 ns4 = new NS4(Nb_1, session_cryptoManager);
				sm = new SecureMessageImplementation(ns4);
				new_socket.send(sm, addr);
			} else {
				throw new ReplayedNonceException("B challenge was replayed: " + Nb);
			}
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

