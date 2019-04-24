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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.CryptographyUtils;
import kdc.KDCServer;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;
import stream.UDP_KDC_Server;

public class NeedhamSchroederServer implements KDCServer {

	private static final String PATH_TO_CONFIG = "./configs/proxy/ciphersuite.conf";
	private InetSocketAddress b_addr;

	public NeedhamSchroederServer(InetSocketAddress b_addr) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		this.b_addr = b_addr;
	}

	@Override
	public Cryptography getSessionParameters() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException { // TODO: isto precisa de outo nome

		AtomicReference<Cryptography> cryptoManager = new AtomicReference<>(null);
		AtomicBoolean finished = new AtomicBoolean(false);
		
		// Listen for incoming requests
		listenRequests(finished, cryptoManager);
		
		while(!finished.get()) {
			try {
				Thread.sleep(100); // TODO : quanto tempo?
			} catch(Exception e) {}
		}
		
		return cryptoManager.get();
	}
	
	private void listenRequests(AtomicBoolean finished, AtomicReference<Cryptography> cryptoManager) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, CryptoFactory.loadFromConfig(PATH_TO_CONFIG));
		inSocket.setTimeout(5*1000); // TODO: ISto parece pouco não?

		System.out.println("Waitting for Ticket...");
		
		while(!finished.get()) {
			try {
				// Receive Ticket
				SecureMessage sm = new SecureMessageImplementation();
				InetSocketAddress addr = inSocket.receive(sm);

				System.out.println("Received Ticket.");
				
				NS3 ns3 = (NS3) sm.getPayload();

				processRequest(ns3, addr, cryptoManager, finished);
			} catch(SocketTimeoutException e) {

			}
		}
		
		inSocket.close();
	}

	private void processRequest(NS3 ns3, InetSocketAddress addr, AtomicReference<Cryptography> cryptoManager, AtomicBoolean finished) {
		new Thread(() -> {
			try {
				
				Cryptography session_cryptoManager = UDP_KDC_Server.deserializeSessionParameters(ns3.getKs());

				SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
				new_socket.setTimeout(30*1000); // TODO : quanto timeout?

				long Nb = CryptographyUtils.getNonce(session_cryptoManager.getSecureRandom());
				NS4 ns4 = new NS4(Nb, session_cryptoManager);
				SecureMessage sm = new SecureMessageImplementation(ns4);
				new_socket.send(sm, addr);
				System.out.println("Sending Challenge... " + Nb);
				
				SecureMessage sm2 = new SecureMessageImplementation();
				new_socket.receive(sm2);
				//System.out.println("Received Challenge answer.");

				NS4 ns5 = (NS4) sm2.getPayload();
				
				if(ns5.getNb() == (Nb+1)) {			
					System.out.println("Valid Challenge Answer: " + ns5.getNb());
					cryptoManager.set(session_cryptoManager);
					finished.set(true); // TODO: Verificar se o NONCE é válido
				} else {
					System.err.println("Invalid Challenge Answer: " + ns5.getNb() + " != " + (Nb+1));
				}
				
				new_socket.close();
				
			} catch(Exception e) {
				e.printStackTrace();
			}
		}).start();
	}

}
