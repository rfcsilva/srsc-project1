package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyUtils;
import kdc.KDCServer;
import kdc.UDP_KDC_Server;
import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederServer implements KDCServer {
	
	private static final String PATH_TO_CONFIG = "./configs/proxy/ciphersuite.conf";
	private InetSocketAddress b_addr;
	private Cryptography cryptoManager;
	 
	
	public NeedhamSchroederServer(InetSocketAddress b_addr) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		
		this.b_addr = b_addr;
		cryptoManager = getSessionParameters(); // O que é isto bina?
		
	}

	@Override
	public Cryptography getSessionParameters() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException { // TODO: isto precisa de outo nome
		
		SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, AbstractCryptography.loadFromConfig(PATH_TO_CONFIG));
		inSocket.setTimeout(30*1000);
		
		AtomicBoolean finished = new AtomicBoolean(false);
		ConcurrentHashMap<String, Cryptography> results = new ConcurrentHashMap<>();
		
		while(!finished.get()) {
			try {
			System.out.println("Waitting for Ticket...");
			
			// Receive Ticket
			SecureMessage sm = new SecureMessageImplementation();
			InetSocketAddress addr = inSocket.receive(sm);
			
			NS3 ns3 = (NS3) sm.getPayload();
			
			processRequest(ns3, addr, results, finished);
			} catch(SocketTimeoutException e) {
				
			}
		}
		
		return results.get("session_cryptoManager");
	}
	
	private void processRequest(NS3 ns3, InetSocketAddress addr, ConcurrentHashMap<String, Cryptography> results, AtomicBoolean finished) {
		new Thread(() -> {
			try {
			System.out.println("Received Ticket.");
			
			System.out.println("Sending Challenge...");
			Cryptography session_cryptoManager = UDP_KDC_Server.deserializeSessionParameters(ns3.getKs());
			
			System.out.println(Base64.getEncoder().encodeToString(ns3.getKs()) + " \n"
		     + Base64.getEncoder().encodeToString(ns3.getTicket()));
			
			SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
			new_socket.setTimeout(30*1000);
			
			long Nb = CryptographyUtils.getNonce(session_cryptoManager.getSecureRandom());
			SecureMessage sm = new SecureMessageImplementation(new NS4(Nb, session_cryptoManager));
			new_socket.send(sm, addr);
			System.out.println(Nb);
			
			
			InetSocketAddress addr2 = new_socket.receive(sm);
			System.out.println("Received Challenge answer.");
			
			NS4 ns5 = (NS4) sm.getPayload();
			
			System.out.println(ns5.getNb());
			
			results.put("session_cryptoManager", session_cryptoManager);
			finished.set(true); // TODO: Verificar se o NONCE é válido
			} catch(Exception e) {
				e.printStackTrace();
			}
		}).start();
	}

}
