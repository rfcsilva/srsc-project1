package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

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
		
		System.out.println("Waitting for Ticket...");
		
		// Receive Ticket
		SecureMessage sm = new SecureMessageImplementation();
		InetSocketAddress addr = inSocket.receive(sm);
		
		NS3 ns3 = (NS3) sm.getPayload();
		
		System.out.println("Received Ticket.");
		
		System.out.println("Sending Challenge...");
		Cryptography session_cryptoManager = UDP_KDC_Server.deserializeSessionParameters(ns3.getKs());
		inSocket.setCryptoManager(session_cryptoManager);
		long Nb = CryptographyUtils.getNonce(session_cryptoManager.getSecureRandom());
		sm = new SecureMessageImplementation(new NS4(Nb, session_cryptoManager));
		inSocket.send(sm, addr);
		System.out.println(Nb);
		
		System.out.println("Received Challenge answer.");
		addr = inSocket.receive(sm);
		
		NS4 ns5 = (NS4) sm.getPayload();
		
		System.out.println(ns5.getNb());
		
		return session_cryptoManager;
	}
	
	

}
