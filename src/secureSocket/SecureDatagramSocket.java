package secureSocket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import cryptography.nonce.CounterNonceManager;
import cryptography.nonce.NonceManager;
import secureSocket.exceptions.*;
import secureSocket.secureMessages.DefaultPayload;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class SecureDatagramSocket {

	private static final long INITIAL_ID  = 1L;
	
	private DatagramSocket socket;
	private Cryptography cryptoManager;
	private NonceManager nonceManager;
	
	public SecureDatagramSocket(int port, InetAddress laddr, Cryptography cryptoManager, NonceManager nonceManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
		} else {
			socket = new DatagramSocket(port, laddr);
		}
		this.cryptoManager = cryptoManager;
		this.nonceManager = nonceManager;
	}
	
	public SecureDatagramSocket(int port, InetAddress inAddr, Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(port, inAddr, cryptoManager, new CounterNonceManager());
	}
	
	public SecureDatagramSocket(InetSocketAddress addr, Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress(), cryptoManager);
	}
	
	public SecureDatagramSocket(InetSocketAddress addr, Cryptography cryptoManager, NonceManager nonceManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress(), cryptoManager, nonceManager);
	}

	public SecureDatagramSocket(Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(cryptoManager, new CounterNonceManager());
	}
	
	public SecureDatagramSocket(Cryptography cryptoManager, NonceManager nonceManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		socket = new DatagramSocket();
		this.cryptoManager = cryptoManager;
		this.nonceManager = nonceManager;

	}
	public void close() throws IOException {
		socket.close();
	}
	
	public void receive(DatagramPacket p) throws IOException, ShortBufferException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
		NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidPayloadTypeException {

		byte[] message = null;
		while (true) {
			try {
				socket.receive(p);
				byte[] secureMessageBytes = Arrays.copyOfRange(p.getData(), 0, p.getLength());
				SecureMessage sm = new SecureMessageImplementation(secureMessageBytes, cryptoManager, nonceManager); // TODO: isto não deveria ser um método estático?
				
				message = sm.getPayload().getMessage();
				break;
			} catch (InvalidMacException | ReplayedNonceException e) {
				System.err.println(e.getMessage());
			}
		}
		p.setData(message);
		p.setLength(message.length);
	}

	public void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		byte[] message = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		Payload payload = new DefaultPayload(INITIAL_ID, nonceManager.getNonce(), message, cryptoManager);
		SecureMessage sm = new SecureMessageImplementation(payload);
		byte[] secureMessageBytes = sm.serialize();
		p.setData(secureMessageBytes);
		p.setLength(secureMessageBytes.length);
		socket.send(p);
	}
}
