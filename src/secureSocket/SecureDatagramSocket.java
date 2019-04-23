package secureSocket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
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
import cryptography.CryptographyDoubleMac;
import cryptography.CryptographyUtils;
import secureSocket.exceptions.*;
import secureSocket.secureMessages.ClearPayload;
import secureSocket.secureMessages.DefaultPayload;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class SecureDatagramSocket {

	private static final long INITIAL_ID  = 0L;
	private static final byte VERSION_RELEASE = 0x01;
	
	private DatagramSocket socket;
	private Cryptography cryptoManager;
	
	public SecureDatagramSocket(int port, InetAddress laddr, Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
		} else {
			socket = new DatagramSocket(port, laddr);
		}
		this.cryptoManager = cryptoManager;
	}

	public SecureDatagramSocket(InetSocketAddress addr, Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress(), cryptoManager);
	}

	public SecureDatagramSocket(Cryptography cryptoManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		socket = new DatagramSocket();
		this.cryptoManager = cryptoManager;
	}

	public void close() throws IOException {
		socket.close();
	}
	
	public void setTimeout(int t) throws SocketException {
		socket.setSoTimeout(t);
	}
	
	// TODO: FAZER OUTRO RCV que RECEBE SecureMessage -> metter setters e retronar o endereço de onde veio
	public InetSocketAddress receive(SecureMessage sm) throws IOException, ShortBufferException, IllegalBlockSizeException,
	BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {

	byte[] buffer = new byte[4 * 1024];
	DatagramPacket p = new DatagramPacket(buffer, buffer.length);
		
	while (true) {
		try {
			socket.receive(p);
			byte[] secureMessageBytes = Arrays.copyOfRange(p.getData(), 0, p.getLength());
			((SecureMessageImplementation)sm).deserialize(secureMessageBytes, cryptoManager);
			break;
		} catch (InvalidMacException | ReplayedNonceException | BrokenIntegrityException  e) {
			System.err.println(e.getMessage());
		}
	} 
	
	return new InetSocketAddress(p.getAddress(), p.getPort());
}
	
	public void receive(DatagramPacket p) throws IOException, ShortBufferException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
		NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {

		byte[] message = null;
		while (true) {
			try {
				socket.receive(p);
				byte[] secureMessageBytes = Arrays.copyOfRange(p.getData(), 0, p.getLength());
				SecureMessage sm = new SecureMessageImplementation(secureMessageBytes, cryptoManager);
				
				message = sm.getPayload().getMessage();
				break;
			} catch (InvalidMacException | ReplayedNonceException | BrokenIntegrityException  e) {
				System.err.println(e.getMessage());
			}
		}
		p.setData(message);
		p.setLength(message.length);
	}
	
	public void send(DatagramPacket p, byte type) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException {
		byte[] message = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		Payload payload = null;
		switch(type) {
		
		case ClearPayload.TYPE:
			payload = new ClearPayload(message, cryptoManager);
			break;
		case DefaultPayload.TYPE:
			payload = new DefaultPayload(INITIAL_ID, CryptographyUtils.getNonce(), message, cryptoManager);
			break;
		default : System.err.println("Unknown Payload Type");
		}
		
		send(p, payload);
	}

	public void send(DatagramPacket p) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException {
		send(p, DefaultPayload.TYPE);
	}
	
	public void send(DatagramPacket p, Payload payload) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		SecureMessage sm = new SecureMessageImplementation(VERSION_RELEASE, payload);
		byte[] secureMessageBytes = sm.serialize();
		p.setData(secureMessageBytes);
		p.setLength(secureMessageBytes.length);
		socket.send(p);
	}
	
	public void send(SecureMessage sm, InetSocketAddress address) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		byte[] secureMessageBytes = sm.serialize();
		DatagramPacket p = new DatagramPacket(secureMessageBytes, 0, secureMessageBytes.length, address);
		socket.send(p);
	}
	
	public InetAddress getLocalAddress() {
		return socket.getLocalAddress();
	}
	
}
