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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import secureSocket.exceptions.*;
import secureSocket.secureMessages.DefaultPayload;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.secureMessageImplementation;
import util.Utils;

public class SecureDatagramSocket {
	
	private static final String CIPHERSUITE_CONFIG_PATH = "configs/server/ciphersuite.conf";

	private static final long INITIAL_ID  = 0L;
	private static final byte VERSION_RELEASE = 0x01;
	private DatagramSocket socket;
	private Cryptography cryptoManager;
	
	public SecureDatagramSocket(int port, InetAddress laddr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
			cryptoManager = Cryptography.loadFromConfig(CIPHERSUITE_CONFIG_PATH, Cipher.DECRYPT_MODE);
		} else {
			socket = new DatagramSocket(port, laddr);
			cryptoManager = Cryptography.loadFromConfig(CIPHERSUITE_CONFIG_PATH, Cipher.DECRYPT_MODE);
		}
	}

	public SecureDatagramSocket(InetSocketAddress addr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress());
	}

	public SecureDatagramSocket() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		socket = new DatagramSocket();
		cryptoManager = Cryptography.loadFromConfig(CIPHERSUITE_CONFIG_PATH, Cipher.ENCRYPT_MODE);
	}

	public void close() throws IOException {
		socket.close();
	}
	
	public void receive(DatagramPacket p) throws IOException, ShortBufferException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
		NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {

		byte[] message = null;
		while (true) {
			try {
				socket.receive(p);
				byte[] secureMessageBytes = Arrays.copyOfRange(p.getData(), 0, p.getLength());
				SecureMessage sm = new secureMessageImplementation(secureMessageBytes, cryptoManager);
				
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
		Payload payload = new DefaultPayload(INITIAL_ID, Utils.getNonce(), message, cryptoManager);
		SecureMessage sm = new secureMessageImplementation(VERSION_RELEASE, payload);
		byte[] secureMessageBytes = sm.serialize();
		p.setData(secureMessageBytes);
		p.setLength(secureMessageBytes.length);
		socket.send(p);
	}
}
