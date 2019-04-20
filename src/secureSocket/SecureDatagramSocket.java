package secureSocket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
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

import Utils.ArrayUtils;
import secureSocket.secureMessages.DefaultPayload;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.secureMessageImplementation;

public class SecureDatagramSocket implements java.io.Closeable {

	private static final long INITIAL_ID  = 0L;
	private static final byte VERSION_RELEASE = 0x01;
	private static DatagramSocket socket;
	private Cryptography criptoService;
	
	public SecureDatagramSocket(int port, InetAddress laddr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
		} else {
			socket = new DatagramSocket(port, laddr);
		}
	
		criptoService = new Cryptography(Cipher.DECRYPT_MODE);
	}


	public SecureDatagramSocket(InetSocketAddress addr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress());
	}

	public SecureDatagramSocket() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		socket = new DatagramSocket();	
		criptoService = new Cryptography(Cipher.ENCRYPT_MODE);
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}
	
	public static void receive(DatagramPacket p) throws
		IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
	
		socket.receive(p);
		byte[] secureMessageBytes = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		SecureMessage sm = new secureMessageImplementation( secureMessageBytes );
		byte[] message = sm.getPayload().getMessage();
		p.setData(message);	
		p.setLength(message.length);
	}

	public static void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		
		byte[] message = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		Payload payload = new DefaultPayload(INITIAL_ID, Utils.Utils.getNonce(), message);
		SecureMessage sm = new secureMessageImplementation(VERSION_RELEASE, payload);
		byte[] secureMessageBytes = sm.getBytes();
		p.setData(secureMessageBytes);
		p.setLength(secureMessageBytes.length);
		socket.send(p);
	}
	
	
	private static byte[] retrieveM(byte[] Mp) throws IOException {
		ByteArrayInputStream byteIn = new ByteArrayInputStream(Mp);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		long id = dataIn.readLong();
		long nonce = dataIn.readLong();
		
		int size = Mp.length - 2 * Long.BYTES;
		byte[] m = new byte[size];
		dataIn.read(m, 0, size);
		
		dataIn.close();
		byteIn.close();
		return m;
	}

	/*
	private static final byte HEADER_SEPARATOR = 0x00;
	
	private static byte[] appendHeader(byte version_release, byte payload_type, short payload_size, byte[] payload) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.write(version_release);
		dataOut.write(HEADER_SEPARATOR);
		dataOut.write(payload_type);
		dataOut.write(HEADER_SEPARATOR);
		dataOut.writeShort(payload_size);
		dataOut.write(payload, 0, payload.length);
		
		dataOut.flush();
		byteOut.flush();
		
		//cipher MP
		byte[] msg = byteOut.toByteArray();
		
		dataOut.close();
		byteOut.close();
		
		return msg;
	}
	*/
	// não sei como ler
	
}
