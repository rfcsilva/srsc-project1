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

public class SecureDatagramSocket implements java.io.Closeable {

	private DatagramSocket socket;
	private Cryptography criptoService;
	private int nonce;
	
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

	public void receive(DatagramPacket p) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		socket.receive(p);
		byte[] ciphertext = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] mp = criptoService.decrypt(ciphertext);
		byte[] message = retrieveM(mp);
		p.setData(message);	
		p.setLength(message.length);
	}

	public void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
		
		byte[] message = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] mp = buildMp(0, 0, message);
		byte[] cypherText = criptoService.encrypt(mp);
		p.setData(cypherText);
		p.setLength(cypherText.length);
		socket.send(p);
	}
	
	private static byte[] buildMp(long id, long nonce, byte[] message ) throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeLong(id);
		dataOut.writeLong(nonce);
		dataOut.write(message, 0, message.length);
		
		// Colocar logo aqui o Mac
		
		// Depois cifrar tudo logo aqui
		
		// Depois fazer append do mac final aqui também ?
		
		dataOut.flush();
		byteOut.flush();
		
		byte[] Mp = byteOut.toByteArray();
		
		dataOut.close();
		byteOut.close();
		
		return Mp;
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
}
