package secureSocket;

import java.io.ByteArrayOutputStream;
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
		byte[] payload = criptoService.decrypt(ciphertext);
		p.setData(payload);	
		p.setLength(payload.length);
	}

	public void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
		
		byte[] plaintext = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] cypherText = criptoService.encrypt(plaintext);
		p.setData(cypherText);
		p.setLength(cypherText.length);
		socket.send(p);
	}
	
	private static byte[] buildMp(long id, long nonce, byte[] message ) throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		ObjectOutputStream dataOut = new ObjectOutputStream(byteOut);
		
		dataOut.writeLong(id);
		dataOut.writeLong(nonce);
		dataOut.write(message, 0, message.length);
		
		// Colocar logo aqui o Mac
		
		// Depois cifrar tudo logo aqui
		
		// Depois fazer append do mac final aqui também ?
		
		dataOut.flush();
		byteOut.flush();
		return byteOut.toByteArray();
	}
}
