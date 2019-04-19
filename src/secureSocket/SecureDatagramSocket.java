package secureSocket;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class SecureDatagramSocket implements java.io.Closeable {

	private DatagramSocket socket;
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

	public void receive(DatagramPacket p) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		socket.receive(p);
		byte[] ciphertext = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] payload = criptoService.decryptSecurePacket(ciphertext);
		p.setData(payload);
		p.setLength(payload.length);
	}

	public void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		byte[] plaintext = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] cypherText = criptoService.encryptSecurePacket(plaintext);
		p.setData(cypherText);
		p.setLength(cypherText.length);
		socket.send(p);
	}

}
