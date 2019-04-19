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
	
	public void receive(DatagramPacket p) throws
		IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
	

		socket.receive(p);
		byte[] ciphertext = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] mp = criptoService.decrypt(ciphertext);
		byte[] message = retrieveM(mp);
		p.setData(message);	
		p.setLength(message.length);
	}

	public void send(DatagramPacket p) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
		
		byte[] message = Arrays.copyOfRange(p.getData(), 0, p.getLength());
		byte[] cypherText = buildPayload(0, 0, message);
		p.setData(cypherText);
		p.setLength(cypherText.length);
		socket.send(p);
	}
	
	private byte[] buildPayload(long id, long nonce, byte[] message ) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeLong(id);
		dataOut.writeLong(nonce);
		dataOut.write(message, 0, message.length);
		dataOut.flush();
		byteOut.flush();
		
		//cipher MP
		byte[] Mp = byteOut.toByteArray();
		byte[] cipheredMp = criptoService.encrypt(Mp);
		
		//Append MacDoS
		byte[] macDos = criptoService.computeMacDoS(cipheredMp);
		
		dataOut.close();
		byteOut.close();
		
		return ArrayUtils.concat(cipheredMp, macDos);
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
