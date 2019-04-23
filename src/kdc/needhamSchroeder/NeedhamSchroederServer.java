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
import kdc.KDCServer;
import secureSocket.SecureDatagramSocket;

public class NeedhamSchroederServer implements KDCServer {
	
	private static final String PATH_TO_CONFIG = "./configs/server/ciphersuite.conf";
	private InetSocketAddress b_addr;
	private Cryptography cryptoManager;
	 
	
	public NeedhamSchroederServer(InetSocketAddress b_addr) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		
		this.b_addr = b_addr;
		cryptoManager = getSessionParameters();
		
	}

	@Override
	public Cryptography getSessionParameters() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException { // TODO: isto precisa de outo nome
		
		SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, AbstractCryptography.loadFromConfig(PATH_TO_CONFIG, Cipher.DECRYPT_MODE));
		NS3 keys = inSocket.receive();
		System.out.println("Ks: " + keys.getKs());
		return keys.getSessionCryptoManager(); 
	}
	
	

}
