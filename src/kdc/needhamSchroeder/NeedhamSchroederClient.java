package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
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
import kdc.KDCClient;
import kdc.KDCReply;
import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.ClearPayload;
import secureSocket.secureMessages.Payload;


public class NeedhamSchroederClient implements KDCClient {
	
	private static final String PATH_TO_CONFIG = "./configs/server/ciphersuite.conf";
	
	private Cryptography cryptoManager;
	private InetSocketAddress kdc_addr;
	private InetSocketAddress b_addr;
	
	public NeedhamSchroederClient(InetSocketAddress kdc_addr, InetSocketAddress b_addr) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		this.kdc_addr = kdc_addr;
		this.b_addr = b_addr;
		cryptoManager = AbstractCryptography.loadFromConfig(PATH_TO_CONFIG, Cipher.ENCRYPT_MODE);
	}
	
	@Override
	public KDCReply getSessionParameters() {
		
		System.out.println("Requesting keys...");
		byte[] keys = requestKeys(kdc_addr);
		
		System.out.println("Sharing keys...");
		shareKeys(b_addr, keys);
		
		return null;
	}
	
	private byte[] requestKeys(InetSocketAddress kdc_addr) {
		try {
			long Na = CryptographyUtils.getNonce();
						
			SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
			byte[] buff = new byte[65000];
			DatagramPacket p = new DatagramPacket(buff, buff.length, kdc_addr );
			
			/*Payload ns1 = new NS1(socket.getLocalAddress().getAddress(),
					b_addr.getAddress().getAddress(), Na, cryptoManager);*/
			
			//TODO: Change ID
			Payload ns1 = new NS1("a".getBytes(), "b".getBytes(), Na, cryptoManager);

			socket.send(p, ns1);
			
			// Receive reply from KDC
			socket.receive(p);
			byte[] reply = Arrays.copyOfRange(p.getData(), 0, p.getLength());
			
			// TODO : como fazer deserialize?
			System.out.println(new String(reply)); // temp
			
			return reply;
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IOException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}  
	
	private void shareKeys(InetSocketAddress b_addr, byte[] keys) {
		try {
			// Trocar este cryptoManager pelo crytpo manager que é construído no métod anteiroro para usar a chave dos macs definida pelo kdc uma vez que o a não partilha nenhuma chave com o b e depois nem o a nem o b conseguem validar as merdas.
			
			SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
			byte[] buff = new byte[65000];
			DatagramPacket p = new DatagramPacket(buff, buff.length, b_addr );
			
			//byte[] request = "To Chaves!".getBytes();
			
			p.setData(keys, 0, keys.length );
			p.setSocketAddress( b_addr );
			socket.send(p, ClearPayload.TYPE);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | KeyStoreException
				| CertificateException | IOException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}  
	
	// KDC Client returns CriptoMananger
	// Alterar construtor do SecureSocket para receber CriptoManager

	// A -> KDC : A, B, Na
	// KDC -> A : {Na+1, Nc, Ks , B, {Nc, A, B, Ks}KB }KA 
	
	// A -> B : {Nc, A, B, Ks }KB
	// B -> A : {Nb }Ks
	// A -> B : {Nb+1 }Ks
	
	// A -> KDC : Dá-me Chaves
	// KDC -> A : toma
	// A -> B : toma também
	
 
	
}
