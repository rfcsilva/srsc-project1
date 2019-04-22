package kdc;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
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

import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.ClearPayload;
import util.ArrayUtils;

public class NeedhamSchroederClient implements KDCClient {

	private InetSocketAddress kdc_addr;
	private InetSocketAddress b_addr;
	
	public NeedhamSchroederClient(InetSocketAddress kdc_addr, InetSocketAddress b_addr) {
		this.kdc_addr = kdc_addr;
		this.b_addr = b_addr;
	}
	
	@Override
	public KDCReply getSessionParameters() {
		// TODO Auto-generated method stub
		shareKeys(b_addr, requestKeys(kdc_addr));
		
		return null;
	}
	
	private static byte[] requestKeys(InetSocketAddress kdc_addr) {
		try {
			SecureDatagramSocket socket = new SecureDatagramSocket();
			byte[] buff = new byte[65000];
			DatagramPacket p = new DatagramPacket(buff, buff.length, kdc_addr );
			
			byte[] request = "Dá-me Chaves!".getBytes();
			
			p.setData(request, 0, request.length );
			p.setSocketAddress( kdc_addr );
			socket.send(p, ClearPayload.TYPE);
			
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
	
	private static void shareKeys(InetSocketAddress b_addr, byte[] keys) {
		try {
			SecureDatagramSocket socket = new SecureDatagramSocket();
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
