package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import kdc.KDC;
import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.ClearPayload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederKDC implements KDC {

	private SecureDatagramSocket socket;
	
	public NeedhamSchroederKDC(InetSocketAddress addr) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr, null);
	}
	
	//TODO: temos de lidar com os nonces

	@Override
	public SocketAddress receiveRequest( SecureMessage sm ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		
		// TODO: Não deveria fazer mais coisas?
		
		return socket.receive(sm);
		
		/*byte[] request = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
		System.out.println(new String(request));*/
		
		/*String msg = "YOLO";
		inPacket.setData(msg.getBytes(), 0, msg.length());
		inPacket.setAddress(inPacket.getAddress());
		socket.send(inPacket, ClearPayload.TYPE);*/
		
		
	}

	@Override
	public void sendReply() {
		// TODO Auto-generated method stub
		
	}
}
