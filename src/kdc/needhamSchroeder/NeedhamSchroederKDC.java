package kdc.needhamSchroeder;

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

import kdc.KDC;
import kdc.KDCReply;
import secureSocket.SecureDatagramSocket;
import secureSocket.secureMessages.ClearPayload;

public class NeedhamSchroederKDC implements KDC {

	private SecureDatagramSocket socket;
	
	public NeedhamSchroederKDC(InetSocketAddress addr) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr);
	}

	@Override
	public void receiveRequest() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		
		byte[] buffer = new byte[4 * 1024];
		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		socket.receive(inPacket);
		
		byte[] request = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
		System.out.println(new String(request));
		
		String msg = "YOLO";
		inPacket.setData(msg.getBytes(), 0, msg.length());
		inPacket.setAddress(inPacket.getAddress());
		socket.send(inPacket, ClearPayload.TYPE);
		
		
	}

	@Override
	public void sendReply(KDCReply reply) {
		// TODO Auto-generated method stub
		
	}
}
