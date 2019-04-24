package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptographyUtils;
import kdc.KDC;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederKDC implements KDC {

	private SecureDatagramSocket socket;
	
	public NeedhamSchroederKDC(InetSocketAddress addr) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr, null);
	}
	
	public NeedhamSchroederKDC() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(null);
	}
	
	//TODO: temos de lidar com os nonces

	@Override
	public InetSocketAddress receiveRequest( SecureMessage sm ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		
		// TODO: Não deveria fazer mais coisas?
		
		return socket.receive(sm);
		
		/*byte[] request = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
		System.out.println(new String(request));*/
		
		/*String msg = "YOLO";
		inPacket.setData(msg.getBytes(), 0, msg.length());
		inPacket.setAddress(inPacket.getAddress());
		socket.send(inPacket, ClearPayload.TYPE);*/
		
		
	}

	//TODO: Fazer verificação dos nonces
	
	@Override
	public void sendReply(NS1 request, byte[] securityParams, InetSocketAddress addr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		long Na_1 = request.getNa() + 1;
		long Nc = CryptographyUtils.getNonce();
		
		Payload payload = new NS2(Na_1, Nc, securityParams, request.getA(), request.getB(), request.getCryptoManagerB(), request.getCryptoManagerA());
		SecureMessage sm = new SecureMessageImplementation(payload);
		
		socket.send(sm, addr);
	}
}
