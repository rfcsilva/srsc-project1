package kdc.needhamSchroeder;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.util.Arrays;

import cryptography.Cryptography;
import kdc.KDCServer;
import secureSocket.SecureDatagramSocket;

public class NeedhamSchroederServer implements KDCServer {
	
	private InetSocketAddress b_addr;
	
	public NeedhamSchroederServer(InetSocketAddress b_addr) {
		this.b_addr = b_addr;
	}

	@Override
	public Cryptography getSessionParameters() { // TODO: isto precisa de outo nome
		
		receiveKeys(b_addr);
		
		return null; 
	}

	private static byte[] receiveKeys(InetSocketAddress b_addr) {
		try {
			// nesta msg3 o dred tem de ler a chave e criar o cryptoManager com essas chaves para validar o mac
			SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, null);

			byte[] buffer = new byte[4 * 1024];
			DatagramPacket p = new DatagramPacket(buffer, buffer.length);

			inSocket.receive(p);

			byte[] reply = Arrays.copyOfRange(p.getData(), 0, p.getLength());

			System.out.println(new String(reply)); // temp
			
			return reply;
		} catch(Exception e) {

		}
		return null;
	}

}
