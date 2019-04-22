package kdc;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.util.Arrays;

import secureSocket.SecureDatagramSocket;

public class NeedhamSchroederServer implements KDCServer {
	
	private InetSocketAddress b_addr;
	
	public NeedhamSchroederServer(InetSocketAddress b_addr) {
		this.b_addr = b_addr;
	}

	@Override
	public KDCReply getSessionParameters() { // TODO: isto precisa de outo nome
		
		receiveKeys(b_addr);
		
		return null; 
	}

	private static byte[] receiveKeys(InetSocketAddress b_addr) {
		try {
			SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr);

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
