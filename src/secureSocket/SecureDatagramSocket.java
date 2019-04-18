package secureSocket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;

public class SecureDatagramSocket implements java.io.Closeable {

	private DatagramSocket socket;

	public SecureDatagramSocket(int port, InetAddress laddr) throws IOException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
		} else {
			socket = new DatagramSocket(port, laddr);
		}
	}
	
	public SecureDatagramSocket(InetSocketAddress addr) throws IOException {
		this(addr.getPort(), addr.getAddress());
	}

	public SecureDatagramSocket() throws IOException {
		socket = new DatagramSocket();
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}
	
	public void receive(DatagramPacket p) throws IOException {
		socket.receive(p);
	}
	
	public void send(DatagramPacket p) throws IOException {
		socket.send(p);
	}

}
