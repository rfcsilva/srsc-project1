package keyEstablishmentProtocol;

import java.net.InetSocketAddress;

import secureSocket.SecureDatagramSocket;

public interface RequestHandler {

	void execute(SecureDatagramSocket socket, InetSocketAddress addr, String[] args);
	
}
