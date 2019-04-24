/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

//
package stream;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import secureSocket.SecureDatagramSocket;

class hjUDPproxy {
	
	private static final String CIPHERSUITE_CONFIG_PATH = "configs/server/ciphersuite.conf";
	
	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {
		InputStream inputStream = new FileInputStream("configs/proxy/config.properties");
		Properties properties = new Properties();
		properties.load(inputStream);
		String remote = properties.getProperty("remote");
		String destinations = properties.getProperty("localdelivery");

		InetSocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

		// Create inSocket 
		Cryptography cryptoManager = CryptoFactory.loadFromConfig(CIPHERSUITE_CONFIG_PATH);
		SecureDatagramSocket inSocket = new SecureDatagramSocket(inSocketAddress, cryptoManager);
		
		DatagramSocket outSocket = new DatagramSocket();
		byte[] buffer = new byte[4 * 1024];

		System.out.println("Proxy ready to receive...");
		
		// main loop
		while (true) {
			DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);

			inSocket.receive(inPacket);

			System.out.print("*");
			for (SocketAddress outSocketAddress : outSocketAddressSet) {
				outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
			}
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
