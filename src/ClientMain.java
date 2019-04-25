

import java.net.InetSocketAddress;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import kdc.KDCClient;
import kdc.KDCServer;
import kdc.needhamSchroeder.NeedhamSchroederClient;
import kdc.needhamSchroeder.NeedhamSchroederServer;

public class ClientMain { //

	public static void main(String[] args) throws Exception {

		InetSocketAddress kdc_addr = new InetSocketAddress("localhost", 8888);
		InetSocketAddress b_addr = new InetSocketAddress( "localhost", 8889);
		
		if( args[0].equals("client") ) {
			System.out.println("Client ready");

			String config_file = "./configs/proxy/ciphersuite.conf";
			Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(config_file);
			KDCClient needhamClient = new NeedhamSchroederClient(kdc_addr, "a", master_cryptoManager); // TODO: read a and b from some file
			Cryptography session_cryptoManager = needhamClient.getSessionParameters("b", b_addr);
		}else {
			System.out.println("Server ready");
			String config_file = "./configs/server/ciphersuite.conf";
			Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(config_file);
			
			KDCServer kdc_server = new NeedhamSchroederServer(b_addr, master_cryptoManager);
			Cryptography session_cryptoManager = kdc_server.getSessionParameters();
		}
	}
}
