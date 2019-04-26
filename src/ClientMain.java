

import java.net.InetSocketAddress;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import keyEstablishmentProtocol.KeyEstablishmentProtocolClient;
import keyEstablishmentProtocol.KeyEstablishmentProtocolServer;
import keyEstablishmentProtocol.needhamSchroeder.NeedhamSchroederClient;
import keyEstablishmentProtocol.needhamSchroeder.NeedhamSchroederServer;

public class ClientMain { //

	public static void main(String[] args) throws Exception {

		InetSocketAddress kdc_addr = new InetSocketAddress("localhost", 8888);
		InetSocketAddress b_addr = new InetSocketAddress("localhost", 8889);
		
		if( args[0].equals("client") ) {
			System.out.println("Client ready");

			String config_file = "./configs/proxy/ciphersuite.conf";
			//Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(config_file);
			Cryptography master_cryptoManager = CryptoFactory.getInstace("password", "configs/proxy/ciphersuite.conf");
			KeyEstablishmentProtocolClient needhamClient = new NeedhamSchroederClient(kdc_addr, "proxy", master_cryptoManager); // TODO: read a and b from some file
			Cryptography session_cryptoManager = needhamClient.getSessionParameters("b",  new String[] {"cars"});
		}else {
			System.out.println("Server ready");
			String config_file = "./configs/server/ciphersuite.conf";
			Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(config_file);
			
			KeyEstablishmentProtocolServer kdc_server = new NeedhamSchroederServer(b_addr, master_cryptoManager);
			kdc_server.start(null); // PODE ERCEBER NULL?
		}
	}
}
