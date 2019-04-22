package kdc;

import java.net.InetSocketAddress;

public class ClientMain {

	public static void main(String[] args) throws Exception {

		InetSocketAddress a_addt = new InetSocketAddress("localhost", 5555);
		InetSocketAddress kdc_addr = new InetSocketAddress("localhost", 8888);
		InetSocketAddress b_addr = new InetSocketAddress("localhost", 6666);
		
		if(args[0].equals("client") ) {
			System.out.println("Client ready");
			NeedhamSchroederClient nsc = new NeedhamSchroederClient(kdc_addr, b_addr);
			nsc.getSessionParameters();	
		}else {
			System.out.println("Server ready");
			NeedhamSchroederServer ncs = new NeedhamSchroederServer(b_addr);
			ncs.getSessionParameters();
		}
	}
}
