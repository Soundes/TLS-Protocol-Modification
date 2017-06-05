package org.bouncycastle.tls.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Client {
  public static void main(String args[]) throws Exception {
	
	System.out.println("I am the client");
    System.setProperty("javax.net.ssl.trustStore", "clienttrust");

    SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
    Socket s = ssf.createSocket("localhost", 8787);

    SSLSession session = ((SSLSocket) s).getSession();
    
    Certificate[] cchain = session.getPeerCertificates();
    System.out.println("The Certificates used by peer");
   // for (int i = 0; i < cchain.length; i++) {
   //   System.out.println(((X509Certificate) cchain[i]).getSubjectDN());
   // }

    
    System.out.println("Peer host is " + session.getPeerHost());
    System.out.println("Cipher is " + session.getCipherSuite());
    System.out.println("Protocol is " + session.getProtocol());
    System.out.println("ID is " + new BigInteger(session.getId()));
    System.out.println("Session created in " + session.getCreationTime());
    System.out.println("Session accessed in " + session.getLastAccessedTime());

    BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
    String x = in.readLine();
    System.out.println(x);
    in.close();

  }
}








