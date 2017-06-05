package org.bouncycastle.tls.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import sun.rmi.runtime.Log;

public class Server extends utilities {
	
	
	  
	  
  public static void main(String args[]) throws Exception {
    //create a keystore 
	  KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

	  char[] password = "sondos27".toCharArray();
	  ks.load(null, password);

	  // Store away the keystore.
	  FileOutputStream fos = new FileOutputStream("keytoresondos");
	  ks.store(fos, password);
	  fos.close();
	  
	  ks = initKeyStore("keytoresondos","JKS","sondos27");
	  //System.setProperty("javax.net.ssl.keyStore", "keytoresondos");
      //System.setProperty("javax.net.ssl.keyStorePassword", "sondos27");
	  X509Certificate certificate = generateX509Certificate("CAselfSignedCertificate.cer");
	  storeCertInKeystore(certificate);
	  /////////////////////////////////////////////
	  TrustManagerFactory trustManagerFactory =
			    TrustManagerFactory.getInstance("PKIX", "SunJSSE");
			trustManagerFactory.init(ks);
			
	  X509TrustManager x509TrustManager = null;
	  for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
	      if (trustManager instanceof X509TrustManager) {
	    x509TrustManager = (X509TrustManager) trustManager;
	    break;
	      }
	  }
	   
	  if (x509TrustManager == null) {
	      throw new NullPointerException();
	  }
	  
	  KeyManagerFactory keyManagerFactory =
			    KeyManagerFactory.getInstance("SunX509", "SunJSSE");
			keyManagerFactory.init(ks, "sondos27".toCharArray());
			 
			X509KeyManager x509KeyManager = null;
			for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
			    if (keyManager instanceof X509KeyManager) {
			  x509KeyManager = (X509KeyManager) keyManager;
			  break;
			    }
			}
			 
			if (x509KeyManager == null) {
			    throw new NullPointerException();
			}
			
			
			// load in the appropriate keystore and truststore for the server
			// get the X509KeyManager and X509TrustManager instances
			 
			SSLContext sslContext = SSLContext.getInstance("TLS");
			// the final null means use the default secure random source
			sslContext.init(new KeyManager[]{x509KeyManager},
			    new TrustManager[]{x509TrustManager}, null);
			 
			SSLServerSocketFactory serverSocketFactory =
			    sslContext.getServerSocketFactory();
			SSLServerSocket serverSocket =
			    (SSLServerSocket) serverSocketFactory.createServerSocket(8787);
			 
			serverSocket.setNeedClientAuth(false);
			// prevent older protocols from being used, especially SSL2 which is insecure
			serverSocket.setEnabledProtocols(new String[]{"TLSv1"});
			 
			// you can now call accept() on the server socket, etc
			
	  ////////////////////////////////////////////
	   
	 
    //SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
    //ServerSocket ss = ssf.createServerSocket(8787);
    while (true) {
      Socket s = serverSocket.accept();
      SSLSession session = ((SSLSocket) s).getSession();
      if(session == null) System.out.println("session is null ");
      Certificate[] cchain2 = session.getLocalCertificates();
      //for (int i = 0; i < cchain2.length; i++) {
      //  System.out.println(((X509Certificate) cchain2[i]).getSubjectDN());
      //}
      System.out.println("I am the server");
      System.out.println("Peer host is " + session.getPeerHost());
      System.out.println("Cipher is " + session.getCipherSuite());
      System.out.println("Protocol is " + session.getProtocol());
      System.out.println("ID is " + new BigInteger(session.getId()));
      System.out.println("Session created in " + session.getCreationTime());
      System.out.println("Session accessed in " + session.getLastAccessedTime());

      PrintStream out = new PrintStream(s.getOutputStream());
      out.println("Hi");
      out.close();
      s.close();
    }

  }
  
  private static boolean storeCertInKeystore(X509Certificate certificate) {
	    try {
	        
	    	InputStream is = new FileInputStream("keytoresondos"); ;
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        keyStore.load(is, "sondos27".toCharArray());
	        keyStore.setCertificateEntry("mycert", certificate);

	        return true;
	    } catch(Exception e) {
	            e.printStackTrace();
	    }
	    return false;
	}
}








