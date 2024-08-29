package org.ravib.sslvalidator;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class CipherValidator {

    SSLContext context;
    public void validateCipher(SSLContext context, String sslHost, int sslPort) {
        this.context=context;
          final String httpsURL = "https://"+sslHost+":"+sslPort;
        try {

            SSLSocketFactory factory = context.getSocketFactory();
            String[] defaultCiphers = factory.getSupportedCipherSuites();

            List<String> supportedCiphers = new ArrayList<>();
            List<String> unsupportedCiphers = new ArrayList<>();

            for (String cipher : defaultCiphers) {
                try {

                    HttpsURLConnection.setDefaultSSLSocketFactory(new CustomSSLSocketFactory(context,cipher));
                    URL url = new URL(httpsURL);
                    HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                    connection.setConnectTimeout(30000);
                    connection.connect();
                    supportedCiphers.add(cipher);
                    connection.disconnect();
                } catch (Exception e) {
                    unsupportedCiphers.add(cipher);
                }
            }

            HttpsURLConnection.setDefaultSSLSocketFactory(factory);

            System.out.println("Unsupported or failed ciphers on client side that are not supported on server");
            for (String cipher : unsupportedCiphers) {
                System.out.println("\t" + cipher);
            }

            if(supportedCiphers.size()>0) {
                System.out.println("Supported " + supportedCiphers.size() + " ciphers are listed below");
                for (String cipher : supportedCiphers) {
                    System.out.println("\t" + cipher);
                }
            }
            else {
                System.out.println("There are no common ciphers. Server must support one of the ciphers listed above. \nTo check the cipher being used on the server run this tool only with \"--listCiphers true\" option on the server node");

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}