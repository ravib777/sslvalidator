package org.ravib.sslvalidator;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;

public class CertValidator {

    static String sslHost;
    static Integer sslPort;
    static String keyStorePath = null;
    static String keyStorePassword = null;
    static Boolean mTLS = false;
    static String trustStorePath = null;
    static String trustStorePassword = null;
    static String protocol = "TLSv1.2";
    static Boolean cipherCheck = false;
    static Boolean listCiphers = false;


    public static void main(String[] args) throws Exception {

        Map<String, String> arguments = new HashMap<>();


        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                if (i + 1 < args.length) {
                    String key = args[i].substring(2);
                    String value = args[i + 1];
                    arguments.put(key, value);
                }
                i++;
            }
        }

        for (Map.Entry<String, String> entry : arguments.entrySet()) {
            switch (entry.getKey()) {
                case "sslHost":
                    sslHost = entry.getValue();
                    break;
                case "sslPort":
                    sslPort = Integer.parseInt(entry.getValue());
                    break;
                case "keyStorePath":
                    keyStorePath = entry.getValue();
                    break;
                case "keyStorePassword":
                    keyStorePassword = entry.getValue();
                    break;
                case "mTLS":
                    mTLS = Boolean.parseBoolean(entry.getValue());
                    break;
                case "trustStorePath":
                    trustStorePath = entry.getValue();
                    break;
                case "trustStorePassword":
                    trustStorePassword = entry.getValue();
                    break;
                case "protocol":
                    protocol = entry.getValue();
                    break;
                case "cipherCheck":
                    cipherCheck = Boolean.parseBoolean(entry.getValue());
                    break;
                case "listCiphers":
                    listCiphers = Boolean.parseBoolean(entry.getValue());
                    break;
                default:
                    System.out.println("Unknown config: " + entry.getKey());
                    break;
            }

        }

        SSLContext context;
        TrustManagerFactory tmf;

        if (listCiphers == true && cipherCheck == true || listCiphers == true && sslHost != null || listCiphers == true && sslPort != null) {
            System.out.println("ignoring --listCiphers");
            listCiphers = false;
        }


        try {
            context = SSLContext.getInstance(protocol);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }

        if (!listCiphers) {
            try {
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            }

            KeyStore trustStore = null;
            if (trustStorePath != null) {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                try (FileInputStream trustStoreFis = new FileInputStream(trustStorePath)) {
                    trustStore.load(trustStoreFis, trustStorePassword.toCharArray());
                }
            }
            tmf.init((KeyStore) trustStore);
            X509TrustManager defaultTm = findX509TrustManager(tmf.getTrustManagers());
            CustomTrustManager tm = new CustomTrustManager(defaultTm);

            SSLSocket socket = null;
            SSLSocketFactory factory = null;
            KeyStore keyStore = null;

            if (keyStorePath != null && mTLS) {
                keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keyStorePassword.toCharArray());
                X509KeyManager defaultKeyManager = (X509KeyManager) kmf.getKeyManagers()[0];
                context.init(new KeyManager[]{defaultKeyManager}, new TrustManager[]{tm}, null);
                factory = context.getSocketFactory();
                System.out.println("Attempting to open an SSL connection to " + sslHost + ":" + sslPort);
                socket = (SSLSocket) factory.createSocket(sslHost, sslPort);
                socket.setNeedClientAuth(true);
            } else {
                context.init(null, new TrustManager[]{tm}, null);
                factory = context.getSocketFactory();
                System.out.println("Attempting to open an SSL connection to " + sslHost + ":" + sslPort);
                socket = (SSLSocket) factory.createSocket(sslHost, sslPort);
            }

            if (socket != null) {
                socket.setSoTimeout(30000);
                Boolean handshakeResult = false;
                try {
                    socket.startHandshake();
                    socket.close();
                    System.out.println("SSL Handshake Successful! Skipping Certificate validation");
                    handshakeResult = true;

                } catch (SSLException e) {
                    System.out.println("**Error Encountered**");
                    System.out.print("**SSL Handshake Failed** Error: \n\t\t\"" + e.getMessage() + "\"");
                    if (e.getMessage().contains("Received fatal alert: handshake_failure") && !cipherCheck) {
                        System.out.println("Try running Error possibly due to unsupported TLS Protocol and Cipher Suites. Try running this command with different \"--protocol <TLSvXX>\" or if possible listing ciphers on both client and server nodes using \"--listCiphers true\"");
                    }
                    else if(e.getMessage().contains("Received fatal alert: handshake_failure") && cipherCheck){
                        cipherCheck=false;
                        System.out.println("Skipping cipherCheck! Error possibly due to unsupported TLS Protocol and Cipher Suites. Try running this with different \"--protocol <TLSvXX>\" or if possible listing ciphers on both client and server nodes using \"--listCiphers true\"");
                    }
                    if (e.getMessage().contains("unable to find valid certification path to requested target")) {
                        System.out.println(". The client's truststore does not seem to have required CA cert. Review the CA validation output below.");
                    }
                }

                X509Certificate[] serverCerts = tm.chain;

                if (serverCerts == null) {
                    System.out.println("Could not obtain server's certificate chain!");
                }

                Boolean trustStoreFaulty = false;
                if (!handshakeResult && serverCerts != null) {
                    System.out.println("\n\n**Certificate Validation:**\nValidating if CA cert for Server's Certificate is present in client's truststore");
                    for (X509Certificate cert : serverCerts) {
                        try {
                            cert.checkValidity();
                            if (cert.getBasicConstraints() == -1) {
                                //    System.out.println("\tSkipping Private Key Cert from server :" + cert.getSubjectDN());
                                continue;
                            }
                            tm.checkServerTrusted(new X509Certificate[]{cert}, "RSA");
                            System.out.println("Certificate is trusted: " + cert.getSubjectDN());
                        } catch (CertificateExpiredException ce) {
                            trustStoreFaulty = true;
                            System.out.println("\tCert expired : " + cert.getSubjectDN() + " Expiry was valid between " + cert.getNotBefore() + " and " + cert.getNotAfter());
                        } catch (CertificateException e) {
                            trustStoreFaulty = true;
                            if (cert.getIssuerDN().equals(cert.getIssuerDN())) {
                                System.out.println("\tThis CA cert is missing in client's truststore: " + cert.getSubjectDN() + ". \n\tError received while parsing this cert is:" + e.getMessage());
                            } else {
                                System.out.println("\tThis CA cert is missing in client's truststore: " + cert.getSubjectDN() + "\n\t and its issuer is " + cert.getIssuerDN() + ". \n\tError received while parsing this cert is:" + e.getMessage());
                            }
                            if (mTLS) {
                                System.out.println("\nSkipping validating client's keystore as client's truststore has issues. Fix client's truststore and run the command again to validate client's keystore.");
                            }
                        }
                    }
                }
                if (!handshakeResult && mTLS && serverCerts != null && !trustStoreFaulty) {
                    System.out.println("\nConnection type was set to mTLS. Reading client's keystore now");
                    if (keyStore == null) {
                        System.out.println("\t--keyStorePath & --keyStorePassword missing for mTLS connection test. Exiting");
                        System.exit(1);
                    }
                    Enumeration<String> aliases = keyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();

                        if (keyStore.isKeyEntry(alias)) {
                            Certificate[] certificateChain = keyStore.getCertificateChain(alias);
                            X509Certificate[] x509CertificateChain = new X509Certificate[certificateChain.length];

                            for (int i = 0; i < certificateChain.length; i++) {
                                if (certificateChain[i] instanceof X509Certificate) {
                                    x509CertificateChain[i] = (X509Certificate) certificateChain[i];
                                } else {
                                    throw new IllegalArgumentException("The certificate is not an X509Certificate.");
                                }
                            }
                            for (X509Certificate clientCert : x509CertificateChain) {
                                try {
                                    clientCert.checkValidity();
                                } catch (CertificateExpiredException cee) {
                                    System.out.println("\tClient's Certificate " + clientCert.getSubjectDN() + " expired on " + clientCert.getNotAfter());
                                }
                            }

                            X509Certificate rootCA = x509CertificateChain[x509CertificateChain.length - 1];

                            if (rootCA.getIssuerDN().equals(rootCA.getSubjectDN())) {
                                System.out.println("\tClient cert's CA is:" + rootCA.getIssuerDN() + " . Check server's truststore or cacerts to ensure this cert is present there");
                            } else {
                                System.out.print("\tClient cert's CA is Subject: " + rootCA.getSubjectDN() + " and Issuer is:" + rootCA.getIssuerDN() + " . Check server's truststore or cacerts to ensure these cert is present there");
                            }
                        }
                    }
                }
                if (cipherCheck) {
                    System.out.println("\n**Cipher Validation:**");
                    System.out.println("\tValidating if local ciphers are supported by the server");

                    String[] defaultCiphers = factory.getSupportedCipherSuites();

                    List<String> supportedCiphers = new ArrayList<>();
                    List<String> unsupportedCiphers = new ArrayList<>();

                    for (String cipher : defaultCiphers) {
                        try {

                            HttpsURLConnection.setDefaultSSLSocketFactory(new CustomSSLSocketFactory(context,cipher));
                            URL url = new URL("https://"+sslHost+":"+sslPort);
                            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                            connection.setConnectTimeout(30000);
                            connection.connect();
                            supportedCiphers.add(cipher);
                            connection.disconnect();
                        } catch (Exception e) {
                            unsupportedCiphers.add(cipher);
                        }
                    }

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
                }
            }
        } else {
            context.init(null, null, null);
            String[] defaultCiphers = context.getSocketFactory().getSupportedCipherSuites();
            System.out.println("\n**Listing Cipher:**");
            System.out.println("Following are " + defaultCiphers.length + " default ciphers on this node:");
            for (String cipher : defaultCiphers) {
                System.out.println("\t" + cipher);
            }
        }
    }

    private static X509TrustManager findX509TrustManager(TrustManager[] trustManagers) {
        for (TrustManager tm : trustManagers) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        return null;
    }

    private static class CustomTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        X509Certificate[] chain;
        X509Certificate[] clientChain;

        CustomTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            return tm.getAcceptedIssuers();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.clientChain = chain;
            try {
                tm.checkClientTrusted(chain, authType);
            } catch (CertificateException e) {
                throw e;
            }
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            try {
                tm.checkServerTrusted(chain, authType);
            } catch (CertificateException e) {
                throw e;
            }
        }
    }
}   
