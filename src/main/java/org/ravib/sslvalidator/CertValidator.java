package org.ravib.sslvalidator;

import javax.net.ssl.*;
import java.io.FileInputStream;
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

        if (listCiphers == true && cipherCheck == true) {
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
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keyStorePassword.toCharArray());
                X509KeyManager defaultKeyManager = (X509KeyManager) kmf.getKeyManagers()[0];
                context.init(new KeyManager[]{defaultKeyManager}, new TrustManager[]{tm}, null);
                factory = context.getSocketFactory();
                System.out.println("Opening a SSL connection to " + sslHost + ":" + sslPort);
                socket = (SSLSocket) factory.createSocket(sslHost, sslPort);
                socket.setNeedClientAuth(true);
            } else {
                context.init(null, new TrustManager[]{tm}, null);
                factory = context.getSocketFactory();
                System.out.println("Opening a SSL connection to " + sslHost + ":" + sslPort);
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
                    System.out.print("SSL Handshake Failed! Error: \n\t\t\"" + e.getMessage() + "\"");
                    if (e.getMessage().contains("Received fatal alert: handshake_failure") && !cipherCheck) {
                        System.out.println(". Run the command again with \"--cipherCheck true\" to check if there is a cipher mismatch");
                    }
                    if (e.getMessage().contains("unable to find valid certification path to requested target")) {
                        System.out.println(". The client's truststore does not seem to have CA cert.");
                    }
                }

                X509Certificate[] serverCerts = tm.chain;

                if (serverCerts == null) {
                    System.out.println("\nCould not even obtain server's certificate chain. Check server's certificates using openssl or keytool");
                }

                Boolean trustStoreFaulty = false;
                if (!handshakeResult && serverCerts != null) {
                    System.out.println("\n\nValidating if CA cert for Server's Certificate is present in client's truststore");
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
                                System.out.println("\tMissing or untrusted certificate in client's truststore: " + cert.getSubjectDN() + ". \n\tError received while parsing this cert is:" + e.getMessage());
                            } else {
                                System.out.println("\tMissing or untrusted certificate in client's truststore: " + cert.getSubjectDN() + "\n\t and its issuer is " + cert.getIssuerDN() + ". \n\tError received while parsing this cert is:" + e.getMessage());
                            }
                            if (mTLS) {
                                System.out.println("Skipping validating client's keystore as client's truststore has issues. Fix client's truststore and run the command again to validate client's keystore.");
                            }
                        }
                    }
                }
                if (!handshakeResult && mTLS && serverCerts != null && !trustStoreFaulty) {
                    System.out.println("\nConnection type was set to mTLS. Reading client's keystore now");
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
                                    System.out.println("\tCertificate " + clientCert.getSubjectDN() + " expired on " + clientCert.getNotAfter());
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
                    System.out.println("\nValidating ciphers from server");
                    CipherValidator cipherValidator = new CipherValidator();
                    cipherValidator.validateCipher(context, sslHost, sslPort);

                }
            }
        } else {
            context.init(null, null, null);
            String[] defaultCiphers = context.getSocketFactory().getSupportedCipherSuites();
            System.out.println("Listing out all " + defaultCiphers.length + " default ciphers on this node:");
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
