package org.ravib.sslvalidator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class CustomSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory underlyingFactory;
    private final String[] enabledCiphers;

    public CustomSSLSocketFactory(SSLContext context, String cipher) throws Exception {
        this.underlyingFactory = context.getSocketFactory();
        this.enabledCiphers = new String[]{cipher};
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return enabledCiphers;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return enabledCiphers;
    }

    @Override
    public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws java.io.IOException {
        java.net.Socket socket = underlyingFactory.createSocket(s, host, port, autoClose);
        ((javax.net.ssl.SSLSocket) socket).setEnabledCipherSuites(enabledCiphers);
        return socket;
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
        return null;
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return null;
    }
}