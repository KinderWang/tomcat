/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.tomcat.util.net.jsse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.apache.tomcat.util.res.StringManager;

/**
 * SSL server socket factory. It <b>requires</b> a valid RSA key and
 * JSSE.<br/>
 * keytool -genkey -alias tomcat -keyalg RSA</br>
 * Use "changeit" as password (this is the default we use).
 *
 * @author Harish Prabandham
 * @author Costin Manolache
 * @author Stefan Freyr Stefansson
 * @author EKR -- renamed to JSSESocketFactory
 * @author Jan Luehe
 * @author Bill Barker
 */
public class JSSESocketFactory
    extends org.apache.tomcat.util.net.ServerSocketFactory {

    private static final org.apache.juli.logging.Log log =
            org.apache.juli.logging.LogFactory.getLog(JSSESocketFactory.class);
    private static StringManager sm =
        StringManager.getManager("org.apache.tomcat.util.net.jsse.res");

    // defaults
    private static final String defaultProtocol = "TLS";
    private static final String defaultKeystoreType = "JKS";
    private static final String defaultKeystoreFile
        = System.getProperty("user.home") + "/.keystore";
    private static final int defaultSessionCacheSize = 0;
    private static final int defaultSessionTimeout = 86400;
    private static final String ALLOW_ALL_SUPPORTED_CIPHERS = "ALL";
    private static final String defaultKeyPass = "changeit";

    private final boolean rfc5746Supported;
    private final String[] defaultServerProtocols;
    private final String[] defaultServerCipherSuites;

    protected boolean initialized;
    protected SSLServerSocketFactory sslProxy = null;
    protected String[] enabledCiphers;
    protected boolean allowUnsafeLegacyRenegotiation = false;

    /**
     * Flag to state that we require client authentication.
     */
    protected boolean requireClientAuth = false;

    /**
     * Flag to state that we would like client authentication.
     */
    protected boolean wantClientAuth    = false;


    public JSSESocketFactory () {
        this(null);
    }

    public JSSESocketFactory(String sslProtocol) {

        if (sslProtocol == null) {
            sslProtocol = defaultProtocol;
        }

        SSLContext context;
        try {
             context = SSLContext.getInstance(sslProtocol);
             context.init(null,  null,  null);
        } catch (NoSuchAlgorithmException e) {
            // This is fatal for the connector so throw an exception to prevent
            // it from starting
            throw new IllegalArgumentException(e);
        } catch (KeyManagementException e) {
            // This is fatal for the connector so throw an exception to prevent
            // it from starting
            throw new IllegalArgumentException(e);
        }

        // Supported cipher suites aren't accessible directly from the
        // SSLContext so use the SSL server socket factory
        SSLServerSocketFactory ssf = context.getServerSocketFactory();
        String supportedCiphers[] = ssf.getSupportedCipherSuites();
        boolean found = false;
        for (String cipher : supportedCiphers) {
            if ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV".equals(cipher)) {
                found = true;
                break;
            }
        }
        rfc5746Supported = found;

        // There is no standard way to determine the default protocols and
        // cipher suites so create a server socket to see what the defaults are
        SSLServerSocket socket;
        try {
            socket = (SSLServerSocket) ssf.createServerSocket();
        } catch (IOException e) {
            // This is very likely to be fatal but there is a slim chance that
            // the JSSE implementation just doesn't like creating unbound
            // sockets so allow the code to proceed.
            defaultServerCipherSuites = new String[0];
            defaultServerProtocols = new String[0];
            log.warn(sm.getString("jsse.noDefaultCiphers"));
            log.warn(sm.getString("jsse.noDefaultProtocols"));
            return;
        }

        defaultServerCipherSuites = socket.getEnabledCipherSuites();
        if (defaultServerCipherSuites.length == 0) {
            log.warn(sm.getString("jsse.noDefaultCiphers"));
        }

        // Filter out all the SSL protocols (SSLv2 and SSLv3) from the defaults
        // since they are no longer considered secure
        defaultServerProtocols = filterInsecureProtocols(socket.getEnabledProtocols());

        if (defaultServerProtocols.length == 0) {
            log.warn(sm.getString("jsse.noDefaultProtocols"));
        }
    }

    @Override
    public ServerSocket createSocket (int port)
        throws IOException
    {
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port);
        initServerSocket(socket);
        return socket;
    }

    @Override
    public ServerSocket createSocket (int port, int backlog)
        throws IOException
    {
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port, backlog);
        initServerSocket(socket);
        return socket;
    }

    @Override
    public ServerSocket createSocket (int port, int backlog,
                                      InetAddress ifAddress)
        throws IOException
    {
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port, backlog,
                                                          ifAddress);
        initServerSocket(socket);
        return socket;
    }

    @Override
    public Socket acceptSocket(ServerSocket socket)
        throws IOException
    {
        SSLSocket asock = null;
        try {
             asock = (SSLSocket)socket.accept();
             configureClientAuth(asock);
        } catch (SSLException e){
          throw new SocketException("SSL handshake error" + e.toString());
        }
        return asock;
    }

    @Override
    public void handshake(Socket sock) throws IOException {
        ((SSLSocket)sock).startHandshake();

        if (!allowUnsafeLegacyRenegotiation && !rfc5746Supported) {
            // Prevent further handshakes by removing all cipher suites
            ((SSLSocket) sock).setEnabledCipherSuites(new String[0]);
        }
    }

    /*
     * Determines the SSL cipher suites to be enabled.
     *
     * @param requestedCiphers Comma-separated list of requested ciphers
     * @param supportedCiphers Array of supported ciphers
     *
     * @return Array of SSL cipher suites to be enabled, or null if none of the
     * requested ciphers are supported
     */
    protected String[] getEnabledCiphers(String requestedCiphersStr,
                                         String[] supportedCiphers) {

        if ((requestedCiphersStr == null)
                || (requestedCiphersStr.trim().length() == 0)) {
            return defaultServerCipherSuites;
        }

        List<String> requestedCiphers = new ArrayList<String>();
        for (String rc : requestedCiphersStr.split(",")) {
            final String cipher = rc.trim();
            if (cipher.length() > 0) {
                requestedCiphers.add(cipher);
            }
        }
        if (requestedCiphers.isEmpty()) {
            return defaultServerCipherSuites;
        }
        List<String> ciphers = new ArrayList<String>(requestedCiphers);
        ciphers.retainAll(Arrays.asList(supportedCiphers));

        if (ciphers.isEmpty()) {
            log.warn(sm.getString("jsse.requested_ciphers_not_supported",
                    requestedCiphersStr));
        }
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("jsse.enableable_ciphers", ciphers));
            if (ciphers.size() != requestedCiphers.size()) {
                List<String> skipped = new ArrayList<String>(requestedCiphers);
                skipped.removeAll(ciphers);
                log.debug(sm.getString("jsse.unsupported_ciphers", skipped));
            }
        }

        return ciphers.toArray(new String[ciphers.size()]);
    }

    /*
     * Gets the SSL server's keystore password.
     */
    protected String getKeystorePassword() {
        String keyPass = (String)attributes.get("keypass");
        if (keyPass == null) {
            keyPass = defaultKeyPass;
        }
        String keystorePass = (String)attributes.get("keystorePass");
        if (keystorePass == null) {
            keystorePass = keyPass;
        }
        return keystorePass;
    }

    /*
     * Gets the SSL server's keystore.
     */
    protected KeyStore getKeystore(String type, String provider, String pass)
            throws IOException {

        String keystoreFile = (String)attributes.get("keystore");
        if (keystoreFile == null)
            keystoreFile = defaultKeystoreFile;

        try {
            return getStore(type, provider, keystoreFile, pass);
        } catch (FileNotFoundException fnfe) {
            throw fnfe;
        } catch (IOException ioe) {
            log.error(sm.getString("jsse.keystore_load_failed", type,
                    keystoreFile, ioe.getMessage()), ioe);
            throw ioe;
        }
    }

    /*
     * Gets the SSL server's truststore.
     */
    protected KeyStore getTrustStore(String keystoreType,
            String keystoreProvider) throws IOException {
        KeyStore trustStore = null;

        String truststoreFile = (String)attributes.get("truststoreFile");
        if(truststoreFile == null) {
            truststoreFile = System.getProperty("javax.net.ssl.trustStore");
        }
        if(log.isDebugEnabled()) {
            log.debug("Truststore = " + truststoreFile);
        }
        String truststorePassword = (String)attributes.get("truststorePass");
        if( truststorePassword == null) {
            truststorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
        }
        if( truststorePassword == null ) {
            truststorePassword = getKeystorePassword();
        }
        if(log.isDebugEnabled()) {
            log.debug("TrustPass = " + truststorePassword);
        }
        String truststoreType = (String)attributes.get("truststoreType");
        if( truststoreType == null) {
            truststoreType = System.getProperty("javax.net.ssl.trustStoreType");
        }
        if(truststoreType == null) {
            truststoreType = keystoreType;
        }
        if(log.isDebugEnabled()) {
            log.debug("trustType = " + truststoreType);
        }
        String truststoreProvider =
            (String)attributes.get("truststoreProvider");
        if( truststoreProvider == null) {
            truststoreProvider =
                System.getProperty("javax.net.ssl.trustStoreProvider");
        }
        if (truststoreProvider == null) {
            truststoreProvider = keystoreProvider;
        }
        if(log.isDebugEnabled()) {
            log.debug("trustProvider = " + truststoreProvider);
        }

        if (truststoreFile != null) {
            try {
                trustStore = getStore(truststoreType, truststoreProvider,
                        truststoreFile, truststorePassword);
            } catch (FileNotFoundException fnfe) {
                throw fnfe;
            } catch (IOException ioe) {
                // Log a warning that we had a password issue
                // and re-try, unless the password is null already
                if (truststorePassword != null) {
                    log.warn(sm.getString("jsse.invalid_truststore_password"),
                            ioe);
                    try {
                        trustStore = getStore(truststoreType,
                                truststoreProvider, truststoreFile, null);
                        ioe = null;
                    } catch (IOException ioe2) {
                        ioe = ioe2;
                    }
                }
                if (ioe != null) {
                    log.error(sm.getString("jsse.keystore_load_failed",
                            truststoreType, truststoreFile, ioe.getMessage()),
                            ioe);
                    throw ioe;
                }
            }
        }

        return trustStore;
    }

    /*
     * Gets the key- or truststore with the specified type, path, and password.
     */
    private KeyStore getStore(String type, String provider, String path,
            String pass) throws IOException {

        KeyStore ks = null;
        InputStream istream = null;
        try {
            if (provider == null) {
                ks = KeyStore.getInstance(type);
            } else {
                ks = KeyStore.getInstance(type, provider);
            }
            if(!("PKCS11".equalsIgnoreCase(type) || "".equalsIgnoreCase(path))) {
                File keyStoreFile = new File(path);
                if (!keyStoreFile.isAbsolute()) {
                    keyStoreFile = new File(System.getProperty("catalina.base"),
                                            path);
                }
                istream = new FileInputStream(keyStoreFile);
            }

            char[] storePass = null;
            if (pass != null && !"".equals(pass)) {
                storePass = pass.toCharArray();
            }
            ks.load(istream, storePass);
        } catch (FileNotFoundException fnfe) {
            log.error(sm.getString("jsse.keystore_load_failed", type, path,
                    fnfe.getMessage()), fnfe);
            throw fnfe;
        } catch (IOException ioe) {
            // May be expected when working with a trust store
            // Re-throw. Caller will catch and log as required
            throw ioe;
        } catch(Exception ex) {
            String msg = sm.getString("jsse.keystore_load_failed", type, path,
                    ex.getMessage());
            log.error(msg, ex);
            throw new IOException(msg);
        } finally {
            if (istream != null) {
                try {
                    istream.close();
                } catch (IOException ioe) {
                    // Do nothing
                }
            }
        }

        return ks;
    }

    /**
     * Reads the keystore and initializes the SSL socket factory.
     */
    void init() throws IOException {
        try {

            String clientAuthStr = (String) attributes.get("clientauth");
            if("true".equalsIgnoreCase(clientAuthStr) ||
               "yes".equalsIgnoreCase(clientAuthStr)) {
                requireClientAuth = true;
            } else if("want".equalsIgnoreCase(clientAuthStr)) {
                wantClientAuth = true;
            }

            // SSL protocol variant (e.g., TLS, SSL v3, etc.)
            String protocol = (String) attributes.get("protocol");
            if (protocol == null) {
                protocol = defaultProtocol;
            }

            // Certificate encoding algorithm (e.g., SunX509)
            String algorithm = (String) attributes.get("algorithm");
            if (algorithm == null) {
                algorithm = KeyManagerFactory.getDefaultAlgorithm();
            }

            String keystoreType = (String) attributes.get("keystoreType");
            if (keystoreType == null) {
                keystoreType = defaultKeystoreType;
            }

            String keystoreProvider =
                (String) attributes.get("keystoreProvider");

            String trustAlgorithm =
                (String)attributes.get("truststoreAlgorithm");
            if( trustAlgorithm == null ) {
                trustAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            }

            // Create and init SSLContext
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(getKeyManagers(keystoreType, keystoreProvider,
                                 algorithm,
                                 (String) attributes.get("keyAlias")),
                         getTrustManagers(keystoreType, keystoreProvider,
                                 trustAlgorithm),
                         new SecureRandom());

            // Configure SSL session cache
            int sessionCacheSize;
            if (attributes.get("sessionCacheSize") != null) {
                sessionCacheSize = Integer.parseInt(
                        (String)attributes.get("sessionCacheSize"));
            } else {
                sessionCacheSize = defaultSessionCacheSize;
            }
            int sessionTimeout;
            if (attributes.get("sessionTimeout") != null) {
                sessionTimeout = Integer.parseInt(
                        (String)attributes.get("sessionTimeout"));
            } else {
                sessionTimeout = defaultSessionTimeout;
            }
            SSLSessionContext sessionContext =
                context.getServerSessionContext();
            if (sessionContext != null) {
                sessionContext.setSessionCacheSize(sessionCacheSize);
                sessionContext.setSessionTimeout(sessionTimeout);
            }

            // create proxy
            sslProxy = context.getServerSocketFactory();

            // Determine which cipher suites to enable
            String requestedCiphers = (String)attributes.get("ciphers");
            if (ALLOW_ALL_SUPPORTED_CIPHERS.equals(requestedCiphers)) {
                enabledCiphers = sslProxy.getSupportedCipherSuites();
            } else {
                enabledCiphers = getEnabledCiphers(requestedCiphers,
                        sslProxy.getSupportedCipherSuites());
            }

            allowUnsafeLegacyRenegotiation =
                "true".equals(attributes.get("allowUnsafeLegacyRenegotiation"));

            // Check the SSL config is OK
            checkConfig();

        } catch(Exception e) {
            if( e instanceof IOException )
                throw (IOException)e;
            throw new IOException(e.getMessage());
        }
    }

    /**
     * Gets the initialized key managers.
     */
    protected KeyManager[] getKeyManagers(String keystoreType,
                                          String keystoreProvider,
                                          String algorithm,
                                          String keyAlias)
                throws Exception {

        KeyManager[] kms = null;

        String keystorePass = getKeystorePassword();

        KeyStore ks = getKeystore(keystoreType, keystoreProvider, keystorePass);
        if (keyAlias != null && !ks.isKeyEntry(keyAlias)) {
            throw new IOException(sm.getString("jsse.alias_no_key_entry", keyAlias));
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, keystorePass.toCharArray());

        kms = kmf.getKeyManagers();
        if (keyAlias != null) {
            if (JSSESocketFactory.defaultKeystoreType.equals(keystoreType)) {
                keyAlias = keyAlias.toLowerCase();
            }
            for(int i=0; i<kms.length; i++) {
                kms[i] = new JSSEKeyManager((X509KeyManager)kms[i], keyAlias);
            }
        }

        return kms;
    }

    /**
     * Gets the intialized trust managers.
     */
    protected TrustManager[] getTrustManagers(String keystoreType,
            String keystoreProvider, String algorithm)
        throws Exception {
        String crlf = (String) attributes.get("crlFile");

        TrustManager[] tms = null;

        KeyStore trustStore = getTrustStore(keystoreType, keystoreProvider);
        if (trustStore != null) {
            if (crlf == null) {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                tmf.init(trustStore);
                tms = getTrustManagers(tmf);
            } else {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                CertPathParameters params = getParameters(algorithm, crlf, trustStore);
                ManagerFactoryParameters mfp = new CertPathTrustManagerParameters(params);
                tmf.init(mfp);
                tms = getTrustManagers(tmf);
            }
        }

        return tms;
    }

    /**
     * Gets the TrustManagers either from Connector's
     * <code>trustManagerClassName</code> attribute (if set) else from the
     * {@link TrustManagerFactory}.
     * @return The TrustManagers to use for this connector.
     * @throws NoSuchAlgorithmException
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InstantiationException
    */
    protected TrustManager[] getTrustManagers(TrustManagerFactory tmf)
            throws NoSuchAlgorithmException, ClassNotFoundException,
            InstantiationException, IllegalAccessException {

        String className = (String) attributes.get("trustManagerClassName");
        if(className != null && className.length() > 0) {
            ClassLoader classLoader = getClass().getClassLoader();
            Class<?> clazz = classLoader.loadClass(className);
            if(!(TrustManager.class.isAssignableFrom(clazz))){
                throw new InstantiationException(sm.getString(
                        "jsse.invalidTrustManagerClassName", className));
            }
            Object trustManagerObject = clazz.newInstance();
            TrustManager trustManager = (TrustManager) trustManagerObject;
            return new TrustManager[]{ trustManager };
        }
        return tmf.getTrustManagers();
    }

    /**
     * Return the initialization parameters for the TrustManager.
     * Currently, only the default <code>PKIX</code> is supported.
     *
     * @param algorithm The algorithm to get parameters for.
     * @param crlf The path to the CRL file.
     * @param trustStore The configured TrustStore.
     * @return The parameters including the CRLs and TrustStore.
     */
    protected CertPathParameters getParameters(String algorithm,
                                                String crlf,
                                                KeyStore trustStore)
        throws Exception {
        CertPathParameters params = null;
        if("PKIX".equalsIgnoreCase(algorithm)) {
            PKIXBuilderParameters xparams = new PKIXBuilderParameters(trustStore,
                                                                     new X509CertSelector());
            Collection<? extends CRL> crls = getCRLs(crlf);
            CertStoreParameters csp = new CollectionCertStoreParameters(crls);
            CertStore store = CertStore.getInstance("Collection", csp);
            xparams.addCertStore(store);
            xparams.setRevocationEnabled(true);
            String trustLength = (String)attributes.get("trustMaxCertLength");
            if(trustLength != null) {
                try {
                    xparams.setMaxPathLength(Integer.parseInt(trustLength));
                } catch(Exception ex) {
                    log.warn("Bad maxCertLength: "+trustLength);
                }
            }

            params = xparams;
        } else {
            throw new CRLException("CRLs not supported for type: "+algorithm);
        }
        return params;
    }


    /**
     * Load the collection of CRLs.
     *
     */
    protected Collection<? extends CRL> getCRLs(String crlf)
        throws IOException, CRLException, CertificateException {

        File crlFile = new File(crlf);
        if( !crlFile.isAbsolute() ) {
            crlFile = new File(System.getProperty("catalina.base"), crlf);
        }
        Collection<? extends CRL> crls = null;
        InputStream is = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            is = new FileInputStream(crlFile);
            crls = cf.generateCRLs(is);
        } catch(IOException iex) {
            throw iex;
        } catch(CRLException crle) {
            throw crle;
        } catch(CertificateException ce) {
            throw ce;
        } finally {
            if(is != null) {
                try{
                    is.close();
                } catch(Exception ex) {
                }
            }
        }
        return crls;
    }

    /**
     * Set the SSL protocol variants to be enabled.
     * @param socket the SSLServerSocket.
     * @param protocols the protocols to use.
     */
    protected void setEnabledProtocols(SSLServerSocket socket, String []protocols){
        if (protocols == null) {
            socket.setEnabledProtocols(defaultServerProtocols);
        } else {
            socket.setEnabledProtocols(protocols);
        }
    }

    /**
     * Determines the SSL protocol variants to be enabled.
     *
     * @param socket The socket to get supported list from.
     * @param requestedProtocols Comma-separated list of requested SSL
     * protocol variants
     *
     * @return Array of SSL protocol variants to be enabled, or null if none of
     * the requested protocol variants are supported
     */
    protected String[] getEnabledProtocols(SSLServerSocket socket,
                                           String requestedProtocols){
        Set<String> supportedProtocols = new HashSet<String>();
        for (String supportedProtocol : socket.getSupportedProtocols()) {
            supportedProtocols.add(supportedProtocol);
        }

        if (requestedProtocols == null) {
            return defaultServerProtocols;
        }

        String[] requestedProtocolsArr = requestedProtocols.split(",");
        List<String> enabledProtocols = new ArrayList<String>(requestedProtocolsArr.length);

        for (String requestedProtocol : requestedProtocolsArr) {
            String requestedProtocolTrim = requestedProtocol.trim();
            if (supportedProtocols.contains(requestedProtocolTrim)) {
                enabledProtocols.add(requestedProtocolTrim);
            } else {
                log.warn(sm.getString("jsse.unsupportedProtocol", requestedProtocolTrim));
            }
        }

        return enabledProtocols.toArray(new String[enabledProtocols.size()]);
    }

    /**
     * Configure Client authentication for this version of JSSE.  The
     * JSSE included in Java 1.4 supports the 'want' value.  Prior
     * versions of JSSE will treat 'want' as 'false'.
     * @param socket the SSLServerSocket
     */
    protected void configureClientAuth(SSLServerSocket socket){
        if (wantClientAuth){
            socket.setWantClientAuth(wantClientAuth);
        } else {
            socket.setNeedClientAuth(requireClientAuth);
        }
    }

    /**
     * Configure Client authentication for this version of JSSE.  The
     * JSSE included in Java 1.4 supports the 'want' value.  Prior
     * versions of JSSE will treat 'want' as 'false'.
     * @param socket the SSLSocket
     */
    protected void configureClientAuth(SSLSocket socket){
        // Per JavaDocs: SSLSockets returned from
        // SSLServerSocket.accept() inherit this setting.
    }

    /**
     * Configures the given SSL server socket with the requested cipher suites,
     * protocol versions, and need for client authentication
     */
    private void initServerSocket(ServerSocket ssocket) {

        SSLServerSocket socket = (SSLServerSocket) ssocket;

        if (enabledCiphers != null) {
            socket.setEnabledCipherSuites(enabledCiphers);
        }

        String requestedProtocols = (String) attributes.get("protocols");
        socket.setEnabledProtocols(getEnabledProtocols(socket, requestedProtocols));

        // we don't know if client auth is needed -
        // after parsing the request we may re-handshake
        configureClientAuth(socket);
    }

    /**
     * Checks that the certificate is compatible with the enabled cipher suites.
     * If we don't check now, the JIoEndpoint can enter a nasty logging loop.
     * See bug 45528.
     */
    private void checkConfig() throws IOException {
        // Create an unbound server socket
        ServerSocket socket = sslProxy.createServerSocket();
        initServerSocket(socket);

        try {
            // Set the timeout to 1ms as all we care about is if it throws an
            // SSLException on accept.
            socket.setSoTimeout(1);

            socket.accept();
            // Will never get here - no client can connect to an unbound port
        } catch (SSLException ssle) {
            // SSL configuration is invalid. Possibly cert doesn't match ciphers
            IOException ioe = new IOException(sm.getString(
                    "jsse.invalid_ssl_conf", ssle.getMessage()));
            ioe.initCause(ssle);
            throw ioe;
        } catch (Exception e) {
            /*
             * Possible ways of getting here
             * socket.accept() throws a SecurityException
             * socket.setSoTimeout() throws a SocketException
             * socket.accept() throws some other exception (after a JDK change)
             *      In these cases the test won't work so carry on - essentially
             *      the behaviour before this patch
             * socket.accept() throws a SocketTimeoutException
             *      In this case all is well so carry on
             */
        } finally {
            // Should be open here but just in case
            if (!socket.isClosed()) {
                socket.close();
            }
        }
    }


    public static String[] filterInsecureProtocols(String[] protocols) {
        if (protocols == null) {
            return null;
        }

        List<String> result = new ArrayList<String>(protocols.length);
        for (String protocol : protocols) {
            if (protocol == null || protocol.toUpperCase(Locale.ENGLISH).contains("SSL")) {
                log.debug(sm.getString("jsse.excludeDefaultProtocol", protocol));
            } else {
                result.add(protocol);
            }
        }
        return result.toArray(new String[result.size()]);
    }
}
