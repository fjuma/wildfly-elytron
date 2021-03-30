/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.EnvUtil;
import static org.wildfly.security.http.oidc.Oidc.PROTOCOL_CLASSPATH;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.StrictHostnameVerifier;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.ssl.SSLContexts;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.wildfly.security.json.util.JsonSerialization;

/**
 * Abstraction for creating HttpClients. Allows SSL configuration.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class HttpClientBuilder {

    public static enum HostnameVerificationPolicy {
        /**
         * Hostname verification is not done on the server's certificate
         */
        ANY,
        /**
         * Allows wildcards in subdomain names i.e. *.foo.com
         */
        WILDCARD
    }

    private KeyStore truststore;
    private boolean disableTrustManager;
    private boolean disableCookieCache = true;
    private KeyStore clientKeyStore;
    private String clientPrivateKeyPassword;
    private int connectionPoolSize = 100;
    private HostnameVerificationPolicy policy = HostnameVerificationPolicy.WILDCARD;
    private HttpHost proxyHost;
    private HostnameVerifier verifier = null;
    private SSLContext sslContext;

    /**
     * This should only be set if you cannot or do not want to verify the identity of the
     * host you are communicating with.
     *
     * @return the builder
     */
    public HttpClientBuilder setDisableTrustManager() {
        this.disableTrustManager = true;
        return this;
    }

    public HttpClientBuilder setDisableCookieCache(boolean disable) {
        this.disableCookieCache = disable;
        return this;
    }

    public HttpClientBuilder setKeyStore(KeyStore keyStore, String password) {
        this.clientKeyStore = keyStore;
        this.clientPrivateKeyPassword = password;
        return this;
    }

    public HttpClientBuilder setConnectionPoolSize(int connectionPoolSize) {
        this.connectionPoolSize = connectionPoolSize;
        return this;
    }

    public HttpClientBuilder setHostnameVerification(HostnameVerificationPolicy policy) {
        this.policy = policy;
        return this;
    }

    public HttpClientBuilder setTrustStore(KeyStore truststore) {
        this.truststore = truststore;
        return this;
    }

    public HttpClient build() {
        HostnameVerifier verifier = null;
        if (this.verifier != null) verifier = new VerifierWrapper(this.verifier);
        else {
            switch (policy) {
                case ANY:
                    verifier = new NoopHostnameVerifier();
                    break;
                case WILDCARD:
                    verifier = new DefaultHostnameVerifier();
                    break;
            }
        }
        try {
            SSLConnectionSocketFactory sslSocketFactory = null;
            SSLContext theContext = sslContext;
            if (disableTrustManager) {
                theContext = SSLContext.getInstance("SSL");
                theContext.init(null, new TrustManager[]{new PassthroughTrustManager()},
                        new SecureRandom());
                verifier = new NoopHostnameVerifier();
                sslSocketFactory = new SSLConnectionSocketFactory(theContext, verifier);
            } else if (theContext != null) {
                sslSocketFactory = new SSLConnectionSocketFactory(theContext, verifier);
            } else if (clientKeyStore != null || truststore != null) {
                sslSocketFactory = new SSLConnectionSocketFactory(SSLContexts.custom()
                        .setProtocol(SSLConnectionSocketFactory.TLS)
                        .setSecureRandom(null)
                        .loadKeyMaterial(clientKeyStore, clientPrivateKeyPassword != null ? clientPrivateKeyPassword.toCharArray() : null)
                        .loadTrustMaterial(truststore,null)
                        .build(), verifier);
            } else {
                final SSLContext tlsContext = SSLContext.getInstance(SSLConnectionSocketFactory.TLS);
                tlsContext.init(null, null, null);
                sslSocketFactory = new SSLConnectionSocketFactory(tlsContext, verifier);
            }
            SchemeRegistry registry = new SchemeRegistry();
            registry.register(
                    new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
            Scheme httpsScheme = new Scheme("https", 443, sslSocketFactory);
            registry.register(httpsScheme);
            ClientConnectionManager cm = null;
            if (connectionPoolSize > 0) {
                ThreadSafeClientConnManager tcm = new ThreadSafeClientConnManager(registry, connectionTTL, connectionTTLUnit);
                tcm.setMaxTotal(connectionPoolSize);
                if (maxPooledPerRoute == 0) maxPooledPerRoute = connectionPoolSize;
                tcm.setDefaultMaxPerRoute(maxPooledPerRoute);
                cm = tcm;

            } else {
                cm = new SingleClientConnManager(registry);
            }
            BasicHttpParams params = new BasicHttpParams();
            params.setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.BROWSER_COMPATIBILITY);

            if (proxyHost != null) {
                params.setParameter(ConnRoutePNames.DEFAULT_PROXY, proxyHost);
            }

            if (socketTimeout > -1) {
                HttpConnectionParams.setSoTimeout(params, (int) socketTimeoutUnits.toMillis(socketTimeout));

            }
            if (establishConnectionTimeout > -1) {
                HttpConnectionParams.setConnectionTimeout(params, (int) establishConnectionTimeoutUnits.toMillis(establishConnectionTimeout));
            }
            DefaultHttpClient client = new DefaultHttpClient(cm, params);

            if (disableCookieCache) {
                client.setCookieStore(new CookieStore() {
                    @Override
                    public void addCookie(Cookie cookie) {
                        //To change body of implemented methods use File | Settings | File Templates.
                    }

                    @Override
                    public List<Cookie> getCookies() {
                        return Collections.emptyList();
                    }

                    @Override
                    public boolean clearExpired(Date date) {
                        return false;  //To change body of implemented methods use File | Settings | File Templates.
                    }

                    @Override
                    public void clear() {
                        //To change body of implemented methods use File | Settings | File Templates.
                    }
                });

            }
            return client;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public HttpClient build(OidcJsonConfiguration oidcClientConfig) {
        setDisableCookieCache(true); // disable cookie cache as we don't want sticky sessions for load balancing

        String truststorePath = oidcClientConfig.getTruststore();
        if (truststorePath != null) {
            truststorePath = EnvUtil.replace(truststorePath);
            String truststorePassword = oidcClientConfig.getTruststorePassword();
            try {
                this.truststore = loadKeyStore(truststorePath, truststorePassword);
            } catch (Exception e) {
                throw log.unableToLoadKeyStore(e);
            }
        }
        String clientKeystore = oidcClientConfig.getClientKeystore();
        if (clientKeystore != null) {
            clientKeystore = EnvUtil.replace(clientKeystore);
            String clientKeystorePassword = oidcClientConfig.getClientKeystorePassword();
            try {
                KeyStore clientCertKeystore = loadKeyStore(clientKeystore, clientKeystorePassword);
                setKeyStore(clientCertKeystore, clientKeystorePassword);
            } catch (Exception e) {
                throw log.unableToLoadTrustStore(e);
            }
        }
        int size = 10;
        if (oidcClientConfig.getConnectionPoolSize() > 0) {
            size = oidcClientConfig.getConnectionPoolSize();
        }
        HttpClientBuilder.HostnameVerificationPolicy policy = HttpClientBuilder.HostnameVerificationPolicy.WILDCARD;
        if (oidcClientConfig.isAllowAnyHostname()) {
            policy = HttpClientBuilder.HostnameVerificationPolicy.ANY;
        }
        setConnectionPoolSize(size);
        setHostnameVerification(policy);
        if (oidcClientConfig.isDisableTrustManager()) {
            setDisableTrustManager();
        } else {
            setTrustStore(truststore);
        }

        configureProxyForAuthServerIfProvided(oidcClientConfig);

        return build();
    }

    /**
     * Configures a the proxy to use for auth-server requests if provided.
     * <p>
     * If the given {@link OidcJsonConfiguration} contains the attribute {@code proxy-url} we use the
     * given URL as a proxy server, otherwise the proxy configuration is ignored.
     * </p>
     *
     * @param adapterConfig
     */
    private void configureProxyForAuthServerIfProvided(OidcJsonConfiguration adapterConfig) {
        if (adapterConfig == null || adapterConfig.getProxyUrl() == null || adapterConfig.getProxyUrl().trim().isEmpty()) {
            return;
        }
        URI uri = URI.create(adapterConfig.getProxyUrl());
        this.proxyHost = new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());
    }

    private static KeyStore loadKeyStore(String filename, String password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream trustStream = null;
        if (filename.startsWith(PROTOCOL_CLASSPATH)) {
            String resourcePath = filename.replace(PROTOCOL_CLASSPATH, "");
            if (Thread.currentThread().getContextClassLoader() != null) {
                trustStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
            }
            if (trustStream == null) {
                trustStream = HttpClientBuilder.class.getResourceAsStream(resourcePath);
            }
            if (trustStream == null) {
                throw log.unableToFindTrustStoreFile(filename);
            }
        } else {
            trustStream = new FileInputStream(new File(filename));
        }
        try (InputStream is = trustStream) {
            trustStore.load(is, password.toCharArray());
        }
        return trustStore;
    }

    static class VerifierWrapper implements HostnameVerifier {
        protected HostnameVerifier verifier;

        VerifierWrapper(HostnameVerifier verifier) {
            this.verifier = verifier;
        }

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return verifier.verify(s, sslSession);
        }
    }
}
