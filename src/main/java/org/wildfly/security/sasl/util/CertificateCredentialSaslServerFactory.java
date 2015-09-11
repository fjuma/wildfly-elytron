/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.util;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.x500.X509CertificateChainPrivateCredential;

/**
 * A {@link SaslServerFactory} which sets the server's credentials using the given certificate credential.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class CertificateCredentialSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param privateKey the server private key
     * @param certificateChain the server certificate chain
     */
    public CertificateCredentialSaslServerFactory(final SaslServerFactory delegate, final PrivateKey privateKey, final X509Certificate... certificateChain) {
        super(delegate);
        Assert.checkNotNullParam("privateKey", privateKey);
        Assert.checkNotNullParam("certificateChain", certificateChain);
        this.credentialFactory = new FixedSecurityFactory<>(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param credential the credential containing the private key and certificate chain
     */
    public CertificateCredentialSaslServerFactory(final SaslServerFactory delegate, final X509CertificateChainPrivateCredential credential) {
        super(delegate);
        Assert.checkNotNullParam("credential", credential);
        this.credentialFactory = new FixedSecurityFactory<>(credential);
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param credentialFactory a factory which produces the credential containing the private key and certificate chain
     */
    public CertificateCredentialSaslServerFactory(final SaslServerFactory delegate, final SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory) {
        super(delegate);
        Assert.checkNotNullParam("credentialFactory", credentialFactory);
        this.credentialFactory = credentialFactory;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof CredentialCallback) {
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    final X509CertificateChainPrivateCredential certChainPrivateCredential;
                    try {
                        certChainPrivateCredential = credentialFactory.create();
                    } catch (GeneralSecurityException e) {
                        throw log.unableToReadCredential(e);
                    }
                    if (credentialCallback.isCredentialSupported(certChainPrivateCredential.getClass(), certChainPrivateCredential.getPrivateKey().getAlgorithm())) {
                        credentialCallback.setCredential(certChainPrivateCredential);
                        iterator.remove();
                    }
                }
            }
            if (! list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }
}
