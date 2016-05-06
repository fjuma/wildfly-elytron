/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.x500.X500;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetKeyStoreCredentialAuthenticationConfiguration extends AuthenticationConfiguration {

    private final SecurityFactory<KeyStore.Entry> entryFactory;

    SetKeyStoreCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final KeyStore keyStore, final String alias, final KeyStore.ProtectionParameter protectionParameter) {
        this(parent, new OneTimeSecurityFactory<>(new KeyStoreEntrySecurityFactory(keyStore, alias, protectionParameter)));
    }

    SetKeyStoreCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityFactory<KeyStore.Entry> entryFactory) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyManagerCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class).without(SetForwardAuthenticationConfiguration.class));
        this.entryFactory = entryFactory;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetKeyStoreCredentialAuthenticationConfiguration(newParent, entryFactory);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            final KeyStore.Entry entry;
            try {
                entry = entryFactory.create();
            } catch (GeneralSecurityException e) {
                throw log.unableToReadCredential(e);
            }
            if (entry instanceof PasswordEntry) {
                credentialCallback.setCredential(new PasswordCredential(((PasswordEntry) entry).getPassword()));
                return;
            } else if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                if (certificateChain != null && certificateChain.length != 0 && credentialCallback.isCredentialTypeSupported(X509CertificateChainPrivateCredential.class, privateKey.getAlgorithm())) {
                    try {
                        final X509Certificate[] x509Certificates = X500.asX509CertificateArray(certificateChain);
                        credentialCallback.setCredential(new X509CertificateChainPrivateCredential(privateKey, x509Certificates));
                        return;
                    } catch (ArrayStoreException ignored) {
                    }
                }
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                final Certificate certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
                if (certificate instanceof X509Certificate) {
                    credentialCallback.setCredential(new X509CertificateChainPublicCredential((X509Certificate) certificate));
                    return;
                }
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                credentialCallback.setCredential(new SecretKeyCredential(((KeyStore.SecretKeyEntry) entry).getSecretKey()));
                return;
            }
        } else if (callback instanceof PasswordCallback) {
            final KeyStore.Entry entry;
            try {
                entry = entryFactory.create();
            } catch (GeneralSecurityException e) {
                throw log.unableToReadCredential(e);
            }
            if (entry instanceof PasswordEntry) {
                final Password password = ((PasswordEntry) entry).getPassword();
                final PasswordFactory passwordFactory;
                try {
                    passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    throw log.unableToReadCredential(e);
                }
                final Password realPassword;
                try {
                    realPassword = passwordFactory.translate(password);
                } catch (InvalidKeyException e) {
                    throw log.unableToReadCredential(e);
                }
                final ClearPasswordSpec keySpec;
                try {
                    keySpec = passwordFactory.getKeySpec(realPassword, ClearPasswordSpec.class);
                } catch (InvalidKeySpecException e) {
                    throw log.unableToReadCredential(e);
                }
                ((PasswordCallback) callback).setPassword(keySpec.getEncodedPassword());
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        // filter the mechanism based on the credential we have
        final KeyStore.Entry entry;
        try {
            entry = entryFactory.create();
        } catch (GeneralSecurityException e) {
            return super.filterOneSaslMechanism(mechanismName);
        }
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        if (types == null) {
            // we don't really know anything about this mech; leave it for a superclass to figure out
            return super.filterOneSaslMechanism(mechanismName);
        }
        // only these credential types really inform mech selection
        if (entry instanceof PasswordEntry) {
            Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, PasswordCredential.class);
            return types.contains(PasswordCredential.class) && (algorithms.isEmpty() || algorithms.contains(((PasswordEntry) entry).getPassword().getAlgorithm())) || super.filterOneSaslMechanism(mechanismName);
        } else if (entry instanceof KeyStore.PrivateKeyEntry) {
            Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, X509CertificateChainPrivateCredential.class);
            return types.contains(X509CertificateChainPrivateCredential.class) && (algorithms.isEmpty() || algorithms.contains(((KeyStore.PrivateKeyEntry) entry).getPrivateKey().getAlgorithm())) || super.filterOneSaslMechanism(mechanismName);
        } else {
            return super.filterOneSaslMechanism(mechanismName);
        }
    }
}
