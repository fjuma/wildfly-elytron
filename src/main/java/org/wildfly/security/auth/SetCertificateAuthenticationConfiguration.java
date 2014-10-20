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

package org.wildfly.security.auth;

import java.io.Closeable;
import java.io.InputStream;
import java.io.IOException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500PrivateCredential;

import org.wildfly.security.auth.callback.CredentialCallback;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetCertificateAuthenticationConfiguration extends AuthenticationConfiguration {

    private final Object certificate;
    private final PrivateKey privateKey;

    SetCertificateAuthenticationConfiguration(final AuthenticationConfiguration parent, final URL certificateUrl, final PrivateKey privateKey) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.certificate = certificateUrl;
        this.privateKey = privateKey;
    }

    SetCertificateAuthenticationConfiguration(final AuthenticationConfiguration parent, final X509Certificate certificate, final PrivateKey privateKey) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        if (certificate instanceof URL) {
            return new SetCertificateAuthenticationConfiguration(newParent, (URL) certificate, privateKey);
        } else if (certificate instanceof X509Certificate) {
            return new SetCertificateAuthenticationConfiguration(newParent, (X509Certificate) certificate, privateKey);
        }
        throw new IllegalStateException();
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            final CredentialCallback credentialCallback = (CredentialCallback) callback;
            if (credentialCallback.isCredentialTypeSupported(X500PrivateCredential.class)) {
                if (certificate instanceof X509Certificate) {
                    credentialCallback.setCredential(new X500PrivateCredential((X509Certificate) certificate, privateKey));
                    return;
                } else if (certificate instanceof URL) {
                    InputStream in;
                    try {
                        in = ((URL) certificate).openStream();
                    } catch (IOException e) {
                        throw new IOException("Unable to read certificate");
                    }
                    X509Certificate cert;
                    try {
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                        cert = (X509Certificate) certificateFactory.generateCertificate(in);
                    } catch (CertificateException e) {
                        throw new IOException("Unable to read certificate", e);
                    } finally {
                        safeClose(in);
                    }
                    credentialCallback.setCredential(new X500PrivateCredential(cert, privateKey));
                    return;
                }
            }
        }
        super.handleCallback(callbacks, index);
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
