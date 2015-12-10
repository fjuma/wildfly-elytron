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

package org.wildfly.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SecurityDomainTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager delegate;
    private final SecurityDomain securityDomain;
    private final EvidenceDecoder evidenceDecoder;

    SecurityDomainTrustManager(final X509ExtendedTrustManager delegate, final SecurityDomain securityDomain, final EvidenceDecoder evidenceDecoder) {
        this.delegate = delegate;
        this.securityDomain = securityDomain;
        this.evidenceDecoder = evidenceDecoder;
    }

    SecurityDomainTrustManager(final X509TrustManager delegate, final SecurityDomain securityDomain, final EvidenceDecoder evidenceDecoder) {
        this(delegate instanceof X509ExtendedTrustManager ?
                (X509ExtendedTrustManager) delegate :
                new WrappingX509ExtendedTrustManager(delegate), securityDomain, evidenceDecoder);
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
        doClientTrustCheck(chain, authType, ((SSLSocket) socket).getHandshakeSession());
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, sslEngine);
        doClientTrustCheck(chain, authType, sslEngine.getHandshakeSession());
    }

    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        doClientTrustCheck(chain, authType, null);
    }

    private void doClientTrustCheck(final X509Certificate[] chain, final String authType, final SSLSession handshakeSession) throws CertificateException {
        Assert.checkNotNullParam("chain", chain);
        Assert.checkNotNullParam("authType", authType);
        if (chain.length == 0) {
            throw ElytronMessages.log.emptyChainNotTrusted();
        }
        final X509Certificate subjectCertificate = chain[0];
        final X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(subjectCertificate);
        Principal principal = evidenceDecoder.getPrincipalFromEvidence(evidence);
        final ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();
        boolean ok = false;
        try {
            authenticationContext.setAuthenticationPrincipal(principal);

            final SupportLevel evidenceSupport = authenticationContext.getEvidenceVerifySupport(X509PeerCertificateChainEvidence.class, evidence.getAlgorithm());
            if (evidenceSupport.mayBeSupported() && authenticationContext.verifyEvidence(evidence)) {
                authenticationContext.succeed();
                if (handshakeSession != null) {
                    handshakeSession.putValue(SSLUtils.SSL_SESSION_IDENTITY_KEY, authenticationContext.getAuthorizedIdentity());
                }
                ok = true;
            }
            throw ElytronMessages.log.notTrusted(principal);
        } catch (RealmUnavailableException e) {
            throw ElytronMessages.log.notTrustedRealmProblem(e, principal);
        } finally {
            if (! ok) {
                authenticationContext.fail();
            }
        }
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, sslEngine);
    }

    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
