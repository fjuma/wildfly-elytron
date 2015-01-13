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

package org.wildfly.security.sasl.entity;

import static org.wildfly.security.asn1.ASN1.*;
import static org.wildfly.security.sasl.entity.Entity.*;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.auth.callback.TrustManagerCallback;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.ByteStringBuilder;

/**
 * SaslClient for the ISO/IEC 9798-3 authentication mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc3163">RFC 3163</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class EntitySaslClient extends AbstractSaslClient {

    private static final int ST_CHALLENGE_RESPONSE = 1;
    private static final int ST_RESPONSE_SENT = 2;

    private final SecureRandom secureRandom;
    private final Signature signature;
    private final boolean serverAuth;
    private byte[] randomA;
    private byte[] randomB;
    private X509TrustManager defaultTrustManager;

    EntitySaslClient(final String mechanismName, final Signature signature, final SecureRandom secureRandom, final String protocol,
            final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, false);
        this.signature = signature;
        this.secureRandom = secureRandom;
        serverAuth = "true".equals(getStringProperty(props, Sasl.SERVER_AUTH, "false"));
    }

    @Override
    public void init() {
        setNegotiationState(ST_CHALLENGE_RESPONSE);
    }

    @Override
    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        switch (state) {
            case ST_CHALLENGE_RESPONSE: {
                DERDecoder decoder = new DERDecoder(challenge);
                Collection<List<?>> trustedAuthorities = null;
                try {
                    decoder.startSequence();

                    // randomB
                    randomB = decoder.decodeOctetString();

                    // entityB
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                        // TODO: entityB was provided, need to decode
                        decoder.decodeImplicit(0);
                    }

                    // certPref
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 1, true)) {
                        decoder.decodeImplicit(1);
                        trustedAuthorities = EntityUtils.decodeTrustedAuthorities(decoder);
                    }
                    decoder.endSequence();
                } catch (ASN1Exception e) {
                    throw new SaslException("Invalid server message");
                }

                // Construct TokenAB, where:
                // TokenAB ::= SEQUENCE {
                //      randomA         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      certA           [1] CertData,
                //      authID          [2] GeneralNames OPTIONAL,
                //      signature       SIGNATURE { TBSDataAB }
                // }
                // TBSDataAB ::= SEQUENCE {
                //      randomA         RandomNumber,
                //      randomB         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      authID          [1] GeneralNames OPTIONAL
                // }
                // CertData ::= CHOICE {
                //      certificateSet  SET SIZE (1..MAX) OF Certificate
                //      certURL         IA5String
                // }
                // SIGNATURE { ToBeSigned } ::= SEQUENCE {
                //      algorithm       AlgorithmIdentifier,
                //      signature       BIT STRING
                // }
                ByteStringBuilder tokenAB = new ByteStringBuilder();
                DEREncoder encoder = new DEREncoder(tokenAB);
                encoder.startSequence();

                // randomA
                randomA = EntityUtils.encodeRandom(encoder, secureRandom);

                // entityB
                encoder.encodeImplicit(0);
                EntityUtils.encodeGeneralNames(encoder, DNS_NAME, getServerName());

                // certA (try obtaining a certificate chain first)
                encoder.startExplicit(1);
                TrustedAuthoritiesCallback trustedAuthoritiesCallback = new TrustedAuthoritiesCallback();
                trustedAuthoritiesCallback.setTrustedAuthorities(trustedAuthorities); // Server's preferred certificates
                CredentialCallback credentialCallback = new CredentialCallback(X509Certificate[].class);
                handleCallbacks(trustedAuthoritiesCallback, credentialCallback);
                X509Certificate[] certChain = (X509Certificate[]) credentialCallback.getCredential();
                if ((certChain != null) && (certChain.length > 0)) {
                    try {
                        EntityUtils.encodeX509CertificateChain(encoder, certChain);
                    } catch (ASN1Exception e) {
                        throw new SaslException("Unable to encode the certificate chain", e);
                    }
                } else {
                    // Try obtaining a certificate URL
                    credentialCallback = new CredentialCallback(String.class);
                    handleCallbacks(trustedAuthoritiesCallback, credentialCallback);
                    String certURL = (String) credentialCallback.getCredential();
                    if (certURL == null) {
                        throw new SaslException("Invalid certificate data");
                    }
                    encoder.encodeIA5String(certURL);
                }
                encoder.endExplicit();

                // authID
                final String authorizationId = getAuthorizationId();
                if (authorizationId != null) {
                    encoder.encodeImplicit(2);
                    // TODO: Encode a GeneralNames element based on this string (e.g, RFC822 name or possibly use a callback to determine the name type)
                }

                // Private key
                credentialCallback = new CredentialCallback(PrivateKey.class);
                handleCallbacks(credentialCallback);
                PrivateKey privateKey = (PrivateKey) credentialCallback.getCredential();
                if (privateKey == null) {
                    throw new SaslException("Private key is null");
                }

                // TBSDataAB
                ByteStringBuilder tbsDataAB = new ByteStringBuilder();
                DEREncoder tbsEncoder = new DEREncoder(tbsDataAB);
                tbsEncoder.startSequence();
                tbsEncoder.encodeOctetString(randomA);
                tbsEncoder.encodeOctetString(randomB);
                tbsEncoder.encodeImplicit(0);
                EntityUtils.encodeGeneralNames(tbsEncoder, DNS_NAME, getServerName());
                if (authorizationId != null) {
                    encoder.encodeImplicit(1);
                    // TODO: Encode a GeneralNames element based on this string (e.g, RFC822 name or possibly use a callback to determine the name type)
                }
                tbsEncoder.endSequence();

                // Signature
                byte[] signatureBytes;
                try {
                    signature.initSign(privateKey);
                    signature.update(tbsDataAB.toArray());
                    signatureBytes = signature.sign();
                } catch (SignatureException | InvalidKeyException e) {
                    throw new SaslException("Unable to create signature", e);
                }

                encoder.startSequence();
                EntityUtils.encodeAlgorithmIdentifier(encoder, signature.getAlgorithm());
                encoder.encodeBitString(signatureBytes);
                encoder.endSequence();

                encoder.endSequence();
                setNegotiationState(ST_RESPONSE_SENT);
                return tokenAB.toArray();
            }
            case ST_RESPONSE_SENT: {
                if (serverAuth) {
                    DERDecoder decoder = new DERDecoder(challenge);
                    try {
                        decoder.startSequence();
                        byte[] randomC = decoder.decodeOctetString();
                        if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                            // TODO: Get entityA and verify that it matches the client's distinguishing identifier
                        }

                        // Get the server's certificate data and verify it
                        decoder.startExplicit(1);
                        X509Certificate[] serverCertChain = EntityUtils.decodeCertificateData(decoder);
                        decoder.endExplicit();

                        X509Certificate serverCert = serverCertChain[0];
                        TrustManagerCallback trustManagerCallback = new TrustManagerCallback(X509TrustManager.class);
                        handleCallbacks(trustManagerCallback);
                        X509TrustManager trustManager = (X509TrustManager) trustManagerCallback.getTrustManager();
                        if (trustManager == null) {
                            if (defaultTrustManager == null) {
                                defaultTrustManager = EntityUtils.getDefaultTrustManager();
                            }
                            trustManager = defaultTrustManager;
                        }

                        try {
                            trustManager.checkServerTrusted(serverCertChain, serverCert.getPublicKey().getAlgorithm());
                        } catch (CertificateException e) {
                            throw new SaslException("Server authenticity cannot be verified", e);
                        }

                        // Get the server's signature and verify it
                        decoder.startSequence();
                        decoder.skipElement();
                        byte[] serverSignature = decoder.decodeBitString();
                        decoder.endSequence();

                        ByteStringBuilder tbsDataBA = new ByteStringBuilder();
                        DEREncoder tbsEncoder = new DEREncoder(tbsDataBA);
                        tbsEncoder.startSequence();
                        tbsEncoder.encodeOctetString(randomB);
                        tbsEncoder.encodeOctetString(randomA);
                        tbsEncoder.encodeOctetString(randomC);
                        // TODO: Add in GeneralNames element for entityA only if it was provided
                        tbsEncoder.endSequence();

                        try {
                            signature.initVerify(serverCert);
                            signature.update(tbsDataBA.toArray());
                            if (! signature.verify(serverSignature)) {
                                setNegotiationState(FAILED_STATE);
                                throw new SaslException("Server authenticity cannot be verified");
                            }
                        } catch (SignatureException | InvalidKeyException e) {
                            throw new SaslException("Unable to verify server signature", e);
                        }
                        decoder.endSequence();
                    } catch (ASN1Exception e) {
                        throw new SaslException("Invalid server message");
                    }
                }
                negotiationComplete();
                return null;
            }
            default: throw new IllegalStateException();
        }
    }
}
