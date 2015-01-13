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
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.sasl.util.ByteStringBuilder;

/**
 * SaslServer for the ISO/IEC 9798-3 authentication mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc3163">RFC 3163</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class EntitySaslServer extends AbstractSaslServer {

    private static final int ST_CHALLENGE = 1;
    private static final int ST_PROCESS_RESPONSE = 2;

    private final SecureRandom secureRandom;
    private final Signature signature;
    private final boolean serverAuth;
    private String authorizationID;
    private byte[] randomB;
    private X509TrustManager defaultTrustManager;

    EntitySaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final Map<String, ?> props, final Signature signature, final SecureRandom secureRandom) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.signature = signature;
        this.secureRandom = secureRandom;
        serverAuth = "true".equals(getStringProperty(props, Sasl.SERVER_AUTH, "false"));
    }

    public void init() {
        setNegotiationState(ST_CHALLENGE);
    }

    public String getAuthorizationID() {
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        switch (state) {
            case ST_CHALLENGE: {
                if ((response != null) && (response.length != 0)) {
                    throw new SaslException("Non-empty message when sending challenge");
                }
                // Construct TokenBA1, where:
                // TokenBA1 ::= SEQUENCE {
                //      randomB         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      certPref        [1] SEQUENCE SIZE (1..MAX) of TrustedAuth OPTIONAL
                // }
                // TrustedAuth ::= CHOICE {
                //      authorityName           [0] Name,
                //      issuerNameHash          [1] OCTET STRING,
                //      issuerKeyHash           [2] OCTET STRING,
                //      authorityCertificate    [3] Certificate,
                //      pkcs15KeyHash           [4] OCTET STRING
                // }
                ByteStringBuilder tokenBA1 = new ByteStringBuilder();
                DEREncoder encoder = new DEREncoder(tokenBA1);
                encoder.startSequence();

                // randomB
                randomB = EntityUtils.encodeRandom(encoder, secureRandom);

                // entityB
                encoder.encodeImplicit(0);
                EntityUtils.encodeGeneralNames(encoder, DNS_NAME, getServerName());

                // certPref
                TrustedAuthoritiesCallback trustedAuthoritiesCallback = new TrustedAuthoritiesCallback();
                handleCallbacks(trustedAuthoritiesCallback);
                Collection<List<?>> trustedAuthorities = trustedAuthoritiesCallback.getTrustedAuthorities();
                if ((trustedAuthorities != null) && (! trustedAuthorities.isEmpty())) {
                    encoder.encodeImplicit(1);
                    EntityUtils.encodeTrustedAuthorities(encoder, trustedAuthorities);
                }
                encoder.endSequence();
                setNegotiationState(ST_PROCESS_RESPONSE);
                return tokenBA1.toArray();
            }
            case ST_PROCESS_RESPONSE: {
                DERDecoder decoder = new DERDecoder(response);
                byte[] randomA;
                X509Certificate[] clientCertChain;
                X509Certificate clientCert;
                String clientName;
                try {
                    decoder.startSequence();
                    randomA = decoder.decodeOctetString();
                    // TODO: entityB as GeneralNames - OPTIONAL, decoder.decodeImplicit(0)

                    // Get the client's certificate data and verify it
                    decoder.startExplicit(1);
                    clientCertChain = EntityUtils.decodeCertificateData(decoder);
                    decoder.endExplicit();

                    clientCert = clientCertChain[0];
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
                        trustManager.checkClientTrusted(clientCertChain, clientCert.getPublicKey().getAlgorithm());
                    } catch (CertificateException e) {
                        throw new SaslException("Client authenticity cannot be verified", e);
                    }

                    // TODO: authID as GeneralNames - OPTIONAL, decoder.decodeImplicit(2)
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, true)) {
                        // The client provided an authID
                    } else {
                        // Use the identity from the client's X.509 certificate
                        //clientCert.getSubjectX500Principal()
                    }

                    // Get the client's signature and verify it
                    decoder.startSequence();
                    decoder.skipElement();
                    byte[] clientSignature = decoder.decodeBitString();
                    decoder.endSequence();

                    ByteStringBuilder tbsDataAB = new ByteStringBuilder();
                    DEREncoder tbsEncoder = new DEREncoder(tbsDataAB);
                    tbsEncoder.startSequence();
                    tbsEncoder.encodeOctetString(randomA);
                    tbsEncoder.encodeOctetString(randomB);
                    // TODO: Add in GeneralNames element for entityB, encoder.encodeImplicit(0)
                    // TODO: Add in GeneralNames element for authID, encoder.encodeImplicit(1)
                    tbsEncoder.endSequence();

                    try {
                        signature.initVerify(clientCert);
                        signature.update(tbsDataAB.toArray());
                        if (! signature.verify(clientSignature)) {
                            setNegotiationState(FAILED_STATE);
                            throw new SaslException("Client authenticity cannot be verified");
                        }
                    } catch (SignatureException | InvalidKeyException e) {
                        throw new SaslException("Unable to verify client signature", e);
                    }
                    decoder.endSequence();
                } catch (ASN1Exception e) {
                    throw new SaslException("Invalid client message");
                }

                if (serverAuth) {
                    // Construct TokenBA2, where:
                    // TokenBA2 ::= SEQUENCE {
                    //      randomC     RandomNumber,
                    //      entityA     [0] GeneralNames OPTIONAL,
                    //      certB       [1] CertData,
                    //      signature   SIGNATURE { TBSDataBA }
                    // }
                    // TBSDataBA ::= SEQUENCE {
                    //      randomB     RandomNumber,
                    //      randomA     RandomNumber,
                    //      randomC     RandomNumber,
                    //      entityA     GeneralNames OPTIONAL
                    // }
                    // CertData ::= CHOICE {
                    //      certificateSet  SET SIZE (1..MAX) OF Certificate
                    //      certURL         IA5String
                    // }
                    // SIGNATURE { ToBeSigned } ::= SEQUENCE {
                    //      algorithm       AlgorithmIdentifier,
                    //      signature       BIT STRING
                    // }
                    ByteStringBuilder tokenBA2 = new ByteStringBuilder();
                    DEREncoder encoder = new DEREncoder(tokenBA2);
                    encoder.startSequence();

                    // randomC
                    byte[] randomC = EntityUtils.encodeRandom(encoder, secureRandom);

                    // entityA (must contain the client's name from their X.509 certificate)
                    encoder.encodeImplicit(0);
                    clientName = clientCert.getSubjectX500Principal().getName();
                    EntityUtils.encodeGeneralNames(encoder, DIRECTORY_NAME, clientName);

                    // certB (try obtaining a certificate chain first)
                    encoder.encodeImplicit(1);
                    CredentialCallback credentialCallback = new CredentialCallback(X509Certificate[].class);
                    handleCallbacks(credentialCallback);
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
                        handleCallbacks(credentialCallback);
                        String certURL = (String) credentialCallback.getCredential();
                        if (certURL == null) {
                            throw new SaslException("Invalid certificate data");
                        }
                        encoder.encodeIA5String(certURL);
                    }

                    // Private key
                    credentialCallback = new CredentialCallback(PrivateKey.class);
                    handleCallbacks(credentialCallback);
                    PrivateKey privateKey = (PrivateKey) credentialCallback.getCredential();
                    if (privateKey == null) {
                        throw new SaslException("Private key is null");
                    }

                    // TBSDataBA
                    ByteStringBuilder tbsDataBA = new ByteStringBuilder();
                    DEREncoder tbsEncoder = new DEREncoder(tbsDataBA);
                    tbsEncoder.startSequence();
                    tbsEncoder.encodeOctetString(randomB);
                    tbsEncoder.encodeOctetString(randomA);
                    tbsEncoder.encodeOctetString(randomC);
                    EntityUtils.encodeGeneralNames(tbsEncoder, DIRECTORY_NAME, clientName);
                    tbsEncoder.endSequence();

                    // Signature
                    byte[] signatureBytes;
                    try {
                        signature.initSign(privateKey);
                        signature.update(tbsDataBA.toArray());
                        signatureBytes = signature.sign();
                    } catch (SignatureException | InvalidKeyException e) {
                        throw new SaslException("Unable to create signature", e);
                    }

                    encoder.startSequence();
                    EntityUtils.encodeAlgorithmIdentifier(encoder, signature.getAlgorithm());
                    encoder.encodeBitString(signatureBytes);
                    encoder.endSequence();

                    encoder.endSequence();
                    negotiationComplete();
                    return tokenBA2.toArray();
                } else {
                    negotiationComplete();
                    return null;
                }
            } case COMPLETE_STATE: {
                  if (response != null && response.length != 0) {
                      throw new SaslException("Client sent extra response");
                  }
                  return null;
            }
            default: throw new IllegalStateException();
        }
    }
}
