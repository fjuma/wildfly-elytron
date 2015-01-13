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

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslException;

import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class EntityUtils {
    // TODO: Move randomCharDictionary and generateRandomString to a different
    // class since it's also used by ScramUtils
    private static final byte[] randomCharDictionary;

    static {
        byte[] dict = new byte[93];
        int i = 0;
        for (byte c = '!'; c < ','; c ++) {
            dict[i ++] = c;
        }
        for (byte c = ',' + 1; c < 127; c ++) {
            dict[i ++] = c;
        }
        assert i == dict.length;
        randomCharDictionary = dict;
    }

    public static byte[] generateRandomString(int length, Random random) {
        final byte[] chars = new byte[length];
        for (int i = 0; i < length; i ++) {
            chars[i] = randomCharDictionary[random.nextInt(93)];
        }
        return chars;
    }

    public static X509TrustManager getDefaultTrustManager() throws SaslException {
        X509TrustManager defaultTrustManager = null;
        try {
            String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(defaultAlgorithm);
            trustManagerFactory.init((KeyStore) null);
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    defaultTrustManager = (X509TrustManager) trustManager;
                    break;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | IllegalStateException e) {
            throw new SaslException("Unable to obtain X.509 trust manager", e);
        }
        return defaultTrustManager;
    }

    /* -- Methods used to encode ASN.1 data structures required for entity authentication -- */

    /**
     * Encode the given {@code X509Certificate} chain using the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param certChain the X.509 certificate chain to encode
     * @throws ASN1Exception if an error occurs while encoding the given certificate chain
     */
    public static void encodeX509CertificateChain(DEREncoder encoder, X509Certificate[] certChain) throws ASN1Exception {
        try {
            int chainSize = certChain.length;
            encoder.startSetOf();
            for (int i = 0; i < chainSize; i++) {
                encoder.writeEncoded(certChain[i].getEncoded());
            }
            encoder.endSetOf();
        } catch (CertificateEncodingException e) {
            throw new ASN1Exception(e.getMessage());
        }
    }

    /**
     * Encode an {@code AlgorithmIdentifier} without any parameters using the given DER encoder and object identifier.
     *
     * @param encoder the DER encoder
     * @param objectIdentifier the object identifier for the algorithm
     * @param omitParametersField true if the parameters field should be ommitted in the encoding and false otherwise
     * @throws ASN1Exception if the given object identifier is invalid
     */
    public static void encodeAlgorithmIdentifier(DEREncoder encoder, String objectIdentifier, boolean omitParametersField) throws ASN1Exception {
        encoder.startSequence();
        encoder.encodeObjectIdentifier(objectIdentifier);
        if (!omitParametersField) {
            encoder.encodeNull();
        }
        encoder.endSequence();
    }

    /**
     * Encode an {@code AlgorithmIdentifier} using the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param algorithm the algorithm name
     */
    public static void encodeAlgorithmIdentifier(DEREncoder encoder, String algorithm) {
        // Determine whether or not the parameters filed should be omitted in the encoding,
        // as specified in RFC 3279
        boolean omitParametersField;
        switch (algorithm) {
            case SHA1_WITH_RSA: {
                omitParametersField = false;
                break;
            }
            case SHA1_WITH_DSA:
            case SHA1_WITH_ECDSA: {
                omitParametersField = true;
                break;
            }
            default: throw new IllegalArgumentException("Unrecognised algorithm");
        }
        encodeAlgorithmIdentifier(encoder, oidMap.get(algorithm), omitParametersField);
    }

    /**
     * Encode a {@code GeneralNames} element using the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param generalNames the general names, given as a {@code Collection} of {@code List} entries where the first
     * entry of each {@code List} is an {@code Integer} (the name type, 0-8) and the second entry is a String (the name)
     * @throws ASN1Exception if any of the general names are invalid
     */
    public static void encodeGeneralNames(DEREncoder encoder, Collection<List<?>> generalNames) throws ASN1Exception {
        encoder.startSequence();
        for (List generalName : generalNames) {
            int type = ((Integer) generalName.get(0)).intValue();
            String name = (String) generalName.get(1);
            switch (type) {
                case RFC_822_NAME:
                case DNS_NAME:
                case URI_NAME:
                    encoder.encodeImplicit(type);
                    encoder.encodeIA5String(name);
                    break;
                case DIRECTORY_NAME:
                    encoder.startExplicit(type);
                    encoder.writeEncoded(new X500Principal(name).getEncoded());
                    encoder.endExplicit();
                    break;
                case REGISTERED_ID:
                    encoder.encodeImplicit(type);
                    encoder.encodeObjectIdentifier(name);
                    break;
                default: throw new ASN1Exception("Invalid general name type");
            }
        }
        encoder.endSequence();
    }

    public static void encodeGeneralNames(DEREncoder encoder, int type, String name) throws ASN1Exception {
        Set<List<?>> generalNames = new HashSet<List<?>>(1);
        List<Object> generalName = new ArrayList<Object>(2);
        generalName.add(type);
        generalName.add(name);
        generalNames.add(generalName);
        encodeGeneralNames(encoder, generalNames);
    }

    public static byte[] encodeRandom(DEREncoder encoder, SecureRandom secureRandom) {
        Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
        byte[] randomA = generateRandomString(48, random);
        encoder.encodeOctetString(randomA);
        return randomA;
    }

    /**
     * Encode a {@code TrustedAuth} element using the given hash and DER encoder.
     *
     * @param encoder the DER encoder
     * @param type the trusted authority hash type, must be one of {@link Entity#ISSUER_NAME_HASH}, {@link Entity#ISSUER_KEY_HASH},
     * or {@link Entity#PKCS_15_KEY_HASH}
     * @param hash the hash that identifies the trusted authority
     * @throws ASN1Exception if the trusted authority hash type is not one of {@link Entity#ISSUER_NAME_HASH},
     * {@link Entity#ISSUER_KEY_HASH}, or {@link Entity#PKCS_15_KEY_HASH}
     */
    public static void encodeTrustedAuthority(DEREncoder encoder, int type, byte[] hash) throws ASN1Exception {
        switch (type) {
            case ISSUER_NAME_HASH:
            case ISSUER_KEY_HASH:
            case PKCS_15_KEY_HASH:
                encoder.encodeImplicit(type);
                encoder.encodeOctetString(hash);
                break;
            default: throw new ASN1Exception("Invalid trusted authority type for a hash identifier");
        }
    }

    /**
     * Encode a {@code TrustedAuth} element using the given X.509 certificate and DER encoder.
     *
     * @param encoder the DER encoder
     * @param cert the X.509 certificate that identifies the trusted authority
     * @throws ASN1Exception if an error occurs while encoding the given certificate
     */
    public static void encodeTrustedAuthority(DEREncoder encoder, X509Certificate cert) throws ASN1Exception {
        encoder.encodeImplicit(AUTHORITY_CERTIFICATE);
        try {
            encoder.writeEncoded(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new ASN1Exception(e.getMessage());
        }
    }

    /**
     * Encode a {@code TrustedAuth} element using the given {@code String} identifier and DER encoder.
     *
     * @param encoder the DER encoder
     * @param type the trusted authority type, must be one of {@link Entity#AUTHORITY_NAME}, {@link Entity#ISSUER_NAME_HASH},
     * {@link Entity#ISSUER_KEY_HASH}, and {@link Entity#PKCS_15_KEY_HASH}
     * @param identifier the identifier for the trusted authority, as a string
     */
    public static void encodeTrustedAuthority(DEREncoder encoder, int type, String identifier) {
        switch (type) {
            case AUTHORITY_NAME:
                encoder.startExplicit(type);
                encoder.writeEncoded((new X500Principal(identifier)).getEncoded());
                encoder.endExplicit();
                break;
            case ISSUER_NAME_HASH:
            case ISSUER_KEY_HASH:
            case PKCS_15_KEY_HASH:
                encoder.encodeImplicit(type);
                encoder.encodeOctetString(identifier);
                break;
            default: throw new ASN1Exception("Invalid type for a string trusted authority identifier");
        }
    }

    /**
     * Encode trusted authorities using the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param trustedAuthorities the trusted authorities, given as a {@code Collection} of {@code List} entries where the first
     * entry of each {@code List} is an {@code Integer} (the trusted authority type, 0-4) and the second entry is a string,
     * {@code X509Certificate}, or a byte array representing the identifier for the trusted authority
     * @throws ASN1Exception if any of the trusted authorities are invalid
     */
    public static void encodeTrustedAuthorities(DEREncoder encoder, Collection<List<?>> trustedAuthorities) {
        encoder.startSequence();
        for (List<?> trustedAuthority : trustedAuthorities) {
            int type = ((Integer) trustedAuthority.get(0)).intValue();
            Object value = trustedAuthority.get(1);
            if (value instanceof String) {
                encodeTrustedAuthority(encoder, type, (String) value);
            } else if (value instanceof X509Certificate) {
                encodeTrustedAuthority(encoder, (X509Certificate) value);
            } else if (value instanceof byte[]) {
                encodeTrustedAuthority(encoder, type, (byte[]) value);
            } else {
                throw new ASN1Exception("Invalid trusted authority value");
            }
        }
        encoder.endSequence();
    }
    /* -- Methods used to decode ASN.1 data structures required for entity authentication -- */

    /**
     * Decode the next element from the given DER decoder as a {@code GeneralNames} element.
     *
     * @param decoder the DER decoder
     * @return the general names, given as a {@code Collection} of {@code List} entries where the first
     * entry of each {@code List} is an {@code Integer} (the name type, 0-8) and the second entry is a String (the name)
     * @throws ASN1Exception if the next element from the given decoder is not a general names element
     */
    public static Collection<List<?>> decodeGeneralNames(DERDecoder decoder) throws ASN1Exception {
        if (decoder.peekType() != SEQUENCE_TYPE) {
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
        DERDecoder generalNamesDecoder = new DERDecoder(decoder.drainElementValue());
        Set<List<?>> generalNames = new HashSet<List<?>>();
        List<Object> generalName;
        int type = -1;
        String name = null;
        while (generalNamesDecoder.hasNextElement()) {
            generalName = new ArrayList<Object>();
            out: {
                for (int generalNameType = 0; generalNameType <= 8; generalNameType++) {
                    switch (generalNameType) {
                        case RFC_822_NAME:
                        case DNS_NAME:
                        case URI_NAME:
                            if (generalNamesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, false)) {
                                type = generalNameType;
                                generalNamesDecoder.decodeImplicit(type);
                                name = generalNamesDecoder.decodeIA5String();
                                break out;
                            }
                            break;
                        case DIRECTORY_NAME:
                            if (generalNamesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, DIRECTORY_NAME, true)) {
                                type = generalNameType;
                                byte[] encodedName = generalNamesDecoder.drainElementValue();
                                name = (new X500Principal(encodedName)).getName();
                                break out;
                            }
                            break;
                        case REGISTERED_ID:
                            if (generalNamesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, REGISTERED_ID, false)) {
                                type = generalNameType;
                                generalNamesDecoder.decodeImplicit(type);
                                name = generalNamesDecoder.decodeObjectIdentifier();
                                break out;
                            }
                            break;
                        default: throw new ASN1Exception("Invalid general name type");
                    }
                }
            }
            generalName.add(type);
            generalName.add(name);
            generalNames.add(generalName);
        }
        return generalNames;
    }

    /**
     * Decode the next element from the given DER decoder as an X.509 certificate chain.
     *
     * @param decoder the DER decoder
     * @return the X.509 certificate chain
     * @throws ASN1Exception if the next element from the given decoder is not an X.509 certificate chain
     * @throws SaslException if an error occurs while decoding the X.509 certificate chain
     */
    public static X509Certificate[] decodeX509CertificateChain(DERDecoder decoder) throws ASN1Exception, SaslException {
        if (decoder.peekType() != SET_TYPE) {
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
        byte[] certChain = decoder.drainElementValue();
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate[]) certFactory.generateCertificates(new ByteArrayInputStream(certChain)).toArray();
        } catch (CertificateException e) {
            throw new SaslException(e.getMessage());
        }
    }

    /**
     * Decode the next element from the given DER decoder as a {@code CertData} element.
     *
     * @param decoder the DER decoder
     * @return the X.509 certificate
     * @throws ASN1Exception if the next element from the given decoder is not a {@code CertData} element
     * @throws SaslException if an error occurs while decoding the certificate data
     */
    public static X509Certificate[] decodeCertificateData(DERDecoder decoder) throws ASN1Exception, SaslException {
        X509Certificate[] peerCertChain;
        if (decoder.peekType() == SET_TYPE) {
            peerCertChain = decodeX509CertificateChain(decoder);
        } else if (decoder.peekType() == IA5_STRING_TYPE) {
            InputStream in;
            try {
                URL certURL = new URL(decoder.decodeIA5String());
                in = certURL.openStream();
            } catch (IOException e) {
                throw new SaslException("Unable to read certificate", e);
            }
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate peerCert = (X509Certificate) certFactory.generateCertificate(in);
                peerCertChain = new X509Certificate[] {peerCert};
            } catch (CertificateException e) {
                throw new SaslException("Unable to read certificate", e);
            } finally {
                safeClose(in);
            }
        } else {
            throw new SaslException("Invalid message");
        }
        return peerCertChain;
    }

    /**
     * Decode the next element from the given DER decoder as a trusted authorities element.
     *
     * @param decoder the DER decoder
     * @return the trusted authorities, given as a {@code Collection} of {@code List} entries where the first
     * entry of each {@code List} is an {@code Integer} (the trusted authority type, 0-4) and the second entry is a string,
     * {@code X509Certificate}, or a byte array representing the identifier for the trusted authority
     * @throws ASN1Exception if the next element from the given decoder is not a trusted authorities element
     * @throws SaslException if an error occurs while decoding a trusted authority certificate
     */
    public static Collection<List<?>> decodeTrustedAuthorities(DERDecoder decoder) throws ASN1Exception, SaslException {
        if (decoder.peekType() != SEQUENCE_TYPE) {
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
        DERDecoder trustedAuthoritiesDecoder = new DERDecoder(decoder.drainElementValue());
        Set<List<?>> trustedAuthorities = new HashSet<List<?>>();
        List<Object> trustedAuthority;
        int type = -1;
        Object identifier = null;
        while (trustedAuthoritiesDecoder.hasNextElement()) {
            trustedAuthority = new ArrayList<Object>();
            out: {
                for (int trustedAuthorityType = 0; trustedAuthorityType <= 4; trustedAuthorityType++) {
                    switch (trustedAuthorityType) {
                        case AUTHORITY_NAME:
                            if (trustedAuthoritiesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, true)) {
                                type = trustedAuthorityType;
                                byte[] encodedName = trustedAuthoritiesDecoder.drainElementValue();
                                identifier = (new X500Principal(encodedName)).getName();
                                break out;
                            }
                            break;
                        case AUTHORITY_CERTIFICATE:
                            if (trustedAuthoritiesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, true)) {
                                type = trustedAuthorityType;
                                trustedAuthoritiesDecoder.decodeImplicit(type);
                                byte[] cert = trustedAuthoritiesDecoder.drainElementValue();
                                try {
                                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                                    identifier = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(cert));
                                } catch (CertificateException e) {
                                    throw new SaslException(e.getMessage());
                                }
                                break out;
                            }
                            break;
                        case ISSUER_NAME_HASH:
                        case ISSUER_KEY_HASH:
                        case PKCS_15_KEY_HASH:
                            if (trustedAuthoritiesDecoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, false)) {
                                type = trustedAuthorityType;
                                trustedAuthoritiesDecoder.decodeImplicit(type);
                                identifier = trustedAuthoritiesDecoder.decodeOctetString();
                                break out;
                            }
                            break;
                        default: throw new ASN1Exception("Invalid general name type");
                    }
                }
            }
            trustedAuthority.add(type);
            trustedAuthority.add(identifier);
            trustedAuthorities.add(trustedAuthority);
        }
        return trustedAuthorities;
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
