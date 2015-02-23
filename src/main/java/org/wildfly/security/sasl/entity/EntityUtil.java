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
import static org.wildfly.security.sasl.entity.GeneralName.*;
import static org.wildfly.security.sasl.entity.TrustedAuthority.*;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.provider.X509CertificateCredentialDecoder;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class EntityUtil {

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

    /* -- Methods used to encode ASN.1 data structures required for entity authentication -- */

    /**
     * Encode an ASN.1 set of certificates using the given DER encoder and the
     * given {@code X509Certificate} chain.
     *
     * @param encoder the DER encoder
     * @param certChain the X.509 certificate chain to encode
     * @throws ASN1Exception if an error occurs while encoding the given certificate chain
     */
    public static void encodeX509CertificateChain(final DEREncoder encoder, X509Certificate[] certChain) throws ASN1Exception {
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
     * <p>
     * Encode an {@code AlgorithmIdentifier} without any parameters using the given
     * DER encoder and object identifier, where {@code AlgorithmIdentifier} is defined as:
     *
     * <pre>
     *      AlgorithmIdentifier  ::=  SEQUENCE  {
     *          algorithm      OBJECT IDENTIFIER,
     *          parameters     ANY DEFINED BY algorithm OPTIONAL
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param objectIdentifier the object identifier for the algorithm
     * @param omitParametersField {@code true} if the parameters field should be ommitted in
     * the encoding and {@code false} otherwise
     * @throws ASN1Exception if the given object identifier is invalid
     */
    public static void encodeAlgorithmIdentifier(final DEREncoder encoder, String objectIdentifier,
            boolean omitParametersField) throws ASN1Exception {
        encoder.startSequence();
        encoder.encodeObjectIdentifier(objectIdentifier);
        if (!omitParametersField) {
            encoder.encodeNull();
        }
        encoder.endSequence();
    }

    /**
     * <p>
     * Encode an {@code AlgorithmIdentifier} using the given DER encoder, where
     * {@code AlgorithmIdentifier} is defined as:
     *
     * <pre>
     *      AlgorithmIdentifier  ::=  SEQUENCE  {
     *          algorithm      OBJECT IDENTIFIER,
     *          parameters     ANY DEFINED BY algorithm OPTIONAL
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param algorithm the algorithm name
     * @throws ASN1Exception if the given algorithm name is unrecognised
     */
    public static void encodeAlgorithmIdentifier(final DEREncoder encoder, String algorithm) throws ASN1Exception {
        // Determine whether or not the parameters field should be omitted in the encoding,
        // as specified in RFC 3279 (http://www.ietf.org/rfc/rfc3279)
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
            default: throw new ASN1Exception("Unrecognised algorithm");
        }
        encodeAlgorithmIdentifier(encoder, algorithmOid(algorithm), omitParametersField);
    }

    /**
     * <p>
     * Encode a {@code GeneralName} element using the given DER encoder,
     * where {@code GeneralName} is defined as:
     *
     * <pre>
     *      GeneralName ::= CHOICE {
     *          otherName                       [0]     OtherName,
     *          rfc822Name                      [1]     IA5String,
     *          dNSName                         [2]     IA5String,
     *          x400Address                     [3]     ORAddress,
     *          directoryName                   [4]     Name,
     *          ediPartyName                    [5]     EDIPartyName,
     *          uniformResourceIdentifier       [6]     IA5String,
     *          iPAddress                       [7]     OCTET STRING,
     *          registeredID                    [8]     OBJECT IDENTIFIER
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param generalName the general name
     * @throws ASN1Exception if the general name is invalid
     */
    public static void encodeGeneralName(final DEREncoder encoder, GeneralName generalName) throws ASN1Exception {
        if (generalName instanceof OtherName) {
            encoder.encodeImplicit(generalName.getType());
            encoder.startSequence();
            encoder.encodeObjectIdentifier(((OtherName) generalName).getObjectIdentifier());
            encoder.writeEncoded(((OtherName) generalName).getEncodedValue());
            encoder.endSequence();
        } else if (generalName instanceof RFC822Name) {
            encoder.encodeImplicit(generalName.getType());
            encoder.encodeIA5String(((RFC822Name) generalName).getName());
        } else if (generalName instanceof DNSName) {
            encoder.encodeImplicit(generalName.getType());
            encoder.encodeIA5String(((DNSName) generalName).getName());
        } else if (generalName instanceof DirectoryName) {
            encoder.startExplicit(generalName.getType());
            encoder.writeEncoded((new X500Principal(((DirectoryName) generalName).getName())).getEncoded());
            encoder.endExplicit();
        } else if (generalName instanceof URIName) {
            encoder.encodeImplicit(generalName.getType());
            encoder.encodeIA5String(((URIName) generalName).getName());
        } else if (generalName instanceof RegisteredID) {
            encoder.encodeImplicit(generalName.getType());
            encoder.encodeObjectIdentifier(((RegisteredID) generalName).getName());
        } else {
            throw new ASN1Exception("Invalid general name type");
        }
    }

    /**
     * <p>
     * Encode a {@code GeneralNames} element using the given DER encoder, where
     * {@code GeneralNames} is defined as:
     *
     * <pre>
     *      GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param generalNames the general names, as a {@code Collection} where each entry is a {@link GeneralName}
     * @throws ASN1Exception if any of the general names are invalid
     */
    public static void encodeGeneralNames(final DEREncoder encoder, Collection<GeneralName> generalNames) throws ASN1Exception {
        encoder.startSequence();
        for (GeneralName generalName : generalNames) {
            encodeGeneralName(encoder, generalName);
        }
        encoder.endSequence();
    }

    /**
     * Encode a {@code GeneralNames} element consisting of one general name using
     * the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param generalName the general name
     * @throws ASN1Exception if the general name is invalid
     */
    public static void encodeGeneralNames(final DEREncoder encoder, GeneralName generalName) throws ASN1Exception {
        Set<GeneralName> generalNames = new HashSet<GeneralName>(1);
        generalNames.add(generalName);
        encodeGeneralNames(encoder, generalNames);
    }

    public static void encodeGeneralNames(final DEREncoder encoder, String subjectName,
            Collection<List<?>> subjectAltNames) throws ASN1Exception {
        encoder.startSequence();
        if (! subjectName.isEmpty()) {
            encodeGeneralName(encoder, new DirectoryName(subjectName));
        }
        if (subjectAltNames != null) {
            for (List altName : subjectAltNames) {
                encodeGeneralName(encoder, convertToGeneralName(altName));
            }
        }
        encoder.endSequence();
    }

    /**
     * <p>
     * Encode a {@code RandomNumber} element using the given DER encoder, where
     * {@code RandomNumber} is defined as:
     *
     * <pre>
     *      RandomNumber ::= OCTET STRING (SIZE(8..MAX))
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param secureRandom the secure random to use (may be null)
     */
    public static byte[] encodeRandomNumber(final DEREncoder encoder, SecureRandom secureRandom) {
        Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
        byte[] randomA = generateRandomString(48, random);
        encoder.encodeOctetString(randomA);
        return randomA;
    }

    public static byte[] generateRandomString(int length, Random random) {
        final byte[] chars = new byte[length];
        for (int i = 0; i < length; i ++) {
            chars[i] = randomCharDictionary[random.nextInt(93)];
        }
        return chars;
    }

    /**
     * <p>
     * Encode a {@code TrustedAuth} element using the given trusted authority and DER encoder,
     * where {@code TrustedAuth} is defined as:
     *
     * <pre>
     *      TrustedAuth ::= CHOICE {
     *          authorityName         [0] Name,
     *              -- SubjectName from CA certificate
     *          issuerNameHash        [1] OCTET STRING,
     *              -- SHA-1 hash of Authority's DN
     *          issuerKeyHash         [2] OCTET STRING,
     *              -- SHA-1 hash of Authority's public key
     *          authorityCertificate  [3] Certificate,
     *              -- CA certificate
     *          pkcs15KeyHash         [4] OCTET STRING
     *              -- PKCS #15 key hash
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder
     * @param trustedAuthority a trusted authority, must be a {@link NameTrustedAuthority},
     * a {@link CertificateTrustedAuthority}, or a {@link HashTrustedAuthority}
     * @throws ASN1Exception if any of the trusted authorities are invalid
     */
    public static void encodeTrustedAuthority(final DEREncoder encoder, TrustedAuthority trustedAuthority) throws ASN1Exception {
        if (trustedAuthority instanceof NameTrustedAuthority) {
            encoder.startExplicit(trustedAuthority.getType());
            encoder.writeEncoded((new X500Principal(((NameTrustedAuthority) trustedAuthority).getIdentifier())).getEncoded());
            encoder.endExplicit();
        } else if (trustedAuthority instanceof HashTrustedAuthority) {
            encoder.encodeImplicit(trustedAuthority.getType());
            encoder.encodeOctetString(((HashTrustedAuthority) trustedAuthority).getIdentifier());
        } else if (trustedAuthority instanceof CertificateTrustedAuthority) {
            encoder.encodeImplicit(trustedAuthority.getType());
            try {
                encoder.writeEncoded(((CertificateTrustedAuthority) trustedAuthority).getIdentifier().getEncoded());
            } catch (CertificateEncodingException e) {
                throw new ASN1Exception(e.getMessage());
            }
        } else {
            throw new ASN1Exception("Invalid trusted authority type");
        }
    }

    /**
     * Encode an ASN.1 sequence of trusted authorities using the given DER encoder.
     *
     * @param encoder the DER encoder
     * @param trustedAuthorities the trusted authorities as a {@code Collection} where each entry must
     * be a {@link NameTrustedAuthority}, a {@link CertificateTrustedAuthority}, or a {@link HashTrustedAuthority}
     * @throws ASN1Exception if any of the trusted authorities are invalid
     */
    public static void encodeTrustedAuthorities(final DEREncoder encoder,
            Collection<TrustedAuthority> trustedAuthorities) throws ASN1Exception {
        encoder.startSequence();
        for (TrustedAuthority trustedAuthority : trustedAuthorities) {
            encodeTrustedAuthority(encoder, trustedAuthority);
        }
        encoder.endSequence();
    }

    /* -- Methods used to decode ASN.1 data structures required for entity authentication -- */

    /**
     * Decode the next element from the given DER decoder as a {@code GeneralNames} element.
     *
     * @param decoder the DER decoder
     * @return the general names
     * @throws ASN1Exception if the next element from the given decoder is not a general names element
     */
    public static Collection<GeneralName> decodeGeneralNames(final DERDecoder decoder) throws ASN1Exception {
        Set<GeneralName> generalNames = new HashSet<GeneralName>();
        GeneralName generalName = null;
        decoder.startSequence();
        while (decoder.hasNextElement()) {
            out: {
                for (int generalNameType = 0; generalNameType <= 8; generalNameType++) {
                    switch (generalNameType) {
                        case OTHER_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, true)) {
                                decoder.decodeImplicit(generalNameType);
                                decoder.startSequence();
                                String typeId = decoder.decodeObjectIdentifier();
                                byte[] encodedValue = decoder.drainElement();
                                decoder.endSequence();
                                generalName = new OtherName(typeId, encodedValue);
                                break out;
                            }
                            break;
                        case RFC_822_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, false)) {
                                decoder.decodeImplicit(generalNameType);
                                generalName = new RFC822Name(decoder.decodeIA5String());
                                break out;
                            }
                            break;
                        case DNS_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, false)) {
                                decoder.decodeImplicit(generalNameType);
                                generalName = new DNSName(decoder.decodeIA5String());
                                break out;
                            }
                            break;
                        case X400_ADDRESS:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, true)) {
                                throw new ASN1Exception("Unsupported general name type"); // TODO
                            }
                        case DIRECTORY_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, DIRECTORY_NAME, true)) {
                                byte[] encodedName = decoder.drainElementValue();
                                generalName = new DirectoryName((new X500Principal(encodedName)).getName(X500Principal.CANONICAL));
                                break out;
                            }
                            break;
                        case EDI_PARTY_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, true)) {
                                throw new ASN1Exception("Unsupported general name type"); // TODO
                            }
                        case URI_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, false)) {
                                decoder.decodeImplicit(generalNameType);
                                generalName = new URIName(decoder.decodeIA5String());
                                break out;
                            }
                            break;
                        case IP_ADDRESS:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, generalNameType, false)) {
                                throw new ASN1Exception("Unsupported general name type"); // TODO
                            }
                        case REGISTERED_ID:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, REGISTERED_ID, false)) {
                                decoder.decodeImplicit(generalNameType);
                                generalName = new RegisteredID(decoder.decodeObjectIdentifier());
                                break out;
                            }
                            break;
                        default: throw new ASN1Exception("Invalid general name type");
                    }
                }
            }
            generalNames.add(generalName);
        }
        decoder.endSequence();
        return generalNames;
    }

    /**
     * Decode the next element from the given DER decoder as an X.509 certificate chain.
     *
     * @param decoder the DER decoder
     * @return the X.509 certificate chain
     * @throws ASN1Exception if the next element from the given decoder is not an X.509
     * certificate chain or if an error occurs while decoding the X.509 certificate chain
     */
    public static X509Certificate[] decodeX509CertificateChain(final DERDecoder decoder) throws ASN1Exception {
        if (decoder.peekType() != SET_TYPE) {
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
        byte[] certChain = decoder.drainElement();
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certChain[0] = SEQUENCE_TYPE; // CertificateFactory#generateCertPath requires a DER SEQUENCE of Certificate instead of a SET of Certificate
            CertPath certPath = certFactory.generateCertPath(new ByteArrayInputStream(certChain));
            List<? extends Certificate> certs = certPath.getCertificates();
            return certs.toArray(new X509Certificate[certs.size()]);
        } catch (CertificateException e) {
            throw new ASN1Exception(e.getMessage());
        }
    }

    /**
     * <p>
     * Decode the next element from the given DER decoder as a {@code CertData} element,
     * which is defined as follows:
     *
     * <pre>
     *      CertData ::= CHOICE {
     *          certificateSet     SET SIZE (1..MAX) OF Certificate,
     *          certURL            IA5String
     *      }
     * </pre>
     * </p>
     *
     * @param decoder the DER decoder
     * @return the X.509 certificate or certificate chain
     * @throws ASN1Exception if the next element from the given decoder is not a {@code CertData}
     * element or if an error occurs while decoding the certificate data
     */
    public static X509Certificate[] decodeCertificateData(final DERDecoder decoder) throws ASN1Exception {
        X509Certificate[] peerCertChain;
        if (decoder.peekType() == SET_TYPE) {
            peerCertChain = decodeX509CertificateChain(decoder);
        } else if (decoder.peekType() == IA5_STRING_TYPE) {
            try {
                X509Certificate peerCert = getCertificateFromUrl(decoder.decodeIA5String());
                peerCertChain = new X509Certificate[] {peerCert};
            } catch (IOException e) {
                throw new ASN1Exception("Unable to read certificate data", e);
            }
        } else {
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
        return peerCertChain;
    }

    /**
     * Obtain an X509Certificate using the given URL.
     *
     * @param certUrl the URL to the X.509 certificate to use, must be a non-relative URL
     * @return the X.509 certificate
     * @throws IOException if the X.509 certificate cannot be obtained
     */
    public static X509Certificate getCertificateFromUrl(String certUrl) throws IOException {
        X509Certificate cert;
        InputStream in = null;
        try {
            URL url = new URL(certUrl);
            in = url.openStream();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            throw new IOException("Unable to read certificate", e);
        } finally {
            safeClose(in);
        }
        return cert;
    }

    /**
     * Decode the next element from the given DER decoder as a trusted authorities element.
     *
     * @param decoder the DER decoder
     * @return the trusted authorities
     * @throws ASN1Exception if the next element from the given decoder is not a trusted authorities
     * element or if an error occurs while decoding the trusted authorities element
     */
    public static Collection<TrustedAuthority> decodeTrustedAuthorities(final DERDecoder decoder) throws ASN1Exception {
        List<TrustedAuthority> trustedAuthorities = new ArrayList<TrustedAuthority>();
        TrustedAuthority trustedAuthority = null;
        decoder.startSequence();
        while (decoder.hasNextElement()) {
            out: {
                for (int trustedAuthorityType = 0; trustedAuthorityType <= 4; trustedAuthorityType++) {
                    switch (trustedAuthorityType) {
                        case AUTHORITY_NAME:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, true)) {
                                byte[] encodedName = decoder.drainElementValue();
                                trustedAuthority = new NameTrustedAuthority((new X500Principal(encodedName)).getName(X500Principal.CANONICAL));
                                break out;
                            }
                            break;
                        case AUTHORITY_CERTIFICATE:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, true)) {
                                decoder.decodeImplicit(trustedAuthorityType);
                                byte[] cert = decoder.drainElementValue();
                                try {
                                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                                    trustedAuthority = new CertificateTrustedAuthority((X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(cert)));
                                } catch (CertificateException e) {
                                    throw new ASN1Exception(e.getMessage());
                                }
                                break out;
                            }
                            break;
                        case ISSUER_NAME_HASH:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, false)) {
                                decoder.decodeImplicit(trustedAuthorityType);
                                trustedAuthority = new IssuerNameHashTrustedAuthority(decoder.decodeOctetString());
                                break out;
                            }
                            break;
                        case ISSUER_KEY_HASH:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, false)) {
                                decoder.decodeImplicit(trustedAuthorityType);
                                trustedAuthority = new IssuerKeyHashTrustedAuthority(decoder.decodeOctetString());
                                break out;
                            }
                            break;
                        case PKCS_15_KEY_HASH:
                            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, trustedAuthorityType, false)) {
                                decoder.decodeImplicit(trustedAuthorityType);
                                trustedAuthority = new PKCS15KeyHashTrustedAuthority(decoder.decodeOctetString());
                                break out;
                            }
                            break;
                        default: throw new ASN1Exception("Invalid general name type");
                    }
                }
            }
            trustedAuthorities.add(trustedAuthority);
        }
        decoder.endSequence();
        return trustedAuthorities;
    }

    public static boolean matchGeneralNames(Collection<GeneralName> generalNames,
            Collection<GeneralName> otherGeneralNames) {
        if (generalNames.size() > otherGeneralNames.size()) {
            // Place smaller collection in generalNames
            Collection<GeneralName> tmp = generalNames;
            generalNames = otherGeneralNames;
            otherGeneralNames = tmp;
        }
        for (GeneralName generalName : generalNames) {
            for (GeneralName otherGeneralName : otherGeneralNames) {
                if (generalName.equals(otherGeneralName)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean matchGeneralNames(Collection<GeneralName> generalNames, X509Certificate cert) {
        Collection<GeneralName> certNames;
        final X509CertificateCredentialDecoder certCredentialDecoder = new X509CertificateCredentialDecoder();
        String certSubjectName = certCredentialDecoder.getNameFromCredential(cert);
        if (! certSubjectName.isEmpty()) {
            certNames = new HashSet<GeneralName>(1);
            certNames.add(new DirectoryName(certSubjectName));
            if (matchGeneralNames(certNames, generalNames)) {
                return true;
            }
        }
        try {
            return matchGeneralNames(convertToGeneralNames(cert.getSubjectAlternativeNames()), generalNames);
        } catch (CertificateParsingException e) {
            // Ingore unless the subject name is empty
            if (certSubjectName.isEmpty()) {
                throw new IllegalStateException("Unable to determine name", e);
            }
        }
        return false;
    }

    public static String getDistinguishedNameFromGeneralNames(Collection<GeneralName> generalNames) {
        for (GeneralName generalName : generalNames) {
            if (generalName instanceof DirectoryName) {
                return ((DirectoryName) generalName).getName();
            }
        }
        return null;
    }

    private static GeneralName convertToGeneralName(List<?> generalName) throws ASN1Exception {
        int type = ((Integer) generalName.get(0)).intValue();
        Object name = generalName.get(1);
        switch (type) {
            case OTHER_NAME:
                return new OtherName((byte[]) name);
            case RFC_822_NAME:
                return new RFC822Name((String) name);
            case DNS_NAME:
                return new DNSName((String) name);
            case DIRECTORY_NAME:
                return new DirectoryName((String) name);
            case URI_NAME:
                return new URIName((String) name);
            case REGISTERED_ID:
                return new RegisteredID((String) name);
            default: throw new ASN1Exception("Invalid general name type");
        }
    }

    private static Collection<GeneralName> convertToGeneralNames(Collection<List<?>> generalNames) throws ASN1Exception {
        Collection<GeneralName> convertedGeneralNames = new HashSet<GeneralName>();
        for (List<?> generalName : generalNames) {
            convertedGeneralNames.add(convertToGeneralName(generalName));
        }
        return convertedGeneralNames;
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
