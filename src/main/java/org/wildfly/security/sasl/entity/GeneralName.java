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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * A representation of an X.509 general name.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public abstract class GeneralName {

    // General name types (TODO: look into adding support for the remaining general name types: x400Address, ediPartyName, and iPAddress)
    public static final int OTHER_NAME = 0;
    public static final int RFC_822_NAME = 1;
    public static final int DNS_NAME = 2;
    public static final int X400_ADDRESS = 3;
    public static final int DIRECTORY_NAME = 4;
    public static final int EDI_PARTY_NAME = 5;
    public static final int URI_NAME = 6;
    public static final int IP_ADDRESS = 7;
    public static final int REGISTERED_ID = 8;

    private final int type;

    GeneralName(final int type) {
        if (type < 0 || type > 8) {
            throw new IllegalArgumentException("Invalid value for a general name type; expected a value between 0 and 8 (inclusive)");
        }
        this.type = type;
    }

    /**
     * Get the type of this general name.
     *
     * @return the type of this general name
     */
    public int getType() {
        return type;
    }

    /**
     * Get the name.
     *
     * @return the name
     */
    public abstract Object getName();

    /**
     * A generic name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class OtherName extends GeneralName {

        private final byte[] encodedName;
        private final String typeId;
        private final byte[] encodedValue;

        /**
         * <p>
         * Create an {@code OtherName} that is defined as:
         *
         * <pre>
         *      OtherName ::= SEQUENCE {
         *                      type-id    OBJECT IDENTIFIER,
         *                      value      [0] EXPLICIT ANY DEFINED BY type-id }
         * </pre>
         * </p>
         *
         * @param encodedName the DER encoded form of the name, as a byte array
         */
        public OtherName(final byte[] encodedName) {
            super(OTHER_NAME);
            this.encodedName = encodedName;
            final DERDecoder decoder = new DERDecoder(encodedName);
            decoder.startSequence();
            typeId = decoder.decodeObjectIdentifier();
            encodedValue = decoder.drainElement();
            decoder.endSequence();
        }

        /**
         * <p>
         * Create an {@code OtherName} that is defined as:
         *
         * <pre>
         *      OtherName ::= SEQUENCE {
         *                      type-id    OBJECT IDENTIFIER,
         *                      value      [0] EXPLICIT ANY DEFINED BY type-id }
         * </pre>
         * </p>
         *
         * @param typeId the object identifier for this name
         * @param encodedValue the DER encoded value for this name
         */
        public OtherName(final String typeId, final byte[] encodedValue) throws ASN1Exception {
            super(OTHER_NAME);
            this.typeId = typeId;
            this.encodedValue = encodedValue;
            ByteStringBuilder generalName = new ByteStringBuilder();
            final DEREncoder encoder = new DEREncoder(generalName);
            encoder.startSequence();
            encoder.encodeObjectIdentifier(typeId);
            encoder.writeEncoded(encodedValue);
            encoder.endSequence();
            encodedName = generalName.toArray();
        }

        public byte[] getName() {
            return encodedName.clone();
        }

        public String getObjectIdentifier() {
            return typeId;
        }

        public byte[] getEncodedValue() {
            return encodedValue.clone();
        }

        public boolean equals(final Object obj) {
            return obj instanceof OtherName && equals((OtherName) obj);
        }

        public boolean equals(final OtherName other) {
            return other != null && Arrays.equals(encodedName, other.getName());
        }

        public int hashCode() {
            return Arrays.hashCode(encodedName);
        }
    }

    /**
     * An RFC 822 name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class RFC822Name extends GeneralName {

        private final String name;

        /**
         * Create an RFC 822 name.
         *
         * @param name the RFC 822 name, as a {@code String}
         */
        public RFC822Name(final String name) {
            super(RFC_822_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public boolean equals(final Object obj) {
            return obj instanceof RFC822Name && equals((RFC822Name) obj);
        }

        public boolean equals(final RFC822Name other) {
            return other != null && name.equalsIgnoreCase(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * A DNS name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class DNSName extends GeneralName {

        private final String name;

        /**
         * Create a DNS name.
         *
         * @param name the DNS name, as a {@code String}
         */
        public DNSName(final String name) {
            super(DNS_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public boolean equals(final Object obj) {
            return obj instanceof DNSName && equals((DNSName) obj);
        }

        public boolean equals(final DNSName other) {
            return other != null && name.equalsIgnoreCase(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * A directory name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class DirectoryName extends GeneralName {

        private final String name;

        /**
         * Create a directory name.
         *
         * @param name the directory name, as a {@code String}
         */
        public DirectoryName(final String name) {
            super(DIRECTORY_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public boolean equals(final Object obj) {
            return obj instanceof DirectoryName && equals((DirectoryName) obj);
        }

        public boolean equals(final DirectoryName other) {
            return (new X500Principal(name)).equals(new X500Principal(other.getName()));
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * A URI name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class URIName extends GeneralName {

        private final String name;

        /**
         * Create a URI name.
         *
         * @param name the URI name, as a {@code String}
         */
        public URIName(final String name) {
            super(URI_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public boolean equals(final Object obj) {
            return obj instanceof URIName && equals((URIName) obj);
        }

        public boolean equals(final URIName other) {
            try {
                return (new URI(name)).equals(new URI(other.getName()));
            } catch (URISyntaxException e) {
                throw new ASN1Exception("Invalid general name for URI type");
            }
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * A registered ID name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class RegisteredID extends GeneralName {

        private final String name;

        /**
         * Create a registered ID name.
         *
         * @param name the registered ID name, as a {@code String}
         */
        public RegisteredID(final String name) {
            super(REGISTERED_ID);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public boolean equals(final Object obj) {
            return obj instanceof RegisteredID && equals((RegisteredID) obj);
        }

        public boolean equals(final RegisteredID other) {
            return name.equals(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }
}
