/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

import static org.wildfly.security._private.ElytronMessages.acme;
import static org.wildfly.security.x500.cert.acme.Acme.base64UrlEncode;
import static org.wildfly.security.x500.cert.acme.Acme.getJwk;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.json.JsonObject;

import org.wildfly.security.util.CodePointIterator;

/**
 * A class that represents an Automatic Certificate Management Environment (ACME) challenge.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.4.0
 */
public final class AcmeChallenge {

    private final Type type;
    private final String url;
    private final String token;
    private final String identifierType;
    private final String identifierValue;

    /**
     * Construct a new instance.
     *
     * @param type the challenge type
     * @param url the challenge URL
     * @param token the challenge token
     * @param identifierType the identifier type associated with the challenge
     * @param identifierValue the identifier value associated with the challenge
     */
    public AcmeChallenge(Type type, String url, String token, String identifierType, String identifierValue) {
        this.type = type;
        this.url = url;
        this.token = token;
        this.identifierType = identifierType;
        this.identifierValue = identifierValue;
    }

    /**
     * Get the challenge value.
     *
     * @return the challenge value
     */
    public Type getType() {
        return type;
    }

    /**
     * Get the challenge URL.
     *
     * @return the challenge URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the challenge token.
     *
     * @return the challenge token
     */
    public String getToken() {
        return token;
    }

    /**
     * Get the identifier type associated with the challenge.
     *
     * @return the identifier type associated with the challenge
     */
    public String getIdentifierType() {
        return identifierType;
    }

    /**
     * Get the identifier value associated with the challenge.
     *
     * @return the identifier value associated with the challenge
     */
    public String getIdentifierValue() {
        return identifierValue;
    }

    /**
     * Get the key authorization string for this challenge.
     *
     * @param account the ACME account information to use
     * @return the key authorization string for this challenge
     * @throws AcmeException if the key authorization string cannot be determined
     */
    public String getKeyAuthorization(AcmeAccount account) throws AcmeException {
        JsonObject jwk = getJwk(account.getPublicKey(), account.getAlgHeader());
        byte[] jwkWithoutWhitespace = CodePointIterator.ofString(jwk.toString()).skip(Character::isWhitespace).skipCrLf().asUtf8().drain();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(jwkWithoutWhitespace);
            byte[] jwkThumbprint = messageDigest.digest();
            return token + "." + base64UrlEncode(jwkThumbprint);
        } catch (NoSuchAlgorithmException e) {
            throw acme.unableToDetermineKeyAuthorizationString(e);
        }
    }

    /**
     * The various Automatic Certificate Management Environment (ACME) challenge types.
     */
    public enum Type {
        HTTP_01("http-01"),
        DNS_01("dns-01"),
        TLS_SNI_02("tls-sni-02");

        private final String value;

        Type(String value) {
            this.value = value;
        }

        /**
         * Get the string value of this challenge type.
         *
         * @return the string value of this challenge type
         */
        public String getValue() {
            return value;
        }

        static Type forName(String name) {
            switch (name) {
                case "http-01": return HTTP_01;
                case "dns-01": return DNS_01;
                case "tls-sni-02": return TLS_SNI_02;
                default: return null;
            }
        }
    }

}
