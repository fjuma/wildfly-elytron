/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.INVALID_ISSUED_FOR_CLAIM;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.wildfly.common.Assert;

/**
 * Validator for an ID token, as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IDTokenValidator {

    private JwtConsumer jwtConsumer;

    private IDTokenValidator(Builder builder) {
        this.jwtConsumer = builder.jwtConsumer;
    }

    /**
     * Parse and verify the given ID token.
     *
     * @param idToken the ID token
     * @return the {@code JwtContext} if the ID token was valid
     * @throws OidcException if the ID token is invalid
     */
    public IDToken parseAndVerifyToken(final String idToken) throws OidcException {
        try {
            JwtClaims jwtClaims = jwtConsumer.process(idToken).getJwtClaims();
            if (jwtClaims == null) {
                throw log.invalidIDTokenClaims();
            }
            return new IDToken(jwtClaims);
        } catch (InvalidJwtException e) {
            throw log.invalidIDToken(e);
        }
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String expectedIssuer;
        private String clientID;
        private String expectedJwsAlgorithm;
        private PublicKey jwksPublicKey;
        private SecretKey clientSecretKey;
        private PrivateKey decryptionKey;
        private JwtConsumer jwtConsumer;

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
        }

        /**
         * Construct a new uninitialized instance.
         *
         * @param clientConfiguration the OIDC client configuration
         */
        Builder(OidcClientConfiguration clientConfiguration) {
            Assert.checkNotNullParam("clientConfiguration", clientConfiguration);
            setExpectedIssuer(clientConfiguration.getIssuerUrl());
            setClientId(clientConfiguration.getResourceName());
            setExpectedJwsAlgorithm(clientConfiguration.getJwsSignatureAlgorithm());
            setJwksPublicKey(getPublicKey())
        }

        /**
         * Set the expected issuer identifier for the OpenID provider.
         *
         * @param expectedIssuer the expected issuer
         * @return this builder instance
         */
        public Builder setExpectedIssuer(final String expectedIssuer) {
            Assert.checkNotNullParam("expectedIssuer", expectedIssuer);
            this.expectedIssuer = expectedIssuer;
            return this;
        }

        /**
         * Set the client ID that was registered with the OpenID provider.
         *
         * @param clientID the client ID that was registered with the OpenID provider
         * @return this builder instance
         */
        public Builder setClientId(final String clientID) {
            Assert.checkNotNullParam("clientID", clientID);
            this.clientID = clientID;
            return this;
        }


        /**
         * Set the expected JWS signature algorithm.
         *
         * @param expectedJwsAlgorithm the expected JWS signature algorithm
         * @return this builder instance
         */
        public Builder setExpectedJwsAlgorithm(final String expectedJwsAlgorithm) {
            Assert.checkNotNullParam("expectedJwsAlgorithm", expectedJwsAlgorithm);
            this.expectedJwsAlgorithm = expectedJwsAlgorithm;
            return this;
        }

        /**
         * Set the OpenID provider's public key.
         *
         * @param jwksPublicKey the OpenID provider's public key to be used to validate the signature
         * @return this builder instance
         */
        public Builder setJwksPublicKey(final PublicKey jwksPublicKey) {
            Assert.checkNotNullParam("jwksPublicKey", jwksPublicKey);
            this.jwksPublicKey = jwksPublicKey;
            return this;
        }

        /**
         * Set the client secret key.
         *
         * @param clientSecretKey the client secret key
         * @return this builder instance
         */
        public Builder setClientSecretKey(final SecretKey clientSecretKey) {
            Assert.checkNotNullParam("clientSecretKey", clientSecretKey);
            this.clientSecretKey = clientSecretKey;
            return this;
        }

        /**
         * Set the key to be used for decryption.
         *
         * @param decryptionKey the key to be used for decryption
         * @return this builder instance
         */
        public Builder setDecryptionKey(final PrivateKey decryptionKey) {
            Assert.checkNotNullParam("decryptionKey", decryptionKey);
            this.decryptionKey = decryptionKey;
            return this;
        }

        /**
         * Create an ID token validator.
         *
         * @return the newly created ID token validator
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid
         */
        public IDTokenValidator build() throws IllegalArgumentException {
            if (expectedIssuer == null || expectedIssuer.length() == 0) {
                throw log.noExpectedIssuerGiven();
            }
            if (clientID == null || clientID.length() == 0) {
                throw log.noClientIDGiven();
            }
            if (expectedJwsAlgorithm == null || expectedJwsAlgorithm.length() == 0) {
                throw log.noExpectedJwsAlgorithmGiven();
            }
            if (jwksPublicKey == null && clientSecretKey == null) {
                throw log.noJwksPublicKeyOrClientSecretKeyGiven();
            }

            JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder()
                    .setExpectedIssuer(expectedIssuer)
                    .setExpectedAudience(clientID)
                    .setJwsAlgorithmConstraints(
                            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, expectedJwsAlgorithm))
                    .setVerificationKey(jwksPublicKey != null ? jwksPublicKey : clientSecretKey)
                    .registerValidator(new AzpValidator(clientID))
                    .setRequireExpirationTime();

            if (decryptionKey != null) {
                jwtConsumerBuilder.setDecryptionKey(decryptionKey);
            }

            jwtConsumer = jwtConsumerBuilder.build();
            return new IDTokenValidator(this);
        }
    }

    private static class AzpValidator implements ErrorCodeValidator {
        public static final String AZP = "azp";
        private final String issuedFor;

        public AzpValidator(String issuedFor) {
            this.issuedFor = issuedFor;
        }

        public ErrorCodeValidator.Error validate(JwtContext jwtContext) throws MalformedClaimException {
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
            boolean valid = false;
            if (jwtClaims.getAudience().size() > 1) {
                // if the ID token contains multiple audiences, then verify that an azp claim is present
                if (jwtClaims.hasClaim(AZP)) {
                    String azpValue = jwtClaims.getStringClaimValue(AZP);
                    valid = azpValue != null && jwtClaims.getClaimValueAsString(AZP).equals(issuedFor);
                }
            } else {
                valid = true; // one audience
            }
            if (! valid) {
                return new ErrorCodeValidator.Error(INVALID_ISSUED_FOR_CLAIM, log.unexpectedValueForIssuedForClaim());
            }
            return null;
        }
    }

    private PublicKey getPublicKey(PublicKeyLocator publicKeyLocator) {
        PublicKey publicKey = publicKeyLocator.getPublicKey(kid, clientConfiguration);
        return publicKey;
    }

}


