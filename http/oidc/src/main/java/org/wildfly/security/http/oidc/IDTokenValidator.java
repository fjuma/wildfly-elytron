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

import java.security.PublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.wildfly.common.Assert;

/**
 * Validator for an ID token, as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IDTokenValidator {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String expectedIssuer;
        private String clientID;
        private String expectedJwsAlgorithm;
        private PublicKey jwksPublicKey;

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
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
         * The client ID that was registered with the OpenID provider.
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
         * The expected JWS signature algorithm.
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
         * The OpenID provider's public key.
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
            if (jwksPublicKey == null) {
                throw log.noJwksPublicKeyGiven();
            }

            try {
                JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                        .setExpectedIssuer(expectedIssuer)
                        .setExpectedAudience(clientID)
                        .setJwsAlgorithmConstraints(
                                new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, expectedJwsAlgorithm))
                        .setVerificationKeyResolver()
                        .build();
            }
        }


    }


}


