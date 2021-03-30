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

    private static final int HEADER_INDEX = 0;
    private JwtConsumerBuilder jwtConsumerBuilder;
    private OidcClientConfiguration clientConfiguration;

    private IDTokenValidator(Builder builder) {
        this.jwtConsumerBuilder = builder.jwtConsumerBuilder;
        this.clientConfiguration = builder.clientConfiguration;
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
            // first pass to determine the kid, if present
            JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setDisableRequireSignature()
                    .setSkipSignatureVerification()
                    .build();
            JwtContext jwtContext = firstPassJwtConsumer.process(idToken);
            String kid =  jwtContext.getJoseObjects().get(HEADER_INDEX).getKeyIdHeaderValue();
            if (kid != null && clientConfiguration.getPublicKeyLocator() != null) {
                jwtConsumerBuilder.setVerificationKey(clientConfiguration.getPublicKeyLocator().getPublicKey(kid, clientConfiguration));
            } else {
                // secret key
                ClientSecretCredentialsProvider clientSecretCredentialsProvider = (ClientSecretCredentialsProvider) clientConfiguration.getClientAuthenticator();
                jwtConsumerBuilder.setVerificationKey(clientSecretCredentialsProvider.getClientSecret());
            }

            // second pass to validate
            jwtConsumerBuilder.build().processContext(jwtContext);
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
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
     * @param clientConfiguration the OIDC client configuration
     * @return the new builder instance
     */
    public static Builder builder(OidcClientConfiguration clientConfiguration) {
        return new Builder(clientConfiguration);
    }

    public static class Builder {
        private OidcClientConfiguration clientConfiguration;
        private String expectedIssuer;
        private String clientID;
        private String expectedJwsAlgorithm;
        private PublicKeyLocator publicKeyLocator;
        private SecretKey clientSecretKey;
        private JwtConsumerBuilder jwtConsumerBuilder;

        /**
         * Construct a new uninitialized instance.
         *
         * @param clientConfiguration the OIDC client configuration
         */
        Builder(OidcClientConfiguration clientConfiguration) {
            Assert.checkNotNullParam("clientConfiguration", clientConfiguration);
            this.clientConfiguration = clientConfiguration;
        }

        /**
         * Create an ID token validator.
         *
         * @return the newly created ID token validator
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid
         */
        public IDTokenValidator build() throws IllegalArgumentException {
            expectedIssuer = clientConfiguration.getIssuerUrl();
            if (expectedIssuer == null || expectedIssuer.length() == 0) {
                throw log.noExpectedIssuerGiven();
            }
            clientID = clientConfiguration.getResourceName();
            if (clientID == null || clientID.length() == 0) {
                throw log.noClientIDGiven();
            }
            expectedJwsAlgorithm = clientConfiguration.getJwsSignatureAlgorithm();
            if (expectedJwsAlgorithm == null || expectedJwsAlgorithm.length() == 0) {
                throw log.noExpectedJwsAlgorithmGiven();
            }
            publicKeyLocator = clientConfiguration.getPublicKeyLocator();
            if (clientConfiguration.getClientAuthenticator() instanceof ClientSecretCredentialsProvider) {
                ClientSecretCredentialsProvider clientSecretCredentialsProvider = (ClientSecretCredentialsProvider) clientConfiguration.getClientAuthenticator();
                clientSecretKey = clientSecretCredentialsProvider.getClientSecret();
            }
            if (publicKeyLocator == null && clientSecretKey == null) {
                throw log.noJwksPublicKeyOrClientSecretKeyGiven();
            }

            jwtConsumerBuilder = new JwtConsumerBuilder()
                    .setExpectedIssuer(expectedIssuer)
                    .setExpectedAudience(clientID)
                    .setJwsAlgorithmConstraints(
                            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, expectedJwsAlgorithm))
                    .registerValidator(new AzpValidator(clientID))
                    .setRequireExpirationTime();

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

}


