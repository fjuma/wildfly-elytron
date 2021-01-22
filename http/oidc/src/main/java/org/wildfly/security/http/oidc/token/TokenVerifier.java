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

package org.wildfly.security.http.oidc.token;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import org.wildfly.security.http.oidc.OidcClientConfiguration;

public class TokenVerifier<T extends JsonWebToken> {

    private OidcClientConfiguration clientConfiguration;
    private String clientID;
    private String tokenString;
    private Class<? extends JsonWebToken> clazz;
    private T token;

    /**
     * Creates an instance of {@code TokenVerifier} from the given string on a JWT of the given class.
     * The token verifier has no checks defined. Note that the checks are only tested when
     * {@link #verify()} method is invoked.
     * @param <T> Type of the token
     * @param tokenString string representation of the JWT
     * @param clazz Class of the token
     * @return
     */
    public static <T extends JsonWebToken> TokenVerifier<T> create(String tokenString, Class<T> clazz) {
        return new TokenVerifier(tokenString, clazz);
    }

    protected TokenVerifier(String tokenString, Class<T> clazz) {
        this.tokenString = tokenString;
        this.clazz = clazz;
    }

    public static VerifiedTokens verifyTokens(String accessTokenString, String idTokenString, OidcClientConfiguration clientConfiguration) throws VerificationException {
        // Adapters currently do most of the checks including signature etc on the access token
        TokenVerifier<AccessToken> tokenVerifier = createVerifier(accessTokenString, deployment, true, AccessToken.class);
        AccessToken accessToken = tokenVerifier.verify().getToken();

        if (idTokenString != null) {
            // Don't verify signature again on IDToken
            IDToken idToken = TokenVerifier.create(idTokenString, IDToken.class).getToken();
            TokenVerifier<IDToken> idTokenVerifier = TokenVerifier.createWithoutSignature(idToken);

            // Always verify audience and azp on IDToken
            idTokenVerifier.audience(deployment.getResourceName());
            idTokenVerifier.issuedFor(deployment.getResourceName());

            idTokenVerifier.verify();
            return new VerifiedTokens(accessToken, idToken);
        } else {
            return new VerifiedTokens(accessToken, null);
        }
    }

    public T getToken() throws VerificationException {
        if (token == null) {
            parse();
        }
        return token;
    }

    public TokenVerifier<T> parse() throws VerificationException {
        if (jws == null) {
            if (tokenString == null) {
                throw new VerificationException("Token not set");
            }

            try {
                jws = new JWSInput(tokenString);
            } catch (JWSInputException e) {
                throw new VerificationException("Failed to parse JWT", e);
            }


            try {
                token = jws.readJsonContent(clazz);
            } catch (JWSInputException e) {
                throw new VerificationException("Failed to read access token from JWT", e);
            }
        }
        return this;
    }


    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        List<Predicate<JsonWebToken>> checks = new ArrayList<>();
        OidcClientConfiguration clientConfiguration;

        public Builder withDecryptionCheck() {

            return this;
        }

        public Builder withIssuerCheck() {
            Predicate<JsonWebToken> issuerCheck = idToken -> idToken.getIssuer().equals(clientConfiguration.getIssuerUrl());
            checks.add(issuerCheck);
            return this;
        }

        public Builder setClientConfiguration(OidcClientConfiguration clientConfiguration) {
            this.clientConfiguration = clientConfiguration;
            return this;
        }
    }

}