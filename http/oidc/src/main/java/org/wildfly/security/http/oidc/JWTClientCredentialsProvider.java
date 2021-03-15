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
import static org.wildfly.security.http.oidc.Oidc.AUTHORIZATION;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;

import org.jose4j.jwt.JwtClaims;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.jose.jwk.JWK;

/**
 * Client authentication based on JWT signed by client private key.
 * See <a href="https://tools.ietf.org/html/rfc7519">specs</a> for more details.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class JWTClientCredentialsProvider implements ClientCredentialsProvider {

    private KeyPair keyPair;
    private JWK publicKeyJwk;

    private int tokenTimeout;

    @Override
    public String getId() {
        return Oidc.ClientCredentialsProviderType.JWT.getValue();
    }

    public void setupKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
        this.publicKeyJwk = JWKBuilder.create().rs256(keyPair.getPublic());
    }

    public void setTokenTimeout(int tokenTimeout) {
        this.tokenTimeout = tokenTimeout;
    }

    protected int getTokenTimeout() {
        return tokenTimeout;
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    @Override
    public void init(OidcClientConfiguration oidcClientConfiguration, Object credentialsConfig) {
        if (!(credentialsConfig instanceof Map)) {
            throw new RuntimeException("Configuration of jwt credentials is missing or incorrect for client '" + oidcClientConfiguration.getResourceName() + "'. Check your adapter configuration");
        }

        Map<String, Object> cfg = (Map<String, Object>) credentialsConfig;

        String clientKeystoreFile =  (String) cfg.get("client-keystore-file");
        if (clientKeystoreFile == null) {
            throw new RuntimeException("Missing parameter client-keystore-file in configuration of jwt for client " + oidcClientConfiguration.getResourceName());
        }

        String clientKeystoreType = (String) cfg.get("client-keystore-type");
        KeystoreUtil.KeystoreFormat clientKeystoreFormat = clientKeystoreType==null ? KeystoreUtil.KeystoreFormat.JKS : Enum.valueOf(KeystoreUtil.KeystoreFormat.class, clientKeystoreType.toUpperCase());

        String clientKeystorePassword =  (String) cfg.get("client-keystore-password");
        if (clientKeystorePassword == null) {
            throw new RuntimeException("Missing parameter client-keystore-password in configuration of jwt for client " + oidcClientConfiguration.getResourceName());
        }

        String clientKeyPassword = (String) cfg.get("client-key-password");
        if (clientKeyPassword == null) {
            clientKeyPassword = clientKeystorePassword;
        }

        String clientKeyAlias =  (String) cfg.get("client-key-alias");
        if (clientKeyAlias == null) {
            clientKeyAlias = oidcClientConfiguration.getResourceName();
        }

        KeyPair keyPair = KeystoreUtil.loadKeyPairFromKeystore(clientKeystoreFile, clientKeystorePassword, clientKeyPassword, clientKeyAlias, clientKeystoreFormat);
        setupKeyPair(keyPair);

        this.tokenTimeout = asInt(cfg, "token-timeout", 10);
    }

    // TODO: Generic method for this?
    private Integer asInt(Map<String, Object> cfg, String cfgKey, int defaultValue) {
        Object cfgObj = cfg.get(cfgKey);
        if (cfgObj == null) {
            return defaultValue;
        }

        if (cfgObj instanceof String) {
            return Integer.parseInt(cfgObj.toString());
        } else if (cfgObj instanceof Number) {
            return ((Number) cfgObj).intValue();
        } else {
            throw new IllegalArgumentException("Can't parse " + cfgKey + " from the config. Value is " + cfgObj);
        }
    }

    @Override
    public void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders, Map<String, String> formParams) {
        String signedToken = createSignedRequestToken(oidcClientConfiguration.getResourceName(), oidcClientConfiguration.getRealmInfoUrl());

        formParams.put(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT);
        formParams.put(OAuth2Constants.CLIENT_ASSERTION, signedToken);
    }

    public String createSignedRequestToken(String clientId, String realmInfoUrl) {
        JsonWebToken jwt = createRequestToken(clientId, realmInfoUrl);
        return new JWSBuilder()
                .kid(publicKeyJwk.getKeyId())
                .jsonContent(jwt)
                .rsa256(keyPair.getPrivate());
    }

    protected JsonWebToken createRequestToken(String clientId, String realmInfoUrl) {

        JsonWebToken reqToken = new JsonWebToken();
        reqToken.id(Oidc.generateId());
        reqToken.issuer(clientId);
        reqToken.subject(clientId);
        reqToken.audience(realmInfoUrl);

        int now = Time.currentTime();
        reqToken.issuedAt(now);
        reqToken.expiration(now + this.tokenTimeout);
        reqToken.notBefore(now);

        return reqToken;
    }
}
