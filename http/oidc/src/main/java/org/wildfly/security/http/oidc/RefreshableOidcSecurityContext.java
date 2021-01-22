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
import static org.wildfly.security.http.oidc.Oidc.getCurrentTimeInSeconds;

import java.io.IOException;

import org.wildfly.security.http.oidc.token.AccessToken;
import org.wildfly.security.http.oidc.token.AccessAndIDTokenResponse;
import org.wildfly.security.http.oidc.token.IDToken;
import org.wildfly.security.http.oidc.token.Token;
import org.wildfly.security.http.oidc.token.TokenVerifier;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.15.0
 */
public class RefreshableOidcSecurityContext extends OidcSecurityContext {

    protected transient OidcClientConfiguration clientConfiguration;
    protected transient OidcTokenStore tokenStore;
    protected String refreshToken;

    public RefreshableOidcSecurityContext() {
    }

    public RefreshableOidcSecurityContext(OidcClientConfiguration clientConfiguration, OidcTokenStore tokenStore, String tokenString,
                                          AccessToken token, String idTokenString, IDToken idToken, String refreshToken) {
        super(tokenString, token, idTokenString, idToken);
        this.clientConfiguration = clientConfiguration;
        this.tokenStore = tokenStore;
        this.refreshToken = refreshToken;
    }

    @Override
    public AccessToken getToken() {
        refreshExpiredToken(true);
        return super.getToken();
    }

    @Override
    public String getTokenString() {
        refreshExpiredToken(true);
        return super.getTokenString();
    }

    @Override
    public IDToken getIdToken() {
        refreshExpiredToken(true);
        return super.getIdToken();
    }

    @Override
    public String getIdTokenString() {
        refreshExpiredToken(true);
        return super.getIdTokenString();
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void logout(OidcClientConfiguration clientConfiguration) {
        try {
            ServerRequest.invokeLogout(clientConfiguration, refreshToken);
        } catch (Exception e) {
            log.failedToInvokeRemoteLogout(e);
        }
    }

    public boolean isActive() {
        return token != null && this.token.isActive() && clientConfiguration !=null && this.token.getIssuedAt() >= clientConfiguration.getNotBefore();
    }

    public boolean isTokenTimeToLiveSufficient(AccessToken token) {
        return token != null && (token.getExpiration() - this.clientConfiguration.getTokenMinimumTimeToLive()) > getCurrentTimeInSeconds();
    }

    public OidcClientConfiguration getOidcClientConfiguration() {
        return clientConfiguration;
    }

    public void setCurrentRequestInfo(OidcClientConfiguration clientConfiguration, OidcTokenStore tokenStore) {
        this.clientConfiguration = clientConfiguration;
        this.tokenStore = tokenStore;
    }

    /**
     * @param checkActive if true, then we won't send refresh request if current accessToken is still active.
     * @return true if accessToken is active or was successfully refreshed
     */
    public boolean refreshExpiredToken(boolean checkActive) {
        if (checkActive) {
            if (log.isTraceEnabled()) {
                log.trace("checking whether to refresh.");
            }
            if (isActive() && isTokenTimeToLiveSufficient(this.token)) return true;
        }

        if (this.clientConfiguration == null || refreshToken == null) return false; // Might be serialized in HttpSession?

        if (log.isTraceEnabled()) {
            log.trace("Doing refresh");
        }

        // block requests if the refresh accessToken herein stored is already being used to refresh the accessToken so that subsequent requests
        // can use the last refresh accessToken issued by the server. Note that this will only work for deployments using the session store
        // and, when running in a cluster, sticky sessions must be used.
        //
        synchronized (this) {
            if (checkActive) {
                log.trace("Checking whether accessToken has been refreshed in another thread already.");
                if (isActive() && isTokenTimeToLiveSufficient(this.token)) return true;
            }
            AccessAndIDTokenResponse response;
            try {
                response = ServerRequest.invokeRefresh(clientConfiguration, refreshToken);
            } catch (IOException e) {
                log.refreshTokenFailure(e);
                return false;
            } catch (ServerRequest.HttpFailure httpFailure) {
                log.refreshTokenFailureStatus(httpFailure.getStatus(), httpFailure.getError());
                return false;
            }
            if (log.isTraceEnabled()) {
                log.trace("received refresh response");
            }
            String accessTokenString = response.getAccessToken();
            AccessToken accessToken = null;
            IDToken idToken = null;
            try {
                TokenVerifier.VerifiedTokens tokens = TokenVerifier.verifyTokens(clientConfiguration)

                AdapterTokenVerifier.VerifiedTokens tokens = AdapterTokenVerifier.verifyTokens(accessTokenString, response.getIDToken(), clientConfiguration);
                accessToken = tokens.getAccessToken();
                idToken = tokens.getIdToken();
                log.debug("Token Verification succeeded!");
            } catch (VerificationException e) {
                log.failedVerificationOfToken();
                return false;
            }
            // If the TTL is greater-or-equal to the expire time on the refreshed accessToken, have to abort or go into an infinite refresh loop
            if (!isTokenTimeToLiveSufficient(accessToken)) {
                log.failedToRefreshTokenWithALongerTTLThanMin();
                return false;
            }
            if (idToken != null) {
                this.idToken = idToken;
                this.idTokenString = response.getIDToken();
            }
            this.token = accessToken;
            if (response.getRefreshToken() != null) {
                if (log.isTraceEnabled()) {
                    log.trace("Setup new refresh accessToken to the security context");
                }
                this.refreshToken = response.getRefreshToken();
            }
            this.tokenString = accessTokenString;
            if (tokenStore != null) {
                tokenStore.refreshCallback(this);
            }
        }

        return true;
    }

    public void setAuthorizationContext(AuthorizationContext authorizationContext) {
        this.authorizationContext = authorizationContext;
    }
}
