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

import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OidcCookieTokenStore implements OidcTokenStore {

    private final OidcHttpFacade httpFacade;
    private final CallbackHandler callbackHandler;

    public OidcCookieTokenStore(OidcHttpFacade httpFacade, CallbackHandler callbackHandler) {
        this.httpFacade = httpFacade;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public void checkCurrentToken() {
        OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(deployment, httpFacade);
        if (principal == null) {
            return;
        }
        RefreshableOidcSecurityContext securityContext = principal.getOidcSecurityContext();
        if (securityContext.isActive() && ! securityContext.getOidcClientConfiguration().isAlwaysRefreshToken()) return;
        // FYI: A refresh requires same scope, so same roles will be set.  Otherwise, refresh will fail and token will
        // not be updated
        boolean success = securityContext.refreshToken(false);
        if (success && securityContext.isActive()) return;
        saveAccountInfo(new OidcAccount(principal));
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(deployment, httpFacade);
        if (principal == null) {
            log.debug("Account was not in cookie or was invalid, returning null");
            return false;
        }
        OidcAccount account = new OidcAccount(principal);

        if (deployment.getRealm() != null && ! deployment.getRealm().equals(account.getOidcSecurityContext().getRealm())) {
            log.debug("Account in session belongs to a different realm than for this request.");
            return false;
        }

        boolean active = account.checkActive();
        if (! active) {
            active = account.tryRefresh();
        }
        if (active) {
            log.debug("Cached account found");
            restoreRequest();
            httpFacade.authenticationComplete(account, true);
            return true;
        } else {
            log.debug("Account was not active, removing cookie and returning false");
            OidcCookieTokenStore.removeCookie(deployment, httpFacade);
            return false;
        }
    }

    @Override
    public void saveAccountInfo(OidcAccount account) {
        RefreshableOidcSecurityContext secContext = (RefreshableOidcSecurityContext)account.getOidcSecurityContext();
        OidcCookieTokenStore.setTokenCookie(this.httpFacade.getOidcClientConfiguration(), this.httpFacade, secContext);
        HttpScope exchange = this.httpFacade.getScope(Scope.EXCHANGE);
        exchange.registerForNotification(httpServerScopes -> logout());
        exchange.setAttachment(OidcAccount.class.getName(), account);
        exchange.setAttachment(OidcSecurityContext.class.getName(), account.getOidcSecurityContext());
        restoreRequest();
    }

    @Override
    public void logout() {
        logout(false);
    }

    @Override
    public void refreshCallback(RefreshableOidcSecurityContext securityContext) {
        OidcCookieTokenStore.setTokenCookie(this.httpFacade.getOidcClientConfiguration(), httpFacade, securityContext);
    }

    @Override
    public void saveRequest() {

    }

    @Override
    public boolean restoreRequest() {
        return false;
    }

    @Override
    public void logout(boolean glo) {
        OidcPrincipal<RefreshableOidcSecurityContext> principal = OidcCookieTokenStore.getPrincipalFromCookie(this.httpFacade.getOidcClientConfiguration(), this.httpFacade);
        if (principal == null) {
            return;
        }
        OidcCookieTokenStore.removeCookie(this.httpFacade.getOidcClientConfiguration(), this.httpFacade);
        if (glo) {
            OidcSecurityContext securityContext = principal.getOidcSecurityContext();
            if (securityContext == null) {
                return;
            }
            OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
            if (! deployment.isBearerOnly() && securityContext != null && securityContext instanceof RefreshableOidcSecurityContext) {
                ((RefreshableOidcSecurityContext) securityContext).logout(deployment);
            }
        }
    }

    @Override
    public void logoutAll() {
        //no-op
    }

    @Override
    public void logoutHttpSessions(List<String> ids) {
        //no-op
    }

    public static OidcPrincipal<RefreshableOidcSecurityContext> getPrincipalFromCookie(OidcClientConfiguration deployment, OidcHttpFacade facade) {
        OidcHttpFacade.Cookie cookie = facade.getRequest().getCookie(AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE);
        if (cookie == null) {
            log.debug("Not found adapter state cookie in current request");
            return null;
        }

        String cookieVal = cookie.getValue();

        String[] tokens = cookieVal.split(DELIM);
        if (tokens.length != 3) {
            log.warnf("Invalid format of %s cookie. Count of tokens: %s, expected 3", AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE, tokens.length);
            return null;
        }

        String accessTokenString = tokens[0];
        String idTokenString = tokens[1];
        String refreshTokenString = tokens[2];

        try {
            // Skip check if token is active now. It's supposed to be done later by the caller
            TokenVerifier<AccessToken> tokenVerifier = AdapterTokenVerifier.createVerifier(accessTokenString, deployment, true, AccessToken.class)
                    .checkActive(false)
                    .verify();
            AccessToken accessToken = tokenVerifier.getToken();

            IDToken idToken;
            if (idTokenString != null && idTokenString.length() > 0) {
                try {
                    JWSInput input = new JWSInput(idTokenString);
                    idToken = input.readJsonContent(IDToken.class);
                } catch (JWSInputException e) {
                    throw new VerificationException(e);
                }
            } else {
                idToken = null;
            }

            log.debug("Token Verification succeeded!");
            RefreshableOidcSecurityContext secContext = new RefreshableOidcSecurityContext(deployment, this, accessTokenString, accessToken, idTokenString, idToken, refreshTokenString);
            return new OidcPrincipal<>(AdapterUtils.getPrincipalName(deployment, accessToken), secContext);
        } catch (VerificationException ve) {
            log.warn("Failed verify token", ve);
            return null;
        }
    }
}


