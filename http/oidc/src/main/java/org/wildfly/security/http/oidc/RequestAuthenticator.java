/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
import static org.wildfly.security.http.oidc.Oidc.AuthOutcome;

import java.util.Collections;
import java.util.List;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class RequestAuthenticator {

    protected OidcHttpFacade facade;
    protected AuthChallenge challenge;
    protected OidcClientConfiguration deployment;
    protected int sslRedirectPort;
    public RequestAuthenticator(OidcHttpFacade facade, OidcClientConfiguration deployment, int sslRedirectPort) {
        this.facade = facade;
        this.deployment = deployment;
        this.sslRedirectPort = sslRedirectPort;
    }

    public AuthOutcome authenticate() {
        AuthOutcome authenticate = doAuthenticate();
        if (AuthOutcome.AUTHENTICATED.equals(authenticate)) {
            if (! facade.isAuthorized()) {
                return AuthOutcome.FAILED;
            }
        }
        return authenticate;
    }

    protected OAuthRequestAuthenticator createOAuthAuthenticator() {
        return new OAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, facade.getTokenStore());
    }

    protected void completeOAuthAuthentication(final OidcPrincipal<RefreshableOidcSecurityContext> principal) {
        facade.authenticationComplete(new OidcAccount(principal), true);
    }

    protected void completeBearerAuthentication(OidcPrincipal<RefreshableOidcSecurityContext> principal, String method) {
        facade.authenticationComplete(new OidcAccount(principal), false);
    }

    protected String changeHttpSessionId(boolean create) {
        HttpScope session = facade.getScope(Scope.SESSION);
        if (create) {
            if (! session.exists()) {
                session.create();
            }
        }
        return session != null ? session.getID() : null;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    private AuthOutcome doAuthenticate() {
        if (log.isTraceEnabled()) {
            log.trace("--> authenticate()");
        }

        BearerTokenRequestAuthenticator bearer = createBearerTokenAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try bearer");
        }

        AuthOutcome outcome = bearer.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            challenge = bearer.getChallenge();
            log.debug("Bearer FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) return AuthOutcome.FAILED;
            completeAuthentication(bearer, "KEYCLOAK");
            log.debug("Bearer AUTHENTICATED");
            return AuthOutcome.AUTHENTICATED;
        }

        QueryParameterTokenRequestAuthenticator queryParamAuth = createQueryParameterTokenRequestAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try query parameter auth");
        }

        outcome = queryParamAuth.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            challenge = queryParamAuth.getChallenge();
            log.debug("QueryParamAuth auth FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) return AuthOutcome.FAILED;
            log.debug("QueryParamAuth AUTHENTICATED");
            completeAuthentication(queryParamAuth, "KEYCLOAK");
            return AuthOutcome.AUTHENTICATED;
        }

        if (deployment.isEnableBasicAuth()) {
            BasicAuthRequestAuthenticator basicAuth = createBasicAuthAuthenticator();
            if (log.isTraceEnabled()) {
                log.trace("try basic auth");
            }

            outcome = basicAuth.authenticate(facade);
            if (outcome == AuthOutcome.FAILED) {
                challenge = basicAuth.getChallenge();
                log.debug("BasicAuth FAILED");
                return AuthOutcome.FAILED;
            } else if (outcome == AuthOutcome.AUTHENTICATED) {
                if (verifySSL()) return AuthOutcome.FAILED;
                log.debug("BasicAuth AUTHENTICATED");
                completeAuthentication(basicAuth, "BASIC");
                return AuthOutcome.AUTHENTICATED;
            }
        }

        if (deployment.isBearerOnly()) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (isAutodetectedBearerOnly(facade.getRequest())) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: Treating as bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (log.isTraceEnabled()) {
            log.trace("try oauth");
        }

        if (facade.getTokenStore().isCached(this)) {
            if (verifySSL()) return AuthOutcome.FAILED;
            log.debug("AUTHENTICATED: was cached");
            return AuthOutcome.AUTHENTICATED;
        }

        OAuthRequestAuthenticator oauth = createOAuthAuthenticator();
        outcome = oauth.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            challenge = oauth.getChallenge();
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.NOT_ATTEMPTED) {
            challenge = oauth.getChallenge();
            return AuthOutcome.NOT_ATTEMPTED;

        }

        if (verifySSL()) return AuthOutcome.FAILED;

        completeAuthentication(oauth);

        // redirect to strip out access code and state query parameters
        facade.getResponse().setHeader("Location", oauth.getStrippedOauthParametersRequestUri());
        facade.getResponse().setStatus(302);
        facade.getResponse().end();

        log.debug("AUTHENTICATED");
        outcome = AuthOutcome.AUTHENTICATED;
    }

    protected boolean verifySSL() {
        if (!facade.getRequest().isSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.warnf("SSL is required to authenticate. Remote address %s is secure: %s, SSL required for: %s .",
                    facade.getRequest().getRemoteAddr(), facade.getRequest().isSecure(), deployment.getSSLRequired().name());
            return true;
        }
        return false;
    }

    protected boolean isAutodetectedBearerOnly() {
        if (!deployment.isAutodetectBearerOnly()) return false;

        String headerValue = facade.getRequest().getHeader("X-Requested-With");
        if (headerValue != null && headerValue.equalsIgnoreCase("XMLHttpRequest")) {
            return true;
        }

        headerValue = facade.getRequest().getHeader("Faces-Request");
        if (headerValue != null && headerValue.startsWith("partial/")) {
            return true;
        }

        headerValue = facade.getRequest().getHeader("SOAPAction");
        if (headerValue != null) {
            return true;
        }

        List<String> accepts = facade.getRequest().getHeaders("Accept");
        if (accepts == null) accepts = Collections.emptyList();

        for (String accept : accepts) {
            if (accept.contains("text/html") || accept.contains("text/*") || accept.contains("*/*")) {
                return false;
            }
        }

        return true;
    }

    protected BearerTokenRequestAuthenticator createBearerTokenAuthenticator() {
        return new BearerTokenRequestAuthenticator(deployment);
    }

    protected BasicAuthRequestAuthenticator createBasicAuthAuthenticator() {
        return new BasicAuthRequestAuthenticator(deployment);
    }

    protected QueryParameterTokenRequestAuthenticator createQueryParameterTokenRequestAuthenticator() {
        return new QueryParameterTokenRequestAuthenticator(deployment);
    }

    protected void completeAuthentication(OAuthRequestAuthenticator oauth) {
        RefreshableOidcSecurityContext session = new RefreshableOidcSecurityContext(deployment, facade.getTokenStore(), oauth.getTokenString(), oauth.getToken(), oauth.getIDTokenString(), oauth.getIDToken(), oauth.getRefreshToken());
        final OidcPrincipal<RefreshableOidcSecurityContext> principal = new OidcPrincipal<>(oauth.getIDToken().getPrincipalName(deployment), session);
        completeOAuthAuthentication(principal);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

    protected void completeAuthentication(BearerTokenRequestAuthenticator bearer, String method) {
        RefreshableOidcSecurityContext session = new RefreshableOidcSecurityContext(deployment, null, bearer.getTokenString(), bearer.getToken(), null, null, null);
        final OidcPrincipal<RefreshableOidcSecurityContext> principal = new OidcPrincipal<>(AdapterUtils.getPrincipalName(deployment, bearer.getToken()), session);
        completeBearerAuthentication(principal, method);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

}
