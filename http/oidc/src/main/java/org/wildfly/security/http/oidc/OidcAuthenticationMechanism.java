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

import static org.wildfly.security.http.HttpConstants.OIDC_NAME;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;
import static org.wildfly.security.http.oidc.Oidc.CODE;
import static org.wildfly.security.http.oidc.Oidc.ERROR;
import static org.wildfly.security.http.oidc.Oidc.KC_IDP_HINT;
import static org.wildfly.security.http.oidc.Oidc.LOGIN_HINT;
import static org.wildfly.security.http.oidc.Oidc.MAX_AGE;
import static org.wildfly.security.http.oidc.Oidc.OIDC_CLIENT_CONTEXT_KEY;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;
import static org.wildfly.security.http.oidc.Oidc.PROMPT;
import static org.wildfly.security.http.oidc.Oidc.REDIRECT_URI;
import static org.wildfly.security.http.oidc.Oidc.RESPONSE_TYPE;
import static org.wildfly.security.http.oidc.Oidc.SCOPE;
import static org.wildfly.security.http.oidc.Oidc.STATE;
import static org.wildfly.security.http.oidc.Oidc.UI_LOCALES;
import static org.wildfly.security.http.oidc.Oidc.generateId;

import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.http.client.utils.URIBuilder;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * An {@link HttpServerAuthenticationMechanism} to support OpenID Connect (OIDC).
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.15.0
 */
final class OidcAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final Map<String, ?> properties;
    private final CallbackHandler callbackHandler;
    private final OidcClientContext oidcClientContext;

    OidcAuthenticationMechanism(Map<String, ?> properties, CallbackHandler callbackHandler, OidcClientContext oidcClientContext) {
        this.properties = properties;
        this.callbackHandler = callbackHandler;
        this.oidcClientContext = oidcClientContext;
    }

    @Override
    public String getMechanismName() {
        return OIDC_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        OidcClientContext oidcClientContext = getOidcClientContext(request);

        if (oidcClientContext == null) {
            log.debugf("Ignoring request for path [%s] from mechanism [%s]. No client configuration context found.", request.getRequestURI(), getMechanismName());
            request.noAuthenticationInProgress();
            return;
        }

        OidcHttpFacade httpFacade = new OidcHttpFacade(request, oidcClientContext, callbackHandler);
        OidcClientConfiguration oidcClientConfiguration = httpFacade.getOidcClientConfiguration();

        if (!oidcClientConfiguration.isConfigured()) {
            request.noAuthenticationInProgress();
            return;
        }

        RequestAuthenticator authenticator = createRequestAuthenticator(request, httpFacade, oidcClientConfiguration);

        httpFacade.getTokenStore().checkCurrentToken();

        if (preActions(httpFacade, oidcClientContext)) {
            LOGGER.debugf("Pre-actions has aborted the evaluation of [%s]", request.getRequestURI());
            httpFacade.authenticationInProgress();
            return;
        }

        AuthOutcome outcome = authenticator.authenticate();

        if (AuthOutcome.AUTHENTICATED.equals(outcome)) {
            if (new AuthenticatedActionsHandler(oidcClientConfiguration, httpFacade).handledRequest()) {
                httpFacade.authenticationInProgress();
            } else {
                httpFacade.authenticationComplete();
            }
            return;
        }

        AuthChallenge challenge = authenticator.getChallenge();

        if (challenge != null) {
            httpFacade.noAuthenticationInProgress(challenge);
            return;
        }

        if (AuthOutcome.FAILED.equals(outcome)) {
            httpFacade.getResponse().setStatus(403);
            httpFacade.authenticationFailed();
            return;
        }

        httpFacade.noAuthenticationInProgress();
    }

    private void handleCallback(Callback callback) throws HttpAuthenticationException {
        //
    }

    private OidcClientContext getOidcClientContext(HttpServerRequest request) {
        if (this.oidcClientContext == null) {
            return (OidcClientContext) request.getScope(Scope.APPLICATION).getAttachment(OIDC_CLIENT_CONTEXT_KEY);
        }
        return this.oidcClientContext;
    }

    private void authenticate(HttpServerRequest request, OidcHttpFacade facade, OidcClientConfiguration oidcClientConfiguration) {
        String code = getCode(facade);
        if (code == null) {
            String error = getError(facade);
            if (error != null) {

            } else {
                // send authentication request to OpenID Connect server
            }
        } else {

        }

    }

    private void requestAuthentication(OidcHttpFacade facade, OidcClientConfiguration oidcClientConfiguration) {
        String state = generateId();
        String requestUri = facade.getRequest().getURI();

        if (!facade.getRequest().isSecure() && oidcClientConfiguration.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            int port = sslRedirectPort();
            if (port < 0) {
                // disabled?
                return null;
            }
            KeycloakUriBuilder secureUrl = KeycloakUriBuilder.fromUri(url).scheme("https").port(-1);
            if (port != 443) secureUrl.port(port);
            url = secureUrl.build().toString();
        }


        String scope = getQueryParamValue(facade, SCOPE);
        requestUri = stripQueryParam(requestUri, SCOPE);
        String prompt = getQueryParamValue(facade, PROMPT);
        requestUri = stripQueryParam(requestUri, PROMPT);
        String maxAge = getQueryParamValue(facade, MAX_AGE);
        requestUri = stripQueryParam(requestUri, MAX_AGE);
        String uiLocales = getQueryParamValue(facade, UI_LOCALES);
        requestUri = stripQueryParam(requestUri, UI_LOCALES);
        String loginHint = getQueryParamValue(facade, LOGIN_HINT);
        requestUri = stripQueryParam(requestUri, LOGIN_HINT);
        String kcIdpHint = getQueryParamValue(facade, KC_IDP_HINT);
        requestUri = stripQueryParam(requestUri, KC_IDP_HINT);

        URIBuilder redirectLocation = new URIBuilder(oidcClientConfiguration.getAuthUrl())
                .addParameter(SCOPE, addOidcScopeIfNeeded(scope))
                .addParameter(RESPONSE_TYPE, CODE)
                .addParameter(CLIENT_ID, oidcClientConfiguration.getResourceName())
                .addParameter(REDIRECT_URI, )
                .addParameter(STATE, state);
        if (prompt != null && ! prompt.isEmpty()) {
            redirectLocation.addParameter(PROMPT, prompt);
        }
        if (maxAge != null && ! maxAge.isEmpty()) {
            redirectLocation.addParameter(MAX_AGE, prompt);
        }
        if (uiLocales != null && ! uiLocales.isEmpty()) {
            redirectLocation.addParameter(UI_LOCALES, prompt);
        }
        if (loginHint != null && ! loginHint.isEmpty()) {
            redirectLocation.addParameter(LOGIN_HINT, prompt);
        }
        if (kcIdpHint != null && ! kcIdpHint.isEmpty()) {
            redirectLocation.addParameter(KC_IDP_HINT, prompt);
        }

        return redirectLocation.build().toString();
    }

    private static String getCode(OidcHttpFacade facade) {
        return getQueryParamValue(facade, CODE);
    }

    private static String getError(OidcHttpFacade facade) {
        return getQueryParamValue(facade, ERROR);
    }

    private static String getQueryParamValue(OidcHttpFacade facade, String paramName) {
        return facade.getRequest().getQueryParamValue(paramName);
    }

    private static String stripQueryParam(String url, String name){
        return url.replaceFirst("[\\?&]" + name + "=[^&]*$|" + name + "=[^&]*&", "");
    }

    private static String addOidcScopeIfNeeded(String scope) {
        if (scope == null || scope.isEmpty()) {
            return OIDC_SCOPE;
        } else if (hasScope(scope, OIDC_SCOPE)) {
            return scope;
        } else {
            return OIDC_SCOPE + " " + scope;
        }
    }

    private static boolean hasScope(String scopeParam, String targetScope) {
        if (scopeParam == null || targetScope == null) {
            return false;
        }

        String[] scopes = scopeParam.split(" ");
        for (String scope : scopes) {
            if (targetScope.equals(scope)) {
                return true;
            }
        }
        return false;
    }



}
