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
import static org.wildfly.security.http.oidc.Oidc.CODE;
import static org.wildfly.security.http.oidc.Oidc.ERROR;
import static org.wildfly.security.http.oidc.Oidc.STATE;
import static org.wildfly.security.http.oidc.Oidc.generateId;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OAuthRequestAuthenticator {
    protected OidcClientConfiguration deployment;
    protected RequestAuthenticator reqAuthenticator;
    protected int sslRedirectPort;
    protected OidcSessionTokenStore tokenStore;
    protected String tokenString;
    protected String idTokenString;
    protected IDToken idToken;
    protected AccessToken token;
    protected OidcHttpFacade facade;
    protected AuthChallenge challenge;
    protected String refreshToken;
    protected String strippedOauthParametersRequestUri;

    public OAuthRequestAuthenticator(RequestAuthenticator requestAuthenticator, OidcHttpFacade facade, OidcClientConfiguration deployment, int sslRedirectPort, OidcSessionTokenStore tokenStore) {
        this.reqAuthenticator = requestAuthenticator;
        this.facade = facade;
        this.deployment = deployment;
        this.sslRedirectPort = deployment.getConfidentialPort() != -1 ? deployment.getConfidentialPort() : sslRedirectPort;
        this.tokenStore = tokenStore;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    public String getTokenString() {
        return tokenString;
    }

    public AccessToken getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getIDTokenString() {
        return idTokenString;
    }

    public void setIDTokenString(String idTokenString) {
        this.idTokenString = idTokenString;
    }

    public IDToken getIDToken() {
        return idToken;
    }

    public void setIDToken(IDToken idToken) {
        this.idToken = idToken;
    }

    public String getStrippedOauthParametersRequestUri() {
        return strippedOauthParametersRequestUri;
    }

    public void setStrippedOauthParametersRequestUri(String strippedOauthParametersRequestUri) {
        this.strippedOauthParametersRequestUri = strippedOauthParametersRequestUri;
    }

    protected String getRequestUrl() {
        return facade.getRequest().getURI();
    }

    protected boolean isRequestSecure() {
        return facade.getRequest().isSecure();
    }

    protected OidcHttpFacade.Cookie getCookie(String cookieName) {
        return facade.getRequest().getCookie(cookieName);
    }

    protected String getCookieValue(String cookieName) {
        OidcHttpFacade.Cookie cookie = getCookie(cookieName);
        if (cookie == null) return null;
        return cookie.getValue();
    }

    protected String getQueryParamValue(String paramName) {
        return facade.getRequest().getQueryParamValue(paramName);
    }

    protected String getError() {
        return getQueryParamValue(ERROR);
    }

    protected String getCode() {
        return getQueryParamValue(CODE);
    }

    protected String getRedirectUri(String state) {
        String url = getRequestUrl();
        log.debugf("callback uri: %s", url);

        if (!facade.getRequest().isSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            int port = sslRedirectPort();
            if (port < 0) {
                // disabled?
                return null;
            }
            KeycloakUriBuilder secureUrl = KeycloakUriBuilder.fromUri(url).scheme("https").port(-1);
            if (port != 443) secureUrl.port(port);
            url = secureUrl.build().toString();
        }

        String loginHint = getQueryParamValue("login_hint");
        url = UriUtils.stripQueryParam(url,"login_hint");

        String idpHint = getQueryParamValue(AdapterConstants.KC_IDP_HINT);
        url = UriUtils.stripQueryParam(url, AdapterConstants.KC_IDP_HINT);

        String scope = getQueryParamValue(OAuth2Constants.SCOPE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.SCOPE);

        String prompt = getQueryParamValue(OAuth2Constants.PROMPT);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.PROMPT);

        String maxAge = getQueryParamValue(OAuth2Constants.MAX_AGE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.MAX_AGE);

        String uiLocales = getQueryParamValue(OAuth2Constants.UI_LOCALES_PARAM);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.UI_LOCALES_PARAM);

        KeycloakUriBuilder redirectUriBuilder = deployment.getAuthUrl().clone()
                .queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .queryParam(OAuth2Constants.CLIENT_ID, deployment.getResourceName())
                .queryParam(OAuth2Constants.REDIRECT_URI, rewrittenRedirectUri(url))
                .queryParam(OAuth2Constants.STATE, state)
                .queryParam("login", "true");
        if(loginHint != null && loginHint.length() > 0){
            redirectUriBuilder.queryParam("login_hint",loginHint);
        }
        if (idpHint != null && idpHint.length() > 0) {
            redirectUriBuilder.queryParam(AdapterConstants.KC_IDP_HINT,idpHint);
        }
        if (prompt != null && prompt.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }
        if (maxAge != null && maxAge.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.MAX_AGE, maxAge);
        }
        if (uiLocales != null && uiLocales.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.UI_LOCALES_PARAM, uiLocales);
        }

        scope = TokenUtil.attachOIDCScope(scope);
        redirectUriBuilder.queryParam(OAuth2Constants.SCOPE, scope);

        return redirectUriBuilder.build().toString();
    }

    protected int sslRedirectPort() {
        return sslRedirectPort;
    }

    protected String getStateCode() {
        return generateId();
    }

    protected AuthChallenge loginRedirect() {
        final String state = getStateCode();
        final String redirect =  getRedirectUri(state);
        if (redirect == null) {
            return challenge(403, OIDCAuthenticationError.Reason.NO_REDIRECT_URI, null);
        }
        return new AuthChallenge() {

            @Override
            public int getResponseCode() {
                return 0;
            }

            @Override
            public boolean challenge(OidcHttpFacade exchange) {
                tokenStore.saveRequest();
                log.debug("Sending redirect to login page: " + redirect);
                exchange.getResponse().setStatus(302);
                exchange.getResponse().setCookie(deployment.getStateCookieName(), state, "/", null, -1, deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr()), true);
                exchange.getResponse().setHeader("Location", redirect);
                return true;
            }
        };
    }

    protected AuthChallenge checkStateCookie() {
        OidcHttpFacade.Cookie stateCookie = getCookie(deployment.getStateCookieName());

        if (stateCookie == null) {
            log.warn("No state cookie");
            return challenge(400, OIDCAuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }
        // reset the cookie
        log.debug("** reseting application state cookie");
        facade.getResponse().resetCookie(deployment.getStateCookieName(), stateCookie.getPath());
        String stateCookieValue = getCookieValue(deployment.getStateCookieName());

        String state = getQueryParamValue(STATE);
        if (state == null) {
            log.warn("state parameter was null");
            return challenge(400, OIDCAuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }
        if (!state.equals(stateCookieValue)) {
            log.warn("state parameter invalid");
            log.warn("cookie: " + stateCookieValue);
            log.warn("queryParam: " + state);
            return challenge(400, OIDCAuthenticationError.Reason.INVALID_STATE_COOKIE, null);
        }
        return null;

    }

    public Oidc.AuthOutcome authenticate() {
        String code = getCode();
        if (code == null) {
            log.debug("there was no code");
            String error = getError();
            if (error != null) {
                // todo how do we send a response?
                log.warn("There was an error: " + error);
                challenge = challenge(400, OIDCAuthenticationError.Reason.OAUTH_ERROR, error);
                return Oidc.AuthOutcome.FAILED;
            } else {
                log.debug("redirecting to auth server");
                challenge = loginRedirect();
                return Oidc.AuthOutcome.NOT_ATTEMPTED;
            }
        } else {
            log.debug("there was a code, resolving");
            challenge = resolveCode(code);
            if (challenge != null) {
                return Oidc.AuthOutcome.FAILED;
            }
            return Oidc.AuthOutcome.AUTHENTICATED;
        }

    }

    protected AuthChallenge challenge(final int code, final OIDCAuthenticationError.Reason reason, final String description) {
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return code;
            }

            @Override
            public boolean challenge(OidcHttpFacade exchange) {
                OIDCAuthenticationError error = new OIDCAuthenticationError(reason, description);
                exchange.getRequest().setError(error);
                exchange.getResponse().sendError(code);
                return true;
            }
        };
    }

    /**
     * Start or continue the oauth login process.
     * <p/>
     * if code query parameter is not present, then browser is redirected to authUrl.  The redirect URL will be
     * the URL of the current request.
     * <p/>
     * If code query parameter is present, then an access token is obtained by invoking a secure request to the codeUrl.
     * If the access token is obtained, the browser is again redirected to the current request URL, but any OAuth
     * protocol specific query parameters are removed.
     *
     * @return null if an access token was obtained, otherwise a challenge is returned
     */
    protected AuthChallenge resolveCode(String code) {
        // abort if not HTTPS
        if (!isRequestSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.error("Adapter requires SSL. Request: " + facade.getRequest().getURI());
            return challenge(403, OIDCAuthenticationError.Reason.SSL_REQUIRED, null);
        }

        log.debug("checking state cookie for after code");
        AuthChallenge challenge = checkStateCookie();
        if (challenge != null) return challenge;

        AccessTokenResponse tokenResponse = null;
        strippedOauthParametersRequestUri = rewrittenRedirectUri(stripOauthParametersFromRedirect());

        try {
            // For COOKIE store we don't have httpSessionId and single sign-out won't be available
            String httpSessionId = deployment.getTokenStore() == Oidc.TokenStore.SESSION ? reqAuthenticator.changeHttpSessionId(true) : null;
            tokenResponse = ServerRequest.invokeAccessCodeToToken(deployment, code, strippedOauthParametersRequestUri, httpSessionId);
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to turn code into token");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null && !failure.getError().trim().isEmpty()) {
                log.error("   " + failure.getError());
            }
            return challenge(403, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE, null);

        } catch (IOException e) {
            log.error("failed to turn code into token", e);
            return challenge(403, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE, null);
        }

        tokenString = tokenResponse.getToken();
        refreshToken = tokenResponse.getRefreshToken();
        idTokenString = tokenResponse.getIdToken();

        log.debug("Verifying tokens");
        if (log.isTraceEnabled()) {
            logToken("\taccess_token", tokenString);
            logToken("\tid_token", idTokenString);
            logToken("\trefresh_token", refreshToken);
        }

        try {
            AdapterTokenVerifier.VerifiedTokens tokens = AdapterTokenVerifier.verifyTokens(tokenString, idTokenString, deployment);
            token = tokens.getAccessToken();
            idToken = tokens.getIdToken();
            TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();
            TokenValidator.VerifiedTokens verifiedTokens = tokenValidator.parseAndVerifyToken(idTokenString, tokenString);
            idToken = verifiedTokens.getIdToken();
            token = verifiedTokens.getAccessToken();
            log.debug("Token Verification succeeded!");
        } catch (OidcException e) {
            log.failedVerificationOfToken(e.getMessage());
            return challenge(403, OIDCAuthenticationError.Reason.INVALID_TOKEN, null);
        }
        if (tokenResponse.getNotBeforePolicy() > deployment.getNotBefore()) {
            deployment.updateNotBefore(tokenResponse.getNotBeforePolicy());
        }
        if (token.getIssuedAt() < deployment.getNotBefore()) {
            log.error("Stale token");
            return challenge(403, OIDCAuthenticationError.Reason.STALE_TOKEN, null);
        }
        log.debug("successful authenticated");
        return null;
    }

    /**
     * strip out unwanted query parameters and redirect so bookmarks don't retain oauth protocol bits
     */
    protected String stripOauthParametersFromRedirect() {
        KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(facade.getRequest().getURI())
                .replaceQueryParam(OAuth2Constants.CODE, null)
                .replaceQueryParam(OAuth2Constants.STATE, null)
                .replaceQueryParam(OAuth2Constants.SESSION_STATE, null);
        return builder.build().toString();
    }

    private String rewrittenRedirectUri(String originalUri) {
        Map<String, String> rewriteRules = deployment.getRedirectRewriteRules();
        if(rewriteRules != null && !rewriteRules.isEmpty()) {
            try {
                URL url = new URL(originalUri);
                Map.Entry<String, String> rule =  rewriteRules.entrySet().iterator().next();
                StringBuilder redirectUriBuilder = new StringBuilder(url.getProtocol());
                redirectUriBuilder.append("://"+ url.getAuthority());
                redirectUriBuilder.append(url.getPath().replaceFirst(rule.getKey(), rule.getValue()));
                return redirectUriBuilder.toString();
            } catch (MalformedURLException ex) {
                log.error("Not a valid request url");
                throw new RuntimeException(ex);
            }
        }
        return originalUri;
    }

    private void logToken(String name, String token) {
        try {
            JWSInput jwsInput = new JWSInput(token);
            String wireString = jwsInput.getWireString();
            log.tracef("\t%s: %s", name, wireString.substring(0, wireString.lastIndexOf(".")) + ".signature");
        } catch (JWSInputException e) {
            log.errorf(e, "Failed to parse %s: %s", name, token);
        }
    }
}
