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

import java.util.List;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * Representation of a JSON Web Token, as per <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class JsonWebToken {

    public static final String EXP = "expiration";
    public static final String NBF = "notBefore";
    public static final String IAT = "iat";


    private final JwtClaims jwtClaims;

    public JsonWebToken(JwtClaims jwtClaims) {
        this.jwtClaims = jwtClaims;
    }

    public String getIssuer() {
        try {
            return jwtClaims.getIssuer();
        } catch (MalformedClaimException e) {

        }
    }

    public String getSubject() {
        try {
            return jwtClaims.getSubject();
        } catch (MalformedClaimException e) {

        }
    }

    public List<String> getAudience() {
        try {
            return jwtClaims.getAudience();
        } catch (MalformedClaimException e) {

        }
    }

    public Long getExpiration() {
        return getClaimValueAsLong(EXP);
    }

    public boolean isExpired() {
        Long expiration = getExpiration();
        return expiration != null && expiration != 0 ? getCurrentTimeInSeconds() > expiration : false;
    }

    public Long getNotBefore() {
        return getClaimValueAsLong(NBF);
    }

    public boolean isNotBefore() {
        Long notBefore = getNotBefore();
        return notBefore != null ? getCurrentTimeInSeconds() >= notBefore : true;
    }

    /**
     * Checks that the token is not expired and isn't prior to not-before.
     *
     * @return {@code true} if the token is active; {@code false} otherwise
     */
    public boolean isActive() {
        return !isExpired() && isNotBefore();
    }

    public Long getIssuedAt() {
        return getClaimValueAsLong(IAT);
    }

    public String getId() {
        try {
            return jwtClaims.getJwtId();
        } catch (MalformedClaimException e) {

        }
    }

    /**
     * This is a map of any other claims and data that might be in the token.
     *
     * @return
     */
    public Map<String, Object> getOtherClaims() {
        return otherClaims;
    }

    private static int getCurrentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }

    private Long getClaimValueAsLong(String claimName) {
        try {
            Long claimValue = jwtClaims.getClaimValue(claimName, Long.class);
            if (claimValue == null) {
                claimValue = 0L;
            }
        } catch (MalformedClaimException e) {

        }
    }

    protected Object getClaimValue(String claimName) {
        Object claim = null;

        switch (claimName) {
            // convert NumericDate values to Long
            case EXP:
            case IAT:
            case AUTH_TIME:
            case NBF:
            case UPDATED_AT:
                try {
                    claim = jwtClaims.getClaimValue(claimName, Long.class);
                    if (claim == null) {
                        claim = 0L;
                    }
                } catch (MalformedClaimException e) {
                    throw log.
                }
                break;
            default:
                claim = jwtClaims.getClaimValue(claimName);
        }
        return claim;
    }
}
