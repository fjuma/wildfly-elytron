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

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.wildfly.security.json.util.StringOrArrayDeserializer;
import org.wildfly.security.json.util.StringOrArraySerializer;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * Representation of a JSON Web Token, as per <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class JsonWebToken implements Serializable, Token {

    public static final String ISS = "iss";
    public static final String SUB = "sub";
    public static final String AUD = "aud";
    public static final String EXP = "expiration";
    public static final String NBF = "notBefore";
    public static final String IAT = "iat";
    public static final String JTI = "jti";
    public static final String TYP = "typ";

    @JsonProperty(ISS)
    protected String issuer;

    @JsonProperty(SUB)
    protected String subject;

    @JsonProperty(AUD)
    @JsonSerialize(using = StringOrArraySerializer.class)
    @JsonDeserialize(using = StringOrArrayDeserializer.class)
    protected String[] audience;

    @JsonProperty(EXP)
    protected Long expiration;

    @JsonProperty(NBF)
    protected Long notBefore;

    @JsonProperty(IAT)
    protected Long iat;

    @JsonProperty(JTI)
    protected String id;

    @JsonProperty(TYP)
    protected String type;

    protected Map<String, Object> otherClaims = new HashMap<>();

    public String getIssuer() {
        return issuer;
    }

    public JsonWebToken setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public JsonWebToken setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    @JsonIgnore
    public String[] getAudience() {
        return audience;
    }

    public boolean hasAudience(String audience) {
        if (this.audience == null) {
            return false;
        }
        for (String a : this.audience) {
            if (a.equals(audience)) {
                return true;
            }
        }
        return false;
    }

    public JsonWebToken setAudience(String... audience) {
        this.audience = audience;
        return this;
    }

    public JsonWebToken addAudience(String audience) {
        if (this.audience == null) {
            this.audience = new String[] { audience };
        } else {
            // Check if audience is already there
            for (String aud : this.audience) {
                if (audience.equals(aud)) {
                    return this;
                }
            }

            String[] newAudience = Arrays.copyOf(this.audience, this.audience.length + 1);
            newAudience[this.audience.length] = audience;
            this.audience = newAudience;
        }
        return this;
    }

    public Long getExpiration() {
        return expiration;
    }

    @JsonIgnore
    public boolean isExpired() {
        return expiration != null && expiration != 0 ? getCurrentTimeInSeconds() > expiration : false;
    }

    public JsonWebToken setExpiration(Long expiration) {
        this.expiration = expiration;
        return this;
    }

    public Long getNotBefore() {
        return notBefore;
    }

    @JsonIgnore
    public boolean isNotBefore() {
        return notBefore != null ? getCurrentTimeInSeconds() >= notBefore : true;
    }

    public JsonWebToken setNotBefore(Long notBefore) {
        this.notBefore = notBefore;
        return this;
    }
    /**
     * Checks that the token is not expired and isn't prior to not-before.
     *
     * @return {@code true} if the token is active; {@code false} otherwise
     */
    @JsonIgnore
    public boolean isActive() {
        return !isExpired() && isNotBefore();
    }

    public Long getIssuedAt() {
        return iat;
    }

    @JsonIgnore
    public JsonWebToken setIssuedNow() {
        iat = Long.valueOf(getCurrentTimeInSeconds());
        return this;
    }

    public JsonWebToken setIssuedAt(Long iat) {
        this.iat = iat;
        return this;
    }

    public String getId() {
        return id;
    }

    public JsonWebToken setId(String id) {
        this.id = id;
        return this;
    }

    public String getType() {
        return type;
    }

    public JsonWebToken setType(String type) {
        this.type = type;
        return this;
    }

    /**
     * This is a map of any other claims and data that might be in the token.
     *
     * @return
     */
    @JsonAnyGetter
    public Map<String, Object> getOtherClaims() {
        return otherClaims;
    }

    @JsonAnySetter
    public void setOtherClaims(String name, Object value) {
        otherClaims.put(name, value);
    }

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.INTERNAL;
    }

    private static int getCurrentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }
}
