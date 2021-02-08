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

import org.jose4j.jwt.JwtClaims;

/**
 * Representation of an OIDC ID token, as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IDToken extends JsonWebToken {

    public static final String AT_HASH = "at_hash";
    public static final String C_HASH = "c_hash";
    public static final String NAME = "name";
    public static final String GIVEN_NAME = "given_name";
    public static final String FAMILY_NAME = "family_name";
    public static final String MIDDLE_NAME = "middle_name";
    public static final String NICKNAME = "nickname";
    public static final String PREFERRED_USERNAME = "preferred_username";
    public static final String PROFILE = "profile";
    public static final String PICTURE = "picture";
    public static final String WEBSITE = "website";
    public static final String EMAIL = "email";
    public static final String EMAIL_VERIFIED = "email_verified";
    public static final String GENDER = "gender";
    public static final String BIRTHDATE = "birthdate";
    public static final String ZONEINFO = "zoneinfo";
    public static final String LOCALE = "locale";
    public static final String PHONE_NUMBER = "phone_number";
    public static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    public static final String ADDRESS = "address";
    public static final String UPDATED_AT = "updated_at";
    public static final String CLAIMS_LOCALES = "claims_locales";
    public static final String ACR = "acr";
    public static final String S_HASH = "s_hash";

    /**
     * Construct a new instance.
     *
     * @param jwtClaims the JWT claims for this instance (may not be {@code null})
     */
    public IDToken(JwtClaims jwtClaims) {
        super(jwtClaims);
    }

    public String getName() {
        return getClaimValueAsString(NAME);
    }

    public String getGivenName() {
        return getClaimValueAsString(GIVEN_NAME);
    }

    public String getFamilyName() {
        return getClaimValueAsString(FAMILY_NAME);
    }

    public String getMiddleName() {
        return getClaimValueAsString(MIDDLE_NAME);
    }

    public String getNickName() {
        return getClaimValueAsString(NICKNAME);
    }

    public String getPreferredUsername() {
        return getClaimValueAsString(PREFERRED_USERNAME);
    }

    public String getProfile() {
        return getClaimValueAsString(PROFILE);
    }

    public String getPicture() {
        return getClaimValueAsString(PICTURE);
    }

    public String getWebsite() {
        return getClaimValueAsString(WEBSITE);
    }

    public String getEmail() {
        return getClaimValueAsString(EMAIL);
    }

    public Boolean getEmailVerified() {
        return getClaimValue(EMAIL_VERIFIED, Boolean.class);
    }

    public String getGender() {
        return getClaimValueAsString(GENDER);
    }

    public String getBirthdate() {
        return getClaimValueAsString(BIRTHDATE);
    }

    public String getZoneinfo() {
        return getClaimValueAsString(ZONEINFO);
    }

    public String getLocale() {
        return getClaimValueAsString(LOCALE);
    }

    public String getPhoneNumber() {
        return getClaimValueAsString(PHONE_NUMBER);
    }

    public Boolean getPhoneNumberVerified() {
        return getClaimValue(PHONE_NUMBER_VERIFIED, Boolean.class);
    }

    public AddressClaimSet getAddress() {
        Object addressValue = getClaimValue(ADDRESS);
        return address;
    }

    public Long getUpdatedAt() {
        return getClaimValueAsLong(UPDATED_AT);
    }

    public String getClaimsLocales() {
        return getClaimValueAsString(CLAIMS_LOCALES);
    }

    public String getAccessTokenHash() {
        return getClaimValueAsString(AT_HASH);
    }

    public String getCodeHash() {
        return getClaimValueAsString(C_HASH);
    }

    public String getStateHash() {
        return getClaimValueAsString(S_HASH);
    }

    public String getAcr() {
        return getClaimValueAsString(ACR);
    }

}
