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

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jose4j.jwt.JwtClaims;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Representation of an access token.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AccessToken extends JsonWebToken {

    /**
     * Construct a new instance.
     *
     * @param jwtClaims the JWT claims for this instance (may not be {@code null})
     */
    public AccessToken(JwtClaims jwtClaims) {
        super(jwtClaims);
    }

    /*public static class Access implements Serializable {
        @JsonProperty("roles")
        protected Set<String> roles;
        @JsonProperty("verify_caller")
        protected Boolean verifyCaller;

        public Access() {
        }

        public Access clone() {
            Access access = new Access();
            access.verifyCaller = verifyCaller;
            if (roles != null) {
                access.roles = new HashSet<>();
                access.roles.addAll(roles);
            }
            return access;
        }

        public Set<String> getRoles() {
            return roles;
        }

        public Access roles(Set<String> roles) {
            this.roles = roles;
            return this;
        }

        @JsonIgnore
        public boolean isUserInRole(String role) {
            if (roles == null) return false;
            return roles.contains(role);
        }

        public Access addRole(String role) {
            if (roles == null) roles = new HashSet<>();
            roles.add(role);
            return this;
        }

        public Boolean getVerifyCaller() {
            return verifyCaller;
        }

        public Access verifyCaller(Boolean required) {
            this.verifyCaller = required;
            return this;
        }
    }

    public static class Authorization implements Serializable {

        @JsonProperty("permissions")
        private Collection<Permission> permissions;

        public Collection<Permission> getPermissions() {
            return permissions;
        }

        public void setPermissions(Collection<Permission> permissions) {
            this.permissions = permissions;
        }
    }

    // KEYCLOAK-6771 Certificate Bound Token
    // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3.1
    public static class CertConf {
        @JsonProperty("x5t#S256")
        protected String certThumbprint;

        public String getCertThumbprint() {
            return certThumbprint;
        }

        public void setCertThumbprint(String certThumbprint) {
            this.certThumbprint = certThumbprint;
        }
    }

    @JsonProperty("trusted-certs")
    protected Set<String> trustedCertificates;

    @JsonProperty("allowed-origins")
    protected Set<String> allowedOrigins;

    @JsonProperty("realm_access")
    protected Access realmAccess;

    @JsonProperty("resource_access")
    protected Map<String, Access> resourceAccess;

    @JsonProperty("authorization")
    protected Authorization authorization;

    @JsonProperty("cnf")
    protected CertConf certConf;

    @JsonProperty("scope")
    protected String scope;

    @JsonIgnore
    public Map<String, Access> getResourceAccess() {
        return resourceAccess == null ? Collections.<String, Access>emptyMap() : resourceAccess;
    }

    public void setResourceAccess(Map<String, Access> resourceAccess) {
        this.resourceAccess = resourceAccess;
    }

    *//**
     * Does the realm require verifying the caller?
     *
     * @return
     *//*
    @JsonIgnore
    public boolean isVerifyCaller() {
        if (getRealmAccess() != null && getRealmAccess().getVerifyCaller() != null)
            return getRealmAccess().getVerifyCaller().booleanValue();
        return false;
    }

    *//**
     * Does the resource override the requirement of verifying the caller?
     *
     * @param resource
     * @return
     *//*
    @JsonIgnore
    public boolean isVerifyCaller(String resource) {
        Access access = getResourceAccess(resource);
        if (access != null && access.getVerifyCaller() != null) return access.getVerifyCaller().booleanValue();
        return false;
    }

    @JsonIgnore
    public Access getResourceAccess(String resource) {
        return resourceAccess == null ? null : resourceAccess.get(resource);
    }

    public Access addAccess(String service) {
        if (resourceAccess == null) {
            resourceAccess = new HashMap<>();
        }

        Access access = resourceAccess.get(service);
        if (access != null) return access;
        access = new Access();
        resourceAccess.put(service, access);
        return access;
    }

    @Override
    public AccessToken setId(String id) {
        return (AccessToken) super.setId(id);
    }

    @Override
    public AccessToken setExpiration(Long expiration) {
        return (AccessToken) super.setExpiration(expiration);
    }

    @Override
    public AccessToken setNotBefore(Long notBefore) {
        return (AccessToken) super.setNotBefore(notBefore);
    }


    @Override
    public AccessToken setIssuedAt(Long issuedAt) {
        return (AccessToken) super.setIssuedAt(issuedAt);
    }

    @Override
    public AccessToken setIssuer(String issuer) {
        return (AccessToken) super.setIssuer(issuer);
    }

    @Override
    public AccessToken setSubject(String subject) {
        return (AccessToken) super.setSubject(subject);
    }

    @Override
    public AccessToken setType(String type) {
        return (AccessToken) super.setType(type);
    }

    public Set<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(Set<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public Access getRealmAccess() {
        return realmAccess;
    }

    public void setRealmAccess(Access realmAccess) {
        this.realmAccess = realmAccess;
    }

    public Set<String> getTrustedCertificates() {
        return trustedCertificates;
    }

    public void setTrustedCertificates(Set<String> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }

    @Override
    public AccessToken setIssuedFor(String issuedFor) {
        return (AccessToken)super.setIssuedFor(issuedFor);
    }

    public Authorization getAuthorization() {
        return authorization;
    }

    public void setAuthorization(Authorization authorization) {
        this.authorization = authorization;
    }

    public CertConf getCertConf() {
        return certConf;
    }

    public void setCertConf(CertConf certConf) {
        this.certConf = certConf;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.ACCESS;
    }
*/
}
