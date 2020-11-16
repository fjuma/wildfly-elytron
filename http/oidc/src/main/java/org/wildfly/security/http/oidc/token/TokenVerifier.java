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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public class TokenVerifier {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        List<Predicate<JsonWebToken>> checks = new ArrayList<>();

        public Builder withDecryptionCheck() {

            return this;
        }

        public Builder withIssuerCheck(String expectedIssuer) {
            Predicate<JsonWebToken> issuerCheck = idToken -> idToken.getIssuer().equals(expectedIssuer);
            checks.add(issuerCheck);
            return this;
        }

        public Builder
    }
}