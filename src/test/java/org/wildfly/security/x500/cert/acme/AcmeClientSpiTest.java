/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.x500.cert.acme;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.x500.cert.X509CertificateChainAndSigningKey;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import sun.security.ec.ECPublicKeyImpl;


/**
 * Tests for the Automatic Certificate Management Environment (ACME) client SPI. These tests simulate a mock Let's Encrypt
 * server by using messages that were actually sent from Boulder (Let's Encrypt's testing server) to our ACME client.
 * Wireshark was used to record the messages. The use of these recorded messages prevent us from having to integrate the
 * complex Boulder setup into the Elytron testsuite.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AcmeClientSpiTest {

    private static AcmeAccount.Builder populateBasicBuilder() throws Exception {
        AcmeAccount.Builder builder = AcmeAccount.builder()
                .setTermsOfServiceAgreed(true)
                .setContactUrls(new String[] { "mailto:admin@example.com" } )
                .setServerUrl("http://localhost:4001/directory");
        return builder;
    }

    private static final String KEYSTORE = "account.keystore";
    private static final char[] KEYSTORE_PASSWORD = "elytron".toCharArray();
    private static final String ACCOUNT_1 = "account1";
    private static final String ACCOUNT_2 = "account2";
    private static final String ACCOUNT_3 = "account3";
    private static final String ACCOUNT_4 = "account4";
    private static final String ACCOUNT_5 = "account5";
    private static final String ACCOUNT_6 = "account6";
    private static final String ACCOUNT_7 = "account7";
    private static final String ACCOUNT_8 = "account8";
    private static final String ACCOUNT_9 = "account9";
    private static final String REVOKE_ALIAS = "revokealias";
    private static final String REVOKE_WITH_REASON_ALIAS = "revokewithreasonalias";
    private static final String NEW_KEY_ALIAS = "newkey";
    private static final String NEW_EC_KEY_ALIAS = "neweckey";
    private static HashMap<String, X509Certificate> aliasToCertificateMap;
    private static HashMap<String, PrivateKey> aliasToPrivateKeyMap;

    private final SimpleAcmeClient acmeClient = new SimpleAcmeClient();
    private MockWebServer client; // used to simulate a WildFly instance
    private ClientAndServer server; // used to simulate a Let's Encrypt server instance

    @BeforeClass
    public static void setUp() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream is = AcmeClientSpiTest.class.getResourceAsStream(KEYSTORE)) {
            keyStore.load(is, KEYSTORE_PASSWORD);
        }

        int numAliases = keyStore.size();
        aliasToCertificateMap = new HashMap<>(numAliases);
        aliasToPrivateKeyMap = new HashMap<>(numAliases);
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasToCertificateMap.put(alias, (X509Certificate) keyStore.getCertificate(alias));
            aliasToPrivateKeyMap.put(alias, (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD));
        }
    }

    @Before
    public void startMockClient() throws Exception {
        client = new MockWebServer();
        client.start(5002); // this is the port our mock Let's Encrypt server will use to access the client
    }

    @After
    public void shutdownMockClientAndServer() throws Exception {
        if (client != null) {
            client.shutdown();
        }
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void testCreateAccount() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";
        server = setupTestCreateAccount();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testCreateAccountOnlyReturnExisting() throws Exception {
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";
        server = setupTestCreateAccountOnlyReturnExisting();
        AcmeAccount account = populateBasicAccount(ACCOUNT_2);
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION_1, account.getAccountUrl());
        AcmeAccount sameAccount = populateBasicAccount(ACCOUNT_2);

        // the key corresponding to ACCOUNT_2 is associated with an already registered account
        acmeClient.createAccount(sameAccount, false, true);
        assertEquals(account.getAccountUrl(), sameAccount.getAccountUrl());

        AcmeAccount newAccount = populateBasicAccount(ACCOUNT_3);
        try {
            // the key corresponding to ACCOUNT_3 is not associated with an already registered account
            acmeClient.createAccount(newAccount, false, true);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    @Test
    public void testCreateAccountWithECPublicKey() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";
        server = setupTestCreateAccountWithECPublicKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_4);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testUpdateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";
        server = setupTestUpdateAccount();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        account.setAccountUrl(ACCT_LOCATION);
        String[] contacts = new String[] { "mailto:certificates@example.com", "mailto:admin@example.com"};
        acmeClient.updateAccount(account, false, false, contacts);
        assertFalse(account.isTermsOfServiceAgreed());

        String[] updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);

        acmeClient.updateAccount(account, false, false, null);
        updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);
    }

    @Test
    public void testDeactivateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/392";
        server = setupTestDeactivateAccount();
        AcmeAccount account = populateBasicAccount(ACCOUNT_5);
        account.setAccountUrl(ACCT_LOCATION);
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        acmeClient.deactivateAccount(account, false);
        assertTrue(account.isDeactivated());
        try {
            acmeClient.obtainCertificateChain(account, false, client.getHostName());
            fail("Expected AcmeException not thrown");
        } catch (AcmeException e) {
            assertTrue(e.getMessage().contains("deactivated"));
        }
    }

    @Test
    public void testGetNonce() throws Exception {
        final String NEW_NONCE_RESPONSE = "d4o3tdwrnpzwi9xgI21EqNdDyInvLcrENqTXthWD0qg";
        server = setupTestGetNonce();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        account.setNonce(CodePointIterator.ofString("rtJAy_mcjDFGnnzCOAbGMGM6w8P3qU0bRDMf8sjt5IU").base64Decode(Alphabet.Base64Alphabet.URL, false).drain());
        String nonce = ByteIterator.ofBytes(account.getNonce()).base64Encode(Alphabet.Base64Alphabet.URL, false).drainToString();
        assertNotNull(nonce);

        String newNonce = ByteIterator.ofBytes(acmeClient.getNewNonce(account, false)).base64Encode(Alphabet.Base64Alphabet.URL, false).drainToString();
        assertFalse(nonce.equals(newNonce));
        assertEquals(NEW_NONCE_RESPONSE, newNonce);
    }

    @Test
    public void testObtainCertificateChain() throws Exception {
        server = setupTestObtainCertificate();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        String domainName = "fmnhfsziiloydrh.com"; // randomly generated domain name
        obtainCertificateChain(null, -1, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithKeySize() throws Exception {
        server = setupTestObtainCertificateWithKeySize();
        AcmeAccount account = populateBasicAccount(ACCOUNT_6);
        String domainName = "inlneseppwkfwew.com"; // randomly generated domain name
        obtainCertificateChain("RSA", 4096, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithECPublicKey() throws Exception {
        server = setupTestObtainCertificateWithECPublicKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_7);
        String domainName = "qbqxylgyjmgywtk.com"; // randomly generated domain name
        obtainCertificateChain("EC", 256, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithUnsupportedPublicKey() throws Exception {
        try {
            server = setupTestObtainCertificateWithUnsupportedPublicKey();
            AcmeAccount account = populateBasicAccount(ACCOUNT_7);
            String domainName = "iraclzlcqgaymrc.com";
            obtainCertificateChain("DSA", 2048, account, domainName);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    private void obtainCertificateChain(String keyAlgorithmName, int keySize, AcmeAccount account, String domainName) throws Exception {
        X509CertificateChainAndSigningKey certificateChainAndSigningKey = acmeClient.obtainCertificateChain(account, false, keyAlgorithmName, keySize, domainName);
        PrivateKey privateKey = certificateChainAndSigningKey.getSigningKey();

        X509Certificate[] replyCertificates = certificateChainAndSigningKey.getCertificateChain();
        assertTrue(replyCertificates.length == 2);
        X509Certificate signedCert = replyCertificates[0];
        X509Certificate caCert = replyCertificates[1];
        assertTrue(signedCert.getSubjectDN().getName().contains(domainName));
        assertEquals(caCert.getSubjectDN(), signedCert.getIssuerDN());
        assertEquals("CN=cackling cryptographer fake ROOT", caCert.getIssuerDN().getName());
        if (keyAlgorithmName != null && keySize != -1) {
            assertEquals(keyAlgorithmName, privateKey.getAlgorithm());
            assertEquals(keyAlgorithmName, signedCert.getPublicKey().getAlgorithm());
            if (keyAlgorithmName.equals("EC")) {
                assertEquals(keySize, ((ECPublicKeyImpl) signedCert.getPublicKey()).getParams().getCurve().getField().getFieldSize());
            } else if (keyAlgorithmName.equals("RSA")) {
                assertEquals(keySize, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
            }
        } else {
            if (signedCert.getPublicKey().getAlgorithm().equals("RSA")) {
                assertEquals(AcmeClientSpi.DEFAULT_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("RSA", privateKey.getAlgorithm());
            } else if (signedCert.getPublicKey().getAlgorithm().equals("EC")) {
                assertEquals(AcmeClientSpi.DEFAULT_EC_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("EC", privateKey.getAlgorithm());
            }
        }
    }

    @Test
    public void testRevokeCertificateWithoutReason() throws Exception {
        server = setupTestRevokeCertificate();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        revokeCertificate(account, null);
    }

    @Test
    public void testRevokeCertificateWithReason() throws Exception {
        server = setupTestRevokeCertificateWithReason();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        revokeCertificate(account, CRLReason.AA_COMPROMISE);
    }

    private void revokeCertificate(AcmeAccount account, CRLReason reason) throws Exception {
        X509Certificate certificateToRevoke;
        if (reason == null) {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_ALIAS);
        } else {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_WITH_REASON_ALIAS);
        }
        acmeClient.revokeCertificate(account, false, certificateToRevoke);
    }

    @Test
    public void testChangeAccountKey() throws Exception {
        server = setupTestChangeAccountKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_6);
        X509Certificate oldCertificate = account.getCertificate();
        X500Principal oldDn = account.getDn();
        acmeClient.changeAccountKey(account, false);
        assertTrue(! oldCertificate.equals(account.getCertificate()));
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));
    }

    @Test
    public void testChangeAccountKeySpecifyCertificateAndPrivateKey() throws Exception {
        server = setupTestChangeAccountKeySpecifyCertificateAndPrivateKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_8);
        X500Principal oldDn = account.getDn();

        // RSA account key
        X509Certificate newCertificate = aliasToCertificateMap.get(NEW_KEY_ALIAS);
        PrivateKey newPrivateKey = aliasToPrivateKeyMap.get(NEW_KEY_ALIAS);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // ECDSA account key
        newCertificate = aliasToCertificateMap.get(NEW_EC_KEY_ALIAS);
        newPrivateKey = aliasToPrivateKeyMap.get(NEW_EC_KEY_ALIAS);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // attempting to change the account key to a key that is already in use for a different account should fail
        account = populateBasicAccount(ACCOUNT_9);
        X509Certificate oldCertificate = account.getCertificate();
        PrivateKey oldPrivateKey = account.getPrivateKey();
        try {
            acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
        assertEquals(oldCertificate, account.getCertificate());
        assertEquals(oldPrivateKey, account.getPrivateKey());
    }

    /* -- Helper methods used to set up the messages that should be sent from the mock Let's Encrypt server to our ACME client. -- */

    private ClientAndServer setupTestCreateAccount() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"TrOIFke5bdM\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "8-k95dsqpJLtOQapuL-0XGrBH0UM6lcfdop9OUp05_I";

        final String NEW_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiI4LWs5NWRzcXBKTHRPUWFwdUwtMFhHckJIMFVNNmxjZmRvcDlPVXAwNV9JIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXX0\",\"signature\":\"Js_fvpkTcDkWhJqwYNMdDqQKz6pWTxT0I5XzT0PrF0hTupSMc0uvUBc19xD64_x4fFsEZMlv1l_d2jm1pt-7nySWcYQFbkYh-tdRuxygzCCXdFhsXsw3MGh13KghkgiawjW37TFw8DrIWSwlsuGEIjofF2TqExecX0mkyF-vl6VA7Gm9oiqxfRiKx-X4YaO7-ijUnG7EMyesSKfu3PmBcaPsO9gIjRQ4FHrOb1RTSmTupskb4pZ0D2tkwKZcWWmXwO2XnLPjF5ZZi6c0p7GA_f578r665toyqP9n7PV6Vlf8w8XrM_EsF201r4oCFyVTEuAYx9fozKYIEhZe-PDWdw\"}";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28.490176768-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "20y41JJoZ3Rn0VCEKDRa5AzT0kjcz6b6FushFyVS4zY";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY, NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, NEW_ACCT_LOCATION, 201)
                .build();
        return server;
    }

    private ClientAndServer setupTestCreateAccountOnlyReturnExisting() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"5ZnL5mAsOXE\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_1 = "4UlRsB6SRdVCGnNiN3Ll8XKbc1LBw22RAy8PyK7KWlg";

        final String NEW_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJrc2ttSXFLaXcxejFSRXpwTzBXR3B5MWtiT2xYNENIb1dHMFJib0RoSk5KVHRLR2xYcmFMN1lESnBpdFZsUmt0cWlxRDlYdExEUl9qN2llSVlkbUhuOHpkbkV0aGVEaVZ6Wk5UQVFXRGtmbXJnVlRiN1JzS01mVW9qNWR1YnY2YWFLZWVObXpTRFZDQ1hfbU15RnU5QlllV3ZxS1V4OUNXWW84YWRvOU1kQmJMUExYZWJuenhtcVlkOWJUc3JqTkxjYXBWSm50NDhENzdObjdlVURfQWNnclFTOXRyLW1FM01MRTNkeUMyZGpEbC1pY3RkTXJIXzlFdGxhQ3ViUkF6NV9tZG8xWFFlTDdMOHdFVGxqaVdQQ2NCZi03S0xRXzlkTUFpeHk4Yy1ZenplejlNWnQ1bUt0N1FIcWlFdEV5Wm1jNWdaVjNpNUdYMUZiSlY1Vmt3cVEifSwibm9uY2UiOiI0VWxSc0I2U1JkVkNHbk5pTjNMbDhYS2JjMUxCdzIyUkF5OFB5SzdLV2xnIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXX0\",\"signature\":\"bkMP9_HkVWKqvc0iA6SyJedP44L7wKbTLVJ8d2Q6E1iY0_MrqnjZooYPeFQuc4BkmMw3iqm7wB1dmPXtIvieEs4BN8aCduDkCL2KYGcHfbZbjo2x5i3EcOX2n31GYVsC1RCW_2tao6-kNk9q-qivrER2acBwY3fuDTW9Cp1H_71MipA6OJiOhvbBvziCp8ux3GdZpT2wZNJXBZrDyhw0axbaZ-E8-Gzq2HCZU1FiEb72zOoaizc5oYBMYgT5KVSwtAXzKi2oCyoisHv1H-W7iiKLUvRkdDstxuH7VjakhRzRgRwXHY9kStu4QZX9IzrTKFcnXoviSEUMfedjahDLWQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"id\": 387," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"kskmIqKiw1z1REzpO0WGpy1kbOlX4CHoWG0RboDhJNJTtKGlXraL7YDJpitVlRktqiqD9XtLDR_j7ieIYdmHn8zdnEtheDiVzZNTAQWDkfmrgVTb7RsKMfUoj5dubv6aaKeeNmzSDVCCX_mMyFu9BYeWvqKUx9CWYo8ado9MdBbLPLXebnzxmqYd9bTsrjNLcapVJnt48D77Nn7eUD_AcgrQS9tr-mE3MLE3dyC2djDl-ictdMrH_9EtlaCubRAz5_mdo1XQeL7L8wETljiWPCcBf-7KLQ_9dMAixy8c-Yzzez9MZt5mKt7QHqiEtEyZmc5gZV3i5GX1FbJV5VkwqQ\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T13:05:44.561791555-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_1 = "wR25VhDQw1ciGDZhP88SbWjJ4hzNEh6a1PVjAbyEzO4";
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator()  +
                "  \"-McmmrFKskk\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_2 = "2foRCfGWXljb13vsFVElg19cNchN1xt_8_uQFdNEF1c";

        final String NEW_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJrc2ttSXFLaXcxejFSRXpwTzBXR3B5MWtiT2xYNENIb1dHMFJib0RoSk5KVHRLR2xYcmFMN1lESnBpdFZsUmt0cWlxRDlYdExEUl9qN2llSVlkbUhuOHpkbkV0aGVEaVZ6Wk5UQVFXRGtmbXJnVlRiN1JzS01mVW9qNWR1YnY2YWFLZWVObXpTRFZDQ1hfbU15RnU5QlllV3ZxS1V4OUNXWW84YWRvOU1kQmJMUExYZWJuenhtcVlkOWJUc3JqTkxjYXBWSm50NDhENzdObjdlVURfQWNnclFTOXRyLW1FM01MRTNkeUMyZGpEbC1pY3RkTXJIXzlFdGxhQ3ViUkF6NV9tZG8xWFFlTDdMOHdFVGxqaVdQQ2NCZi03S0xRXzlkTUFpeHk4Yy1ZenplejlNWnQ1bUt0N1FIcWlFdEV5Wm1jNWdaVjNpNUdYMUZiSlY1Vmt3cVEifSwibm9uY2UiOiIyZm9SQ2ZHV1hsamIxM3ZzRlZFbGcxOWNOY2hOMXh0XzhfdVFGZE5FRjFjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"f2hWPR39C65InXgAqonIuHPVmPVVshJymqY24iiti9RQ0BKrZJp1xAT_QyjYPlKNTOfLT3DQwCmcEsoHVaOkjg3VXA9OXXfoC413mqmsI6pnJERLFwotllrxKXtxzcECbLligsp8L9wo5V4vKosJrFI-Td8_Ovr6rCLhvBCANoZ4wY7wZHmMRWM2sApbqz7ENwkhjrZyHqyG1HSU5wpJcikaGGYqotQ9aljfmHoRF-TFl-HZ7II0XxPUvA3Vt8jH34kwlkAFc5hOCZeC-IJdfKjdn-OT67cG4MvQSVhyflG7Zlj4pr544Qhi_g9oQAj169aGcpuXkqK326x5GE5vzA\"}";

        final String NEW_ACCT_RESPONSE_BODY_2 = "";

        final String NEW_ACCT_REPLAY_NONCE_2 = "pPg6MZQ3E-BA48w_lTG13vNF9YpavncifBMlqr8I8fE";
        final String NEW_ACCT_LOCATION_2 = "http://localhost:4001/acme/acct/387";

        final String DIRECTORY_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"VmW3Odu7SoU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_3 = "zpTwvAKlWIkRSnIBD25DUF6-IgSEz-RzQCRH7J5eK74";

        final String NEW_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJxYmFNS2hZSDdCRVNaNVRERzdicnI5UmNZdFVhWFRucHJEVVBSTmhIQXBhTDZ5UHhHTnBrcXNhYWZhdDFtVWxzb1NkQjkybHotVjJmUTJjWTJTbjRuU0h6QkFxblRkVlRDa3hNOTZZUFZMT0RWckFRcDIwYlFheG12b1JMbHFUZUVRa3EyX0NjOFBObzB6TmEzOExGUzl1Y1JQZ3hUWkdxczJvdExGWjUtSUxLQXZhSWZSY0VURGhkWHVZU1pLTEwtdXh5ZnF0T0xDd0NrUlU0X2ZRdDg1UUZKXzhHc0V6VVV5V1JnOXFKSWZ4UkRsUjdCYmk4QmNRMzd6OEh6V205SzQxbEZkei1icWdOUDQ3UTJXdWQ1b1dJNmIzRE5UVmVCc1QzOTB1NmdUNGhfbWNaRF9HQXBicElUa2hIdk1HVHN2WDUwSThKNXRhclFCN25McTU1M3cifSwibm9uY2UiOiJ6cFR3dkFLbFdJa1JTbklCRDI1RFVGNi1JZ1NFei1SelFDUkg3SjVlSzc0IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"XFR9CbJf_dztYaMGdbTjloViZozO1ZdFeWjJa5OWlYGFmjwm-sxMUjxJ8-WPSr0okdgHw8JgW50jGi1UHikIgm5HGqJ-X6alfT8DwPpbvny2gDnmW5ZUgPNtfHUDmfzo7sU9caxsYZbQFZCydLUfXRsI8GnI0D27S-ikqIXGPCX0JgfRTIhv2EJBxQNkdnOvMhmCFBZiTA1CHfMsAbiIkgaAt6MXOnOTVqi5hNrLCN6Nb-IaXVTOW8y_fz23T5-K1DBQs23VVyphM53iXUlxmHoJ1L7oZSjKi9XltNxLvEExQra885Os-MUdmpm9eTnJgsDvFlww8tcMQnx7KDpcSQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"type\": \"urn:ietf:params:acme:error:accountDoesNotExist\"," + System.lineSeparator()  +
                "  \"detail\": \"No account exists with the provided key\"," + System.lineSeparator()  +
                "  \"status\": 400" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_3 = "rtJAy_mcjDFGnnzCOAbGMGM6w8P3qU0bRDMf8sjt5IU";
        final String NEW_ACCT_LOCATION_3 = "";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_1, NEW_ACCT_RESPONSE_BODY_1, NEW_ACCT_REPLAY_NONCE_1, NEW_ACCT_LOCATION_1, 201)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_2, NEW_ACCT_RESPONSE_BODY_2, NEW_ACCT_REPLAY_NONCE_2, NEW_ACCT_LOCATION_2, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_3)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_3)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_3, NEW_ACCT_RESPONSE_BODY_3, NEW_ACCT_REPLAY_NONCE_3, NEW_ACCT_LOCATION_3, 400, true)
                .build();
        return server;
    }

    private ClientAndServer setupTestCreateAccountWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"YlEPLZkkmYU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "7bNmFPLpdcNFpSxolQF_8evQ6xtzX3bKyEwsi24nYHA";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"id\": 389," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"EC\"," + System.lineSeparator()  +
                "    \"crv\": \"P-256\"," + System.lineSeparator()  +
                "    \"x\": \"hpB4Z3w5IOsY7ADpPoA-nkwOl3Rh2pCVnzO6ByUMeww\"," + System.lineSeparator()  +
                "    \"y\": \"zeaxTqrr6evY_ind3ZeVQZneL2X79nmlTxhO8aObl5A\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-24T11:04:39.436869571-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "XCFz0nWlCpEs-49S1p7qks-S0JcXS7uw2g4gQtJwUEI";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse("", NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, NEW_ACCT_LOCATION, 201)
                .build();

        return server;
    }

    private ClientAndServer setupTestUpdateAccount() {

        // set up a mock Let's Encrypt server
        final String ACCT_PATH = "/acme/acct/384";
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"UlOnbFfGuy0\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String NEW_NONCE_RESPONSE = "JIXt7BXuxPar-7YHhiy9lQEWB2fuJ_O2ikEy8XoUr7M";

        final String UPDATE_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJKSVh0N0JYdXhQYXItN1lIaGl5OWxRRVdCMmZ1Sl9PMmlrRXk4WG9VcjdNIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zODQifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2UsImNvbnRhY3QiOlsibWFpbHRvOmNlcnRpZmljYXRlc0BleGFtcGxlLmNvbSIsIm1haWx0bzphZG1pbkBleGFtcGxlLmNvbSJdfQ\",\"signature\":\"pkfD8sgtfXWDgKzx0FSEfVRHCCPlhIPCNC5Z4j0pa8qa-L-e3V1YbmPCjsEHF3leziMQ30aEE3capzw_bAev2LBg3Oqko_-nKGEbAHOaFJhIK4zJ7Alc4gEEH7KTNbSHkrW4YAQNcFDRSVaDYsPT-e4N6ZFEwpl11mqYbYC2kn0Basz7oMPqWxmM4u2e6mmYdIZ2fC55pgGWdvmZxDcO42lERmDV2l-BKcaxVcN0XqHZcF5tUY3eUWxvaVClArHjbOAqo0bfTEWEVmPHqBW7xHRpJymySs2HZbzyfxQpXo3VfqMy1hnQheFA8oq0vNBPHH4iyyOmegmza2WHZ7QN8w\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"," + System.lineSeparator()  +
                "    \"mailto:certificates@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String UPDATE_ACCT_REPLAY_NONCE_1 = "rXNvQT-1t0WL34fe6LVNHeP0o3LYW020wNy_NJPvi_o";

        final String UPDATE_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJyWE52UVQtMXQwV0wzNGZlNkxWTkhlUDBvM0xZVzAyMHdOeV9OSlB2aV9vIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zODQifQ\",\"payload\":\"e30\",\"signature\":\"fKFVRc3tirIijgHjwaLOBnv4CKZCiiOxi1ohih0pLSB699LOSePHVr7q-DVQsHSoNAut3Im868tmiVl8XevOep4O4xOn60RppqTCCi7X6uWVJTUfj11qPFmepaleGeKiiHwGWtCShXZbS-TfPm-B3V35ecPQMXiBe-imnsVZZYAGgR58TE58cUVSJnct3n6qQq86910a80vuZDILK6ihv9rK6u6NyHMvR4CZM6xaLOI2SYmiqs-E7itbqh_uFqX_fybffG7VBOhvjR52Ypt76Tx3PbXOOAD4GX-LtjnVkv3tTdjiTmbZnvxAr-wwH-BmyFMcKSJP_Lcnr_BFSJ-ijg\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:certificates@example.com\"," + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_2 = "bM-w3PfPb0GfbqAKvi7_Ew8RhXFuIQlQ6YvSmGYkspI";

        final String UPDATE_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJiTS13M1BmUGIwR2ZicUFLdmk3X0V3OFJoWEZ1SVFsUTZZdlNtR1lrc3BJIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zODQifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2V9\",\"signature\":\"Ihyxf7peIeYWwsI3fKvwPVIrS_u-KDEUj2sz27hjd16xkpvSLDe50EuL1E0Go__Nzj3ox5jRN7rJ96xtojxO4MjKnjof2sGNsVz8qr09FTZpaPtR91GFbzuhuCzh6P0Ba3aF4ufFG6hDDT1hkVn5bYmMsViM8bnE16EB9woiUWRjOFdfYjhXrURyC6koPmkfxTCbGESsRWRJhKW_Fhw0vFmkjuDYShreBDZoe3iX8IwC8cg4ks2Vl_1ZTKDMN6Znh4RIsYyWPxuUye5aOgGi-cwiFVgmdvsD0o8ujB8jva9wjOAydpWksHIzWxlOjmHMJw6kVkq_9OCNDmaVz_ZzHw\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:certificates@example.com\"," + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_3 = "fkD8BDkynfHE1UESpUvHtCLa4S2WkCIwpXdO47Q3vzA";

        final String UPDATE_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJma0Q4QkRreW5mSEUxVUVTcFV2SHRDTGE0UzJXa0NJd3BYZE80N1EzdnpBIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zODQifQ\",\"payload\":\"e30\",\"signature\":\"cyg9Mgmgw4KcTGB96Uz1XPflyZCXgBYWRTiuppLLBMVYBG-eZvrCvzkjqlBTXfmixpBaCPoYU9PnNg3FEYgYzut8zgOsrvcgyu7byYdxnO9LxtxFCnLYPp8xGyoRD9W3owAxcbKnwTf3rmxhSKBRCDZnGs-JuZqJc25kbK4tLNZLaPfdyBS3oaE7xzxKrz6waLCIt9_CoRlSjqc9ZY9P8syUVdkdmdMtlyZJPJNt-keteulOA2_4xZzUV0RdxswlivT3v5Zz9bDuj5JPtHx-1NHSjRhLcM2pl2wk9pvm35q4_au4DjiP5enP-x_-qn6fXJuNUsuUdv_DHjmWLYL7Vw\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_4 = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:certificates@example.com\"," + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_4 = "NT_I4byOA1qs22GwXEcNp9RNyoq4hO6JTBMh1iUK3yI";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_1, UPDATE_ACCT_RESPONSE_BODY_1, UPDATE_ACCT_REPLAY_NONCE_1, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_2, UPDATE_ACCT_RESPONSE_BODY_2, UPDATE_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_3, UPDATE_ACCT_RESPONSE_BODY_3, UPDATE_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_4, UPDATE_ACCT_RESPONSE_BODY_4, UPDATE_ACCT_REPLAY_NONCE_4, ACCT_PATH, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestDeactivateAccount() {
        final String ACCT_PATH = "/acme/acct/392";

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"ZrMhBE165Rs\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "7j07RSDwagTZc4rjP-nlajOulnfJ0JaRkVncHbFHWi4";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzkyIiwibm9uY2UiOiI3ajA3UlNEd2FnVFpjNHJqUC1ubGFqT3VsbmZKMEphUmtWbmNIYkZIV2k0IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zOTIifQ\",\"payload\":\"e30\",\"signature\":\"bJhpQniDy39Cc7_NvBop9Ow6kNc3SFK5PKGgBtb3uON9rRh4xXMjSgW8B96wxxks_FZ4sc3cYKDphz025aWXBeVG24b5oHu3DjC7zIy-AKZhspmN1AB5DK2htvdW57-ZpV868wZ0ir9mr1MwsX69cbWJ0rjjmU54zG46poMtGKpb8Rxcvn7Ukx2ykqDfsPgHKpW0c2Gcns5cRugJsLUW0UHCTcgdthqwmpzZaQjlYFF5VOq_KXIoznVx1b2iM_g_NERZ7-ZhSvQA_-fQgiDqIwvoqqfuvtkd3WdPMKga3iPNpz5057QvKJLNk7EYY8zZJIxFnh1H-e8I-2Yxj0pJAQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 392," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"hUeAw6lgPh8RbmUW-KPexgLmvIRmW7Yf3Z60kUTK3WMIcJK3UxuLC5mSa8nSmzYTnvX9VE7JcjcoNaWn9g01qYbzTaRPMIDpryiEolmhZi4-Of7g-LREiXFRRUmEo9kdYuPOfBeGQRidbLegBP0uevJ0gmvxh-l3G4eal_ptZImDjRj0KQxA5Vv0dFrimIyGE8Cv-H_qXdysmfMtcUlMBQF2fw2kqyb-gpKZt9lsq97TolbkkEzPMR0PoKWdjL5UYlO-2PqU1L3YFjdLwU2M0Y8j9G9rTJkeUyrvi7W3QiXsXAyxJzHTZqKMyN3CAUFis0Imb2M9UIiEZ_a2EebxsQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-04-24T17:37:34-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE = "3zGE6H4OgdOGS-yqaVBkzTolNK_9K4ahMWDHbhw39RE";

        final String UPDATE_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzkyIiwibm9uY2UiOiIzekdFNkg0T2dkT0dTLXlxYVZCa3pUb2xOS185SzRhaE1XREhiaHczOVJFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8zOTIifQ\",\"payload\":\"eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9\",\"signature\":\"PIjiZ1YUO3RKnHqrr7YoGk3od-8TJDjbunJHPoc0dZPjGCtoiYRe2N511_ocRMwlsjS_uRv9B0bmK4q2yC68R7j-QPxOyweM4kUqjbvvaw26YWqEGHpWemCHjOxmIlT1goCo9iytdwT-8MLllqS3mwp6l0jJaQImP6vQLYyGUKuLddKFhUQ3-HmfMZNZWoDV2IpdYfL5ennVmg3QyHH6WzKV5N3QO1gWDEsKqFVLU2brS2x9TIZj0LkTuXSjXGrE2rUNbTLJFjyb-fHaIUW-7MULmbKwjfnvK2N2dA_gQbDVrLdXAo4RV0KX4C5Y4eIcsoSURuQ1EKCK3aFkI7OFaw\"}";

        final String UPDATE_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 392," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"hUeAw6lgPh8RbmUW-KPexgLmvIRmW7Yf3Z60kUTK3WMIcJK3UxuLC5mSa8nSmzYTnvX9VE7JcjcoNaWn9g01qYbzTaRPMIDpryiEolmhZi4-Of7g-LREiXFRRUmEo9kdYuPOfBeGQRidbLegBP0uevJ0gmvxh-l3G4eal_ptZImDjRj0KQxA5Vv0dFrimIyGE8Cv-H_qXdysmfMtcUlMBQF2fw2kqyb-gpKZt9lsq97TolbkkEzPMR0PoKWdjL5UYlO-2PqU1L3YFjdLwU2M0Y8j9G9rTJkeUyrvi7W3QiXsXAyxJzHTZqKMyN3CAUFis0Imb2M9UIiEZ_a2EebxsQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-04-24T17:37:34-04:00\"," + System.lineSeparator() +
                "  \"status\": \"deactivated\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATE_ACCT_REPLAY_NONCE = "ygSXETQgJ4opycgEcdfcn24fLo0dB5hvyS4IYnJetPc";

        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzkyIiwibm9uY2UiOiJ5Z1NYRVRRZ0o0b3B5Y2dFY2RmY24yNGZMbzBkQjVodnlTNElZbkpldFBjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibG9jYWxob3N0In1dfQ\",\"signature\":\"a-6Sf6fYyMLJgOLOxl4bLmz348uTfCLuV4RA-Sd_Yb1ou7DZeRlalCBVgktbl1If4UD0CcZJC7MSJk0_j2DdsZVCmeKU5s952hHCWSmx_xxEkdFCxN1W3LBi1FJgv8-jV-U3wxrLMd-71ew4wJdB23hgvlSNtfbjGN1HsG24eL0Z5_0Z1Wv7qylfGlduMTrhcf5jDE5Qr0km-IL7YHXNk3MkRbNqbRSq7p7O0axU43KIy3qFMnfUEPmGxAm5VgQQS2-smG3HJ3ntWWLoQjrf4LEhNMXgO5v811hng97-kApMINmvEM3jpnTs63H6_UNYiVbd8RvAYc8hcIlH7KI97Q\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:unauthorized\"," + System.lineSeparator() +
                "  \"detail\": \"Account is not valid, has status \\\"deactivated\\\"\"," + System.lineSeparator() +
                "  \"status\": 403" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "f5U5rSKBUtBgltl7L3FyYRwDV4obThvWceFx1eKL_QA";
        final String ORDER_LOCATION = "";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY, UPDATE_ACCT_RESPONSE_BODY, UPDATE_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 403, true)
                .build();
        return server;
    }

    private ClientAndServer setupTestGetNonce() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"L3kiSpDcTos\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "d4o3tdwrnpzwi9xgI21EqNdDyInvLcrENqTXthWD0qg";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .build();
        return server;
    }

    private ClientAndServer setupTestObtainCertificate() {
        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"hb7nxeqSiSo\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "WUPHlxoSwKlvWLMFEHRRwOzHu2w3aIIaRV9WrZ9GyjU";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiJXVVBIbHhvU3dLbHZXTE1GRUhSUndPekh1MnczYUlJYVJWOVdyWjlHeWpVIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"Tf8oG1wgAZk7sjR24hPuCn76OhLLEeU4eYgfEn6Qj00BZGaoyP73sHkEGHXd5i9Wuq1IDZeDyORJwinUy8CyEOrc8a0kexWHc0Mmf4I3E0G0zcYPBhWpiKaJnRZZVS3yIgmVUzIKvSsxcZKMhroBrXBiSAJaRkSMiMlHMneJD8imC8ZhMxPVy6LRcX7Qbn9_UkLziQeCJmFobl22MLz_ztV2Oes4j-XoU29g5CmkSnt2iZhxVFpJBGVjVNrSJ2FpeJRxU5MSiKhGcEyhYGPI1dTNLIP-hsW-EFnt2n4Voc6jODg3y-3i3ss0GoCsxYrZcs0N_R8qgHv11go4XlnGZQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "7__LBygWEmfpW9sHRcQHtC-HM0uwyKBIq-hOGFmzk3c";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiI3X19MQnlnV0VtZnBXOXNIUmNRSHRDLUhNMHV3eUtCSXEtaE9HRm16azNjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZm1uaGZzemlpbG95ZHJoLmNvbSJ9XX0\",\"signature\":\"pt8Nvyg6yKPgVjkUbrWfbhL2qXEg2B3MDay2GfayejfbwAKBArMaydBG_ThhWsPCGFEZCvXwLKV8FmUn2Il8CdKdIzsdY0RMe2MSCUJCAwoEWRklUCN75tNgR6gj9Y2OQKZbbxWbjLpFoAqw2_A_D1znHWN8Ox3sq8bHlcUrD8KkL8O4I2rUKI6Fm8L2y4sZI-PEI_LKIVJXiyFpWWFHsO4ZOfFdOgoL58i1Bgrgr0xhLROcYEI48-p1sn2wmsQqaUrBKJNUXps7dhgKXUt-G93CO0HFm0Xxi3U_-8qOhPwetgw_B-A8bHhGIaMAcP2dnjpmKj4X2hLsH3P0lYTQZQ\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-02T20:11:28.210065401Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fmnhfsziiloydrh.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/384/166\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "YUDhgPBTesEv52ZZ77V8ZfAovAMqPl9TnBhNtTnlbBY";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/384/166";

        final String AUTHZ_URL = "/acme/authz/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fmnhfsziiloydrh.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-02T16:11:28-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/496\"," + System.lineSeparator() +
                "      \"token\": \"6cQ_SO5Nxs3YQeSVBrq91s4ke-yHU4K0VNYD3s4zr9I\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/497\"," + System.lineSeparator() +
                "      \"token\": \"keKCsWqDxcVR1VdZdYnNuht6xiFJwHC6J4jW4CA0yEY\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/498\"," + System.lineSeparator() +
                "      \"token\": \"SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJZVURoZ1BCVGVzRXY1MlpaNzdWOFpmQW92QU1xUGw5VG5CaE50VG5sYkJZIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL2ozX2t3VHMwN0l3TWdDUVp2RHZnMUZPcW80eUJpYmZiTWt5eVFaSWVLYU0vNDk4In0\",\"payload\":\"e30\",\"signature\":\"ZFNvnN1G8BBKFYjUPB0TvND8vMwR6ArN0eEokQpu6E0SYVqBavp5wFAaKTXnBirAvHyfABNCgZjJLD9GLnZa0qL5Kg9PqVPClzbgFsZi8mewPDuwxoqCfx_KsGA0OlNsisW52-NGa3c5cnt_YdtPXhCPIaDPmKTzMZggf9bwS6m9FnepTcpgI9ZjQj-AxS0K6lt4afgAGViAnVQqf2Npmya3df_edrLlTTrBggj1JPM0XOkg5TzaPvCIJsueC203ptXWU0kjxKxEf2Bpzs0cTqy-bj8e1XPFS3JD-VSEwi3NzPCZNIutHG5kXHeBgpd6ro563-m0Zc6ArWKOuEI8Lw\"}";
        final String CHALLENGE_URL = "/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/498";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/498\"," + System.lineSeparator() +
                "  \"token\": \"SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "KrvoQsU_cku-kcg1_vFYnPflMcjlyShqtL-VCT25oOg";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/498";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I";
        final String CHALLENGE_FILE_CONTENTS = "SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I.p8ESGS6nX--L-ReV0llT4mUDFkS7Bt1cyMoa0zqPDkk";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fmnhfsziiloydrh.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-25T16:11:28-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/496\"," + System.lineSeparator() +
                "      \"token\": \"6cQ_SO5Nxs3YQeSVBrq91s4ke-yHU4K0VNYD3s4zr9I\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/497\"," + System.lineSeparator() +
                "      \"token\": \"keKCsWqDxcVR1VdZdYnNuht6xiFJwHC6J4jW4CA0yEY\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM/498\"," + System.lineSeparator() +
                "      \"token\": \"SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://fmnhfsziiloydrh.com:5002/.well-known/acme-challenge/SxIxhH3OqymZm1PSinj2NpAgJGrkA_6supBo7GpPL0I\"," + System.lineSeparator() +
                "          \"hostname\": \"fmnhfsziiloydrh.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"127.0.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"127.0.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/384/166";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-02T20:11:28Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fmnhfsziiloydrh.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/384/166\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff1705619b5f2167417f511e7c433070dd7d\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "9I52cjOeLI5dWfDp4HkEMn9lGENL1j1oPkd6MkXVl6o";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/384/166";

        final String CHECK_ORDER_URL = "/acme/order/384/166";

        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-02T20:11:28Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fmnhfsziiloydrh.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/j3_kwTs07IwMgCQZvDvg1FOqo4yBibfbMkyyQZIeKaM\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/384/166\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff1705619b5f2167417f511e7c433070dd7d\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff1705619b5f2167417f511e7c433070dd7d";

        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIFZTCCBE2gAwIBAgITAP8XBWGbXyFnQX9RHnxDMHDdfTANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODA0MjUxOTEx" + System.lineSeparator() +
                "MjhaFw0xODA3MjQxOTExMjhaMB4xHDAaBgNVBAMTE2Ztbmhmc3ppaWxveWRyaC5j" + System.lineSeparator() +
                "b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCR5ZEym1FSQFUrjUbk" + System.lineSeparator() +
                "GyXm1Q3a67Z8zKBEl7tEkYYrnDwBpezv4o1GfNywOk10EEmWIZ/q5b5Jb0bC87Th" + System.lineSeparator() +
                "HZx6jMl5L6tJynlRsElb49LKZ3zKXsuVRJQdirc3NNRmipjjW5fAiNz8Bvjc1h86" + System.lineSeparator() +
                "hx/qns9KxQ+B5Va8MizgA/fF8gXPE6nEK1uABS68T7qaucxo1BCF6y0Z6Gy369fx" + System.lineSeparator() +
                "ZXg9REUQm0+XZNsNT+XQaaNnMGtzCc00GcUv5VQqsXwFgrr3L674wB/LNX9PZktT" + System.lineSeparator() +
                "pklWElUojKgx7Lv/V28rMRnLSMvqBb4oaKK8eNxhxklFcEYcBUp6ESVZViQelNUJ" + System.lineSeparator() +
                "VVFPAgMBAAGjggKZMIIClTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYB" + System.lineSeparator() +
                "BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFMNiF4yVAK7y" + System.lineSeparator() +
                "qltQobssyTwB26HRMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGQG" + System.lineSeparator() +
                "CCsGAQUFBwEBBFgwVjAiBggrBgEFBQcwAYYWaHR0cDovLzEyNy4wLjAuMTo0MDAy" + System.lineSeparator() +
                "LzAwBggrBgEFBQcwAoYkaHR0cDovL2JvdWxkZXI6NDQzMC9hY21lL2lzc3Vlci1j" + System.lineSeparator() +
                "ZXJ0MB4GA1UdEQQXMBWCE2Ztbmhmc3ppaWxveWRyaC5jb20wJwYDVR0fBCAwHjAc" + System.lineSeparator() +
                "oBqgGIYWaHR0cDovL2V4YW1wbGUuY29tL2NybDBhBgNVHSAEWjBYMAgGBmeBDAEC" + System.lineSeparator() +
                "ATBMBgMqAwQwRTAiBggrBgEFBQcCARYWaHR0cDovL2V4YW1wbGUuY29tL2NwczAf" + System.lineSeparator() +
                "BggrBgEFBQcCAjATDBFEbyBXaGF0IFRob3UgV2lsdDCCAQIGCisGAQQB1nkCBAIE" + System.lineSeparator() +
                "gfMEgfAA7gB1ACh2GhiQJ/vvPNDWGgGNdrBQVynHp0EbzL32BPRdQmFTAAABYv5u" + System.lineSeparator() +
                "rNkAAAQDAEYwRAIgGkEneD0XKGA3kV6nGA9wYwA023+IIo6bNgUKmRu/5HECIAxk" + System.lineSeparator() +
                "XWreei3+6tIAobxjaYEwL/5i4SEHWQg8+cVNYtJ5AHUAFuhpwdGV6tfD+Jca4/B2" + System.lineSeparator() +
                "AfeM4badMahSGLaDfzGoFQgAAAFi/m6s0AAABAMARjBEAiBvXyWcC/a2TMm8yf9h" + System.lineSeparator() +
                "TIisaVIzJkOQFjAfl8aO5T3GPQIgHZSmcFE7u2Z3JTwL1GWG6nAKxjdaCwet+EdK" + System.lineSeparator() +
                "fA6xeicwDQYJKoZIhvcNAQELBQADggEBAEbaXUEdnzGM87mtbhGKXja3dVBipmxx" + System.lineSeparator() +
                "OMphZdmhOcfxP/lxagBXi64RWVIHBweKrVwBy1vlo0dODl1i2F/oraFOnQWgEBcr" + System.lineSeparator() +
                "rwJo+b5+MXqxemTaIhMKpVPYgkSj8xOK49PYypv36JGbySharDr3DOizUoGVy1V0" + System.lineSeparator() +
                "K9yTNw1oUjH5GuXPs5XUBOX8xP4B9KnJ9DN5mjeVwVQy041BOzXrkgcYRRicujGi" + System.lineSeparator() +
                "tgUCbHX98cRvL3rFlP1jXehSuMzUFhANf3lFYp7eD8WNAJJ9JSLCPad2TlGqxXYk" + System.lineSeparator() +
                "hm4LBFmS8nKREnK1LjPB3a6Nzq2KXb322i4xmumReTwREwMf0+Q5+rQ=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_RESPONSE_BODY)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_RESPONSE_BODY, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_RESPONSE_BODY, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestObtainCertificateWithKeySize() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"R0Qoi70t57s\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "wZs7Qj4KhGezoRoMHYzq2nlcQWyZiAiOah2UfQQKhPQ";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoNWlULUY4UzZMczJLZlRMNUZpNV9hRzhpdWNZTl9yajJVXy16ck8yckpxczg2WHVHQnY1SDdMZm9vOWxqM3lsaXlxNVQ2ejdkY3RZOW1rZUZXUEIxaEk0Rjg3em16azFWR05PcnM5TV9KcDlPSVc4QVllNDFsMHBvWVpNQTllQkE0ZnV6YmZDTUdONTdXRjBfMjhRRmJuWTVXblhXR3VPa0N6QS04Uk5IQlRxX3Q1a1BWRV9jNFFVemRJcVoyZG54el9FZ05jdU1hMXVHZEs3YmNybEZIdmNrWjNxMkpsT0NEckxEdEJpYW96ZnlLR0lRUlpheGRYSlE2cl9tZVdHOWhmZUJuMTZKcG5nLTU4TFd6X0VIUVFtLTN1bl85UVl4d2pIY2RDdVBUQ1RXNEFwcFdnZ1FWdE00ZTd6U1ZzMkZYczdpaVZKVzhnMUF1dFFINU53Z1EifSwibm9uY2UiOiJ3WnM3UWo0S2hHZXpvUm9NSFl6cTJubGNRV3laaUFpT2FoMlVmUVFLaFBRIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"S6MIw5ARCDuziMR-Z5QSH_BctKUasPVV4KQyffUG4yRTooWrksISGY9-nX0D7_jIjiP0R-oiAmKiw6m6sVxjpoEC1LRQGXcGvg-SOGxxt_mTMI1fkdjfkn4hvVpX2FOcfCi_3ewdvi2WCndrzohv3pXAjY9_JkMV9egx6sP6vRV_tRJ3ukoKkLdqbnRFeWir_vCUahbExXZi0utJvvD1PyfXeLVMNahQdJxFwahHMYGXz7gofnFIrQtplHEzBvev5Tc7iWps4UM1Kvd4sPhX-j0unJVHZrX5AWFSuFsy9lIdkjpJ2gCd64h7noxstdoTbnETz4761eQjyVIITHrmiA\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "ggf6K6xbBH8NK5ND69jGbM9TRMFO7HssBxzgWKDq0Js";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/398";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzk4Iiwibm9uY2UiOiJnZ2Y2SzZ4YkJIOE5LNU5ENjlqR2JNOVRSTUZPN0hzc0J4emdXS0RxMEpzIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaW5sbmVzZXBwd2tmd2V3LmNvbSJ9XX0\",\"signature\":\"LbOPleWSCBaL1id8fw5fc5xm8eqFGLMOv_kwFXBr8QxfYF5RIDkW6Jsi-6gqCvDY7w5A7UcX-Fzcc2nUwAfwdHEOsUM9hkSBZkS54LmYWxZPLsIuBdTvkCSCSS94bqAnSnZXIch7seiJ4ZR1VQXVRnkMk5hD-_ipIOMYgVSwGqALz2NpW222QoY03LPaA5NkhnMdnIOia5aPzla5NQ9MXmOHBI5MIlTYIrYoccEXhM3jiqu1eDQohvMirUV76e2iAv8BovR8ys7fVC2AC36ithZNA-hRaxcHzJzXg9RGei4yOXcFoCHg6Xn1wygxshd2cc2Ov61TvTx9NUPmeDqK7g\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T18:27:35.087023897Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/398/186\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "u7eY2Z97yZOJTU82Z3nNa9-gFTe4-srSEECIUpa-63c";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/398/186";

        final String AUTHZ_URL = "/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T14:27:35-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/535\"," + System.lineSeparator() +
                "      \"token\": \"AYnykYJWn-VsPeMLf6IFIXH1h9el6vmJf4LuX3qitwI\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/536\"," + System.lineSeparator() +
                "      \"token\": \"yLCOHl4TTraVOukhyFglf2u6bV7yhc3bQULkUJ1KWKI\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/537\"," + System.lineSeparator() +
                "      \"token\": \"6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzk4Iiwibm9uY2UiOiJ1N2VZMlo5N3laT0pUVTgyWjNuTmE5LWdGVGU0LXNyU0VFQ0lVcGEtNjNjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL0xKUkgzLWdqVVB0NVU1djh3SDFDaDNlRmN4dThVSy11b3RqdXRtNU5COXMvNTM3In0\",\"payload\":\"e30\",\"signature\":\"gCp9SSPiVyJNAQ9PUB8rsBVb5aceV-XrjyjtWiXa8JJ5kgN1V4T_KIz372FLd1Bn7w6wGt1uMND_KBHvHRkTTspPJZxfQaJPDLzHvnswPjLsKK1-KHH5Bz3wjXDN379H9rVD8Qo0ZWU2VrI3d5JeuN4VEh5-PpQHJifCCd1pe7eNyOtN2aAZK8Up6HdDU__1CqtBgxbjqVy2uzZ-YiQJptZ5Zp0KnxHbeOPFJlfStoJdl6Xw0B_AFggRiDMOjIU3A4NCAKFdZjo06nd4XNFHusmgPKZTymRmmA6qhfn-NUgVxxv-KhvwMWOJkG61KNyliSjvNUADEKTauc664rENhA\"}";
        final String CHALLENGE_URL = "/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/537";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/537\"," + System.lineSeparator() +
                "  \"token\": \"6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "rjB3PBI-cOW5kdhoWhhruGwub0UnLVn_0PnlwdHP5aI";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/537";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8";
        final String CHALLENGE_FILE_CONTENTS = "6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8.w2Peh-j-AQnRWPMr_Xjf-IdvQBZYnSj__5h29xxhwkk";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-27T14:27:35-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/535\"," + System.lineSeparator() +
                "      \"token\": \"AYnykYJWn-VsPeMLf6IFIXH1h9el6vmJf4LuX3qitwI\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/536\"," + System.lineSeparator() +
                "      \"token\": \"yLCOHl4TTraVOukhyFglf2u6bV7yhc3bQULkUJ1KWKI\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s/537\"," + System.lineSeparator() +
                "      \"token\": \"6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://inlneseppwkfwew.com.com:5002/.well-known/acme-challenge/6X7dIybvt_0JwQ8qUSJQqs83vS40mac5o0rhi8-_xl8\"," + System.lineSeparator() +
                "          \"hostname\": \"finlneseppwkfwew.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"127.0.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"127.0.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzk4Iiwibm9uY2UiOiJyakIzUEJJLWNPVzVrZGhvV2hocnVHd3ViMFVuTFZuXzBQbmx3ZEhQNWFJIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvZmluYWxpemUvMzk4LzE4NiJ9\",\"payload\":\"eyJjc3IiOiJNSUlFc3pDQ0Fwc0NBUUF3SGpFY01Cb0dBMVVFQXd3VGFXNXNibVZ6WlhCd2QydG1kMlYzTG1OdmJUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU1pSHBocGhaMTNRaG5zM0E5ZDVaSUx5MEpoNkNrZDhCNU1uTEJxbVl6UEwzWWR2VXFSSHdiZTBNWDVUQWRYdmR1eDZzNHBNbUg1a21xMUc2STFXU3pzcFBSN1g2TWZ6SGl5dEhPNlc1c0NidlpwVFRBYmw4NGMtZE5UckctdjJaMDA2dHRKWXp2NV9oYzI4UV82TnpZdkM1TWQ0T0QxelZXWnE5eU9KYjF0aHl4RUdwc0lIRVh4LUV4M3lWM2tpbmNfYnBvN2RUQjBndldIeDdiaHhLTUdmM1ktSm9mVUd0WHBWcTY1dDBfdnBQVHRIelBDbWppaG93WXc4S3RwVm5xcTdYVVMyUFFHU3UtcGNFYzBma0huSnNJUmdoRTRPR3E5THR5SkI3Zi1YLWdhRi14NzBDVEdoZ25JMFhaMlNBakYwTVdsVll2Mk9XNUQxOUM2YU1GeS12VlFqUU5VcjFUZGpvZVd3eEJEV0ZvNkwxTVZCcE5lUWVCZXJWT3lVelREZk1XLXBDSXJJUnMxV3lYVmV2WmJMc0pQTUZxRV9RNmV4bWdvU2NNVWUzN3gxenVCMV95VURZZkF4dVZVaVJfT3FUeHRfUUd1ZU8xVTJmQXpfRy0tN3VmbFhSQWw0OXZQM0hGc0ZlZHFKTXdNb2pvTDBSMWFvdEZBNGRSZ1dMc1l0Z3hqM1MtRVZYZWZScjJrTFFuTU1vbngwTjdOMTFuV09seGNSSDhOeld2NGMwYWh0TEliaUtmN2x2YTNMMklPN21RQlVjSHFkbm9pNndpbXJKTTZrQndIU0RyRDVXcVpTenQ0aFZTMmxtOTNEUDVGX2VuVEpDVnl4OUJVVUhoeDljeUxweEtyZ3BLcnk2OVp4MUdnbUUtTTNvVDNYMU4tdy1rMGViNVZSQWdNQkFBR2dVREJPQmdrcWhraUc5dzBCQ1E0eFFUQV9NQjRHQTFVZEVRUVhNQldDRTJsdWJHNWxjMlZ3Y0hkclpuZGxkeTVqYjIwd0hRWURWUjBPQkJZRUZOVmR6WV9nNTQxem80d0VIZUtJZjl5Mml5a1dNQTBHQ1NxR1NJYjNEUUVCREFVQUE0SUNBUUE3VTFYRll0RUM2QmxZY1BpUXhyQmg3eVoyNmM3cGw0U05IMFd4R2tQS1MwbVdDUlUzdm5zb05xblJjZXlxR2oyQmN4WnVUSms0U0IyOTJPc015Qm1sc0l3VWNYMHlodmpYT3RQLTRVUlBaS0o0WUdldmxlMW1xaGttZWpMT2R1bXEtNXFmajd5QXJsXzlETlUwam5UMDY1cHd6UkxCcS1VcXNtQXgxQ3czLW40LWE5VlIyemltNVFUUjZ1ZTF2NUJsTmxBTmI5eGZac3VHVXJ3akhsQ0NQU3FUWERKWnZNdGs4Y05SNUJtY21lZXFiZE9Yc1ZLSktaYTBhaW9ZcG9tT1pmREExQTZpT3RuNzRKc2tWNHBraEVmZUc1a0FEUnBJbmtkWkNIMlB6V1JvSWJRSmViNXY5RzU4aENyS182LWVaV1FjQW5sMkxTcDl5T0JkT2FPOGF4OGRwQUZYQVNyOVdKTFNWcHRuaDVKNnlaWER0eXFiYnctRXVpbjZTektmdTRYWlhUaHNnSmVfeWlncmNpZjRIQnNGc0wwWGFaTXUyY3U3cV9jaHM4bkJpOG5VM0F4RmZoVFZIeURjYkxLa1Z2Qm05WUZFUlFrWEl1WDZid1U0clhWLVFtcUpGNzJWV2ItZ0R0d040UnotWlFzaDZxS01HNTI3Mi15NWZaTjZMQkpTZTJ5WWpBbHhiM2xzZ0hNbFRKYzlPMkhnUE9udkREWmhCYUdPc1EtbTdha3ZJcWc2ZFVuYTB5c2t3MmI5WVd3TDRoMzdPT2JHZVJ1T2t4QTY5Z1N0bmZ1aFIxbGItQVRrMmZYaHFQRlAteGxIT2JtNUh2ekZKVE5ZRU5Rc3VnaFRIY3hoNERUM0F1dVo3aWZtVjQtNHVWTGdKVkdsVHdFcXJTS29PQSJ9\",\"signature\":\"NNtlMV9rfVtUvxgK9ucvWfXxwynELu5KeB-CGYrrM2VavfAeHWYDCr5Hs8Y3_UyOXSwXANUcVR4VjJnfoxsVn4TM-Zd0T6osmorVTIZGaI-xsWyxBckZ5g6xb7AGE6VLYKvCR4if_DhYq9M31Ge7l95rUTgxPg6xQbibGkbUfT1K-CcNetPWfCtQOhEf4V4jIO78MZUKuyb7eQXdWJqP5-ed4UAuqoclKqJ259zxrs1QcqbJGVjV5OJOpL-4odc086dkHvKPEkKIG3s-vFeYcToAVerR1rmIXPFenDu_JN9qqYtuyMrpfT_AhSavyN-DMaFKGvZ6YISQ5A4gq4ESJQ\"}";
        final String FINALIZE_URL = "/acme/finalize/398/186";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T18:27:35Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/398/186\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ffba1352e17b57c2032136e6729b0c2ebac9\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "CZleS8d9p38tiIdjbzLa1PRJIEFcbLevx_jtlZQzYbo";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/398/186";

        final String CHECK_ORDER_URL = "/acme/order/398/186";

        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T18:27:35Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/398/186\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ffba1352e17b57c2032136e6729b0c2ebac9\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ffba1352e17b57c2032136e6729b0c2ebac9";

        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIGZjCCBU6gAwIBAgITAP+6E1Lhe1fCAyE25nKbDC66yTANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODA0MjcxNzI3" + System.lineSeparator() +
                "MzlaFw0xODA3MjYxNzI3MzlaMB4xHDAaBgNVBAMTE2lubG5lc2VwcHdrZndldy5j" + System.lineSeparator() +
                "b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIh6YaYWdd0IZ7NwPX" + System.lineSeparator() +
                "eWSC8tCYegpHfAeTJywapmMzy92Hb1KkR8G3tDF+UwHV73bserOKTJh+ZJqtRuiN" + System.lineSeparator() +
                "Vks7KT0e1+jH8x4srRzulubAm72aU0wG5fOHPnTU6xvr9mdNOrbSWM7+f4XNvEP+" + System.lineSeparator() +
                "jc2LwuTHeDg9c1VmavcjiW9bYcsRBqbCBxF8fhMd8ld5Ip3P26aO3UwdIL1h8e24" + System.lineSeparator() +
                "cSjBn92PiaH1BrV6VauubdP76T07R8zwpo4oaMGMPCraVZ6qu11Etj0BkrvqXBHN" + System.lineSeparator() +
                "H5B5ybCEYIRODhqvS7ciQe3/l/oGhfse9AkxoYJyNF2dkgIxdDFpVWL9jluQ9fQu" + System.lineSeparator() +
                "mjBcvr1UI0DVK9U3Y6HlsMQQ1haOi9TFQaTXkHgXq1TslM0w3zFvqQiKyEbNVsl1" + System.lineSeparator() +
                "Xr2Wy7CTzBahP0OnsZoKEnDFHt+8dc7gdf8lA2HwMblVIkfzqk8bf0BrnjtVNnwM" + System.lineSeparator() +
                "/xvvu7n5V0QJePbz9xxbBXnaiTMDKI6C9EdWqLRQOHUYFi7GLYMY90vhFV3n0a9p" + System.lineSeparator() +
                "C0JzDKJ8dDezddZ1jpcXER/Dc1r+HNGobSyG4in+5b2ty9iDu5kAVHB6nZ6IusIp" + System.lineSeparator() +
                "qyTOpAcB0g6w+VqmUs7eIVUtpZvdwz+Rf3p0yQlcsfQVFB4cfXMi6cSq4KSq8uvW" + System.lineSeparator() +
                "cdRoJhPjN6E919TfsPpNHm+VUQIDAQABo4ICmjCCApYwDgYDVR0PAQH/BAQDAgWg" + System.lineSeparator() +
                "MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G" + System.lineSeparator() +
                "A1UdDgQWBBTVXc2P4OeNc6OMBB3iiH/ctospFjAfBgNVHSMEGDAWgBT7eE8S+WAV" + System.lineSeparator() +
                "gyyfF380GbMuNupBiTBkBggrBgEFBQcBAQRYMFYwIgYIKwYBBQUHMAGGFmh0dHA6" + System.lineSeparator() +
                "Ly8xMjcuMC4wLjE6NDAwMi8wMAYIKwYBBQUHMAKGJGh0dHA6Ly9ib3VsZGVyOjQ0" + System.lineSeparator() +
                "MzAvYWNtZS9pc3N1ZXItY2VydDAeBgNVHREEFzAVghNpbmxuZXNlcHB3a2Z3ZXcu" + System.lineSeparator() +
                "Y29tMCcGA1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly9leGFtcGxlLmNvbS9jcmwwYQYD" + System.lineSeparator() +
                "VR0gBFowWDAIBgZngQwBAgEwTAYDKgMEMEUwIgYIKwYBBQUHAgEWFmh0dHA6Ly9l" + System.lineSeparator() +
                "eGFtcGxlLmNvbS9jcHMwHwYIKwYBBQUHAgIwEwwRRG8gV2hhdCBUaG91IFdpbHQw" + System.lineSeparator() +
                "ggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgDdmTT8peckgMlWaH2BNJkISbJJ97Vp" + System.lineSeparator() +
                "2Me8qz9cwfNuZAAAAWMIXFWgAAAEAwBHMEUCIAXRs9kJpmcgC2u5ErVOqK1OMUkx" + System.lineSeparator() +
                "xgnft0tykRpsUCRJAiEAzSVDO8nVa1MuAT4ak5G8gLy416yx/A2otdf9m7PejScA" + System.lineSeparator() +
                "dQAW6GnB0ZXq18P4lxrj8HYB94zhtp0xqFIYtoN/MagVCAAAAWMIXFWhAAAEAwBG" + System.lineSeparator() +
                "MEQCIF9IqHmvenOE4Oezwe4WdtRyEFoPbSdlXsO4owIuhaTFAiB2V77wpchHm1Gd" + System.lineSeparator() +
                "J4IyR23E6h+w69l3hT7GJAViHM8SoDANBgkqhkiG9w0BAQsFAAOCAQEACQvKKtNy" + System.lineSeparator() +
                "o0vlQq06Qmm8RRZUZCeWbaYUcMDxQhWgHaG89rG2JKhk/l1/raxPBj+q/StoFtwM" + System.lineSeparator() +
                "fOobIYqthjn0tMO+boRyI63CWTS5iQAAOxN/iV1noCejGYWyeRY3O1hqKn5xzflV" + System.lineSeparator() +
                "GAMCjvIVo3IBn4BjIBfcx+wj7giADWSaZI6jef7lPvFG1zekOtois4/SK1U9DUQB" + System.lineSeparator() +
                "pMdRMQKbH8BOC5WzpOAxJqg9M3BUAg+uqknX9c9A/OBm+Aw56aNrHUq9bX1svWht" + System.lineSeparator() +
                "RUBIKAHFtzW+W3R/KUddkuwYDDrTiZRWPNO4MjC8edLBLZV80XJzVoEmwocIcBjG" + System.lineSeparator() +
                "53PzUdxmaWsaTQ==" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_RESPONSE_BODY)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_RESPONSE_BODY, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_RESPONSE_BODY, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestObtainCertificateWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"Xdaqm0jAr6Q\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "hldsFdBl6pMyMC3UFFJ_dlWNKwxBhis7PI0Cnz2Wwa8";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpVk5xSnVoM3VvWW5xdkNfZGtYQzRFMDN4R292eTdLUjAwd3M4QUwwcHJWcktzajhnZFdhWjBLZkZ1Q0NUaUtMU1BhNVQ0ZnRWNFdia2l0djFMa0JWU29Wd1hqSDE0bFpIMWFHYkptR1lCX3pSOV9uVzZJTzRVb1RGc2Vqb3paN05kNW8waVFpQWpyRjBmMDhGVC1xYS1TVVZiVk16dkNnQW16SjJFVlhzOXdOQ2pzSVRnNGh3eDdZRzl5eHRhZjFoT0hkV1dKVWtwZ0hnQkVfclpZT1B5YVNlb2JyeE5mMllxVmhFNWM2ZjhrZUhYdnU2dnprODctZVNLWXlndk9hSW1YOUhFbFZhQXRVcnI0S3hFV3VvUDdNRzZCV0s2TDVpam9Db0VMQjBqM0w2UHNuXzM1VnMxQi05OFR6SFZqYU1sU1NGV20xQjdtS0NzNGZMeE1pRXcifSwibm9uY2UiOiJobGRzRmRCbDZwTXlNQzNVRkZKX2RsV05Ld3hCaGlzN1BJMENuejJXd2E4IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"XoLNas_L_G-pqRW0uHL8ikJ5d4jXipN7aKioq527X5vzwLD2cPIiFQL0sHcMs0MCPWV6fjIG-edArCcpOjPFqkqoR9K2BqKqlqXHUHnrJ0ipNAMOG1CtktXGmApIu6D6R5pRAOVTrraqMvUoXNh8_hEthcVZOclUDIRWZDWt-3q1Db1UvuFFQNDC0M6c5deqUdQ9CwnA1XckGQuvDqlmbjDFoWAo-kPF0A3Kq1z7x28vuZrMFw0qPh4rzJTuu4WY9easTo_5m6mD8cpdx-74cqmzdOV5ZNaBS4jvv5dWPWNogNPRUQkRPIbv9A3FLcoZi8ZgbQ8sPGwhb2ol-2xobQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "0s56tTjhgzilhZhjcSuTZNHX_dyWLnZK3fTzRZ9fBjg";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/401";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDAxIiwibm9uY2UiOiIwczU2dFRqaGd6aWxoWmhqY1N1VFpOSFhfZHlXTG5aSzNmVHpSWjlmQmpnIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoicWJxeHlsZ3lqbWd5d3RrLmNvbSJ9XX0\",\"signature\":\"gAt4IcsxvmkLDKLF7euaiycFgsP2CCdnUueSlsg2xveJbinGytlKwN98BpGhoKBJLxh0m-sU6CrXuEtIRqJu_RXOQPUMkSuOsC-VSVBbWnxxysMm-JeBbVohQVpC8wIh6U3UUyMVEQU_99Vmk0vBmhJVltjr9g_XqdGo3wVl1-ReFRnFeE2LMMQQj1XzaNXLaZOsfVBPsNWMPUpc-VTFl30d6iGpyo_HrI3icze5D7iLj48ETui5wVmmiX2BHlIeMvhnYYoh5OY2LEQ6MG5-duJvf-2-bGz7ZWl4p_viEWmO36gzsB7_5f2qjJyKKIb8WrsYNbCMivipu4aGCFbeiA\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T20:10:36.21542246Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"qbqxylgyjmgywtk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/401/190\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "c4714cbBAMIc2nda2_LSdHRrYJGjDU58RydXW2cAuTE";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/401/190";

        final String AUTHZ_URL = "/acme/authz/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"qbqxylgyjmgywtk.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T16:10:36-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/544\"," + System.lineSeparator() +
                "      \"token\": \"Rk2XeCkkC5SjqzK3dxzhuxQW3LQ2tyHsxm8cGSD8PX0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/545\"," + System.lineSeparator() +
                "      \"token\": \"hH4lU_5CeB6i3GtHnhASoqjgVBMo6lnTcZOVqXAQsco\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/546\"," + System.lineSeparator() +
                "      \"token\": \"8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDAxIiwibm9uY2UiOiJjNDcxNGNiQkFNSWMybmRhMl9MU2RIUnJZSkdqRFU1OFJ5ZFhXMmNBdVRFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL1p1MFpxUXFoNmdrWnNwSFhJYzFoQmp2LV9EVG40elcxVlZLYzRRVVdWbTQvNTQ2In0\",\"payload\":\"e30\",\"signature\":\"OFNrhBeZNd6hEMyzs6f7TENycjvsjR2FQ4L4A2ab__dBGkqUtGoL6MwKYauT30aGkzDJKrlcw99MIUhc6LniLwUijvXCi56qcMvHnCLwQAI859PbQUnh-5KV6nVYOgsaf_JUf-O0kyzfNieAxVuib6RFN1iF6fGWmrjKZqbANWATTPGboC49LrGxDYdjIu8hmKMpvcv5w4dpaTqwIFrCAscr7wey9uQWh-9y6ljaVObTLTeZkLxZ1nEGcfutpDKAyUXyGrBqMTJWsepIzicnGpDcBzW8AV3uufIHjzzf4h67Jn7lbtRHNNAP-jw2YPUILa1SYTT6gwZuHMwg_1Z7rw\"}";
        final String CHALLENGE_URL = "/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/546";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/546\"," + System.lineSeparator() +
                "  \"token\": \"8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "kx6a_hma4yYVZDd4jyCEau7XBGFZfoQ_JlxoSf4NUCI";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/546";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4";
        final String CHALLENGE_FILE_CONTENTS = "8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4.952Xm_XyluK_IpyAn6NKkgOGuXbeWn8qoo0Bs9I8mFg";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"qbqxylgyjmgywtk.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-27T16:10:36-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/544\"," + System.lineSeparator() +
                "      \"token\": \"Rk2XeCkkC5SjqzK3dxzhuxQW3LQ2tyHsxm8cGSD8PX0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/545\"," + System.lineSeparator() +
                "      \"token\": \"hH4lU_5CeB6i3GtHnhASoqjgVBMo6lnTcZOVqXAQsco\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4/546\"," + System.lineSeparator() +
                "      \"token\": \"8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://qbqxylgyjmgywtk.com:5002/.well-known/acme-challenge/8AEqb3RMaBtCpfUqsvi9r8nJ5Gt1pt0xN8B3ucfiih4\"," + System.lineSeparator() +
                "          \"hostname\": \"qbqxylgyjmgywtk.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"127.0.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"127.0.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/401/190";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T20:10:36Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"qbqxylgyjmgywtk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/401/190\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff7d5abb5ad7b36b2919d7d0c43ebe901488\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "YJepHZtqau_kGJ78rrlLih4kzpqO2NLyULRJt1X8H8g";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/401/190";

        final String CHECK_ORDER_URL = "/acme/order/401/190";

        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-04T20:10:36.21542246Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"qbqxylgyjmgywtk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/Zu0ZqQqh6gkZspHXIc1hBjv-_DTn4zW1VVKc4QUWVm4\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/401/190\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff7d5abb5ad7b36b2919d7d0c43ebe901488\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff7d5abb5ad7b36b2919d7d0c43ebe901488";

        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIEnjCCA4agAwIBAgITAP99Wrta17NrKRnX0MQ+vpAUiDANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODA0MjcxOTEw" + System.lineSeparator() +
                "MzZaFw0xODA3MjYxOTEwMzZaMB4xHDAaBgNVBAMTE3FicXh5bGd5am1neXd0ay5j" + System.lineSeparator() +
                "b20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQdAeum8KpMfZq5PmYKpI2GQaxg" + System.lineSeparator() +
                "3E0cMIFEkr5MKhc0g31Ja+pU2hS4afOZMZauXyDoXhwZmibdThzcI2gWviXio4IC" + System.lineSeparator() +
                "nTCCApkwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF" + System.lineSeparator() +
                "BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS/CJzFa4XYCtYqaG0A008skSnR" + System.lineSeparator() +
                "5TAfBgNVHSMEGDAWgBT7eE8S+WAVgyyfF380GbMuNupBiTBmBggrBgEFBQcBAQRa" + System.lineSeparator() +
                "MFgwIgYIKwYBBQUHMAGGFmh0dHA6Ly8xMjcuMC4wLjE6NDAwMi8wMgYIKwYBBQUH" + System.lineSeparator() +
                "MAKGJmh0dHA6Ly8xMjcuMC4wLjE6NDAwMC9hY21lL2lzc3Vlci1jZXJ0MB4GA1Ud" + System.lineSeparator() +
                "EQQXMBWCE3FicXh5bGd5am1neXd0ay5jb20wJwYDVR0fBCAwHjAcoBqgGIYWaHR0" + System.lineSeparator() +
                "cDovL2V4YW1wbGUuY29tL2NybDBhBgNVHSAEWjBYMAgGBmeBDAECATBMBgMqAwQw" + System.lineSeparator() +
                "RTAiBggrBgEFBQcCARYWaHR0cDovL2V4YW1wbGUuY29tL2NwczAfBggrBgEFBQcC" + System.lineSeparator() +
                "AjATDBFEbyBXaGF0IFRob3UgV2lsdDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB1" + System.lineSeparator() +
                "ABboacHRlerXw/iXGuPwdgH3jOG2nTGoUhi2g38xqBUIAAABYwi6mMIAAAQDAEYw" + System.lineSeparator() +
                "RAIgQq7meXdYdkJLa2Bi5uV5cA2cnGY1rulVuBpqrDcPd5MCIFBo8W015liL6UIB" + System.lineSeparator() +
                "Y8z263MEA+JCcPd7twbHBUd3k4raAHcA3Zk0/KXnJIDJVmh9gTSZCEmySfe1adjH" + System.lineSeparator() +
                "vKs/XMHzbmQAAAFjCLqYwwAABAMASDBGAiEAkzofAX5ZsYqSbFHVKIiehZCAMsFs" + System.lineSeparator() +
                "QZC7bO+0O37VEwgCIQCDZfOfjbNRttx9pp9ksw3KtrqTj5OF6DvH59Tr6Fey5TAN" + System.lineSeparator() +
                "BgkqhkiG9w0BAQsFAAOCAQEADqXOHLreDEJ1xj7vA9H6WtG/cp3dOeTVQs7jAOd5" + System.lineSeparator() +
                "3Ffz9biwTi6quCiMzRbH+vbWExVYLuIIA7Wxa74+tHk1zFXxjB7ld2JaJzPHQGch" + System.lineSeparator() +
                "owCMPtLmOOLtZ3tPHPC18PAYPbBc3MN2L7QYHsLkMJe7ucDLAzSbConqyWhUNrx0" + System.lineSeparator() +
                "bMJR8AY2MbQLOb04f75gEpZEcnipzDX4uihH3qhliLanXgNMhZ0zRdaWCPNRUQes" + System.lineSeparator() +
                "ut19jxS5dZArysqq7Zok+kaRL5MxXVsLmtL/x1dmekgIsUJ9wgxzbGulb+uww/Qa" + System.lineSeparator() +
                "2lhjwCXdqSW3tXr4iWkUrUiVvwyQEipswNCuYeHDEbG0tQ==" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_RESPONSE_BODY)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_RESPONSE_BODY, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_RESPONSE_BODY, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestObtainCertificateWithUnsupportedPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"faxV5ndBJsE\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "iOCbfIfMBnuI1J4OUoMjXfo1WGSjQHF0shRxEDsRV1E";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpVk5xSnVoM3VvWW5xdkNfZGtYQzRFMDN4R292eTdLUjAwd3M4QUwwcHJWcktzajhnZFdhWjBLZkZ1Q0NUaUtMU1BhNVQ0ZnRWNFdia2l0djFMa0JWU29Wd1hqSDE0bFpIMWFHYkptR1lCX3pSOV9uVzZJTzRVb1RGc2Vqb3paN05kNW8waVFpQWpyRjBmMDhGVC1xYS1TVVZiVk16dkNnQW16SjJFVlhzOXdOQ2pzSVRnNGh3eDdZRzl5eHRhZjFoT0hkV1dKVWtwZ0hnQkVfclpZT1B5YVNlb2JyeE5mMllxVmhFNWM2ZjhrZUhYdnU2dnprODctZVNLWXlndk9hSW1YOUhFbFZhQXRVcnI0S3hFV3VvUDdNRzZCV0s2TDVpam9Db0VMQjBqM0w2UHNuXzM1VnMxQi05OFR6SFZqYU1sU1NGV20xQjdtS0NzNGZMeE1pRXcifSwibm9uY2UiOiJpT0NiZklmTUJudUkxSjRPVW9NalhmbzFXR1NqUUhGMHNoUnhFRHNSVjFFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"Hbt_PPCv4xua3SjHSqKbBluGkIbzUJW7-qF-KXGuAoovV5Vb1PelCoPADHy2q3iYLnIjLp0FOLw2xWpQ-CYae1F6O64IfOIrnT4PLw5fw_hN4R4CjyWRuK7519mNroPb5h5l4ZEp1PB6H9ID7GMX3fh2_P3bov0yr9Q2XVkau1I72pHGXmcEiioOBeYZvcYdudYP9vu1DfnQGbDva2_ytdONyPBnJtkJu3RMueJ8UyYRluMwwOoZcN0RNLh6jyFilhYC-A-1Jopvfmo_c9SZaNIEFawkWRRdoxSOcfQiYf3jSUH5tjbTqgOWUK8gYFlH7c1n-g6dJdQGBH0nXImHnw\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "Rvyjsq8CE1kTtdrt-HrToIvAJdPMr1TnxtFEnaHsGU0";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/401";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDAxIiwibm9uY2UiOiJSdnlqc3E4Q0Uxa1R0ZHJ0LUhyVG9JdkFKZFBNcjFUbnh0RkVuYUhzR1UwIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaXJhY2x6bGNxZ2F5bXJjLmNvbSJ9XX0\",\"signature\":\"d0CZTIK3hBJ9YOCWU0Hv1CnZp2TU_pCoxfJEOurZNRZj6B_kXbc4of-t33Dx_eeM1JRPMXJ0AcOWaF9DrIyFWm4iFXGe9AB3aZMO0t3bSQ23DFWhX4s8k7UkxQfLVJ7Mga63sHQG5gRuQzJPsnX_bqWGyDzBlYzMBEVG8P2-TgNDHGVGG_MDnAcXjZjyakZH8888i-fnTcdaPuiaLfYYiaGEYkX22j_TSbdQewwrVCD6Nferxn84SyvV3WkM3ZNjwQ9Pa8495mwAhsu2-pQxGzSnFZcJCivzJP4VSjr5Ur4ZHbGV2kR4isuX6IWk5KRntX2Ltx1-VSRMnkCe4DAUJg\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-07T14:29:36.239815881Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/401/201\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "dfsGDv2NEk2p3bwCSzjPWuVicILXJ7gW1cWLQBImpYw";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/401/201";

        final String AUTHZ_URL = "/acme/authz/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-07T10:29:36-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/577\"," + System.lineSeparator() +
                "      \"token\": \"drmkP7AAB0Uv3LC-wS8GcQchsYIvCp560duP_hej9iw\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/578\"," + System.lineSeparator() +
                "      \"token\": \"P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/579\"," + System.lineSeparator() +
                "      \"token\": \"YMPTs8LpgdDA883WALOI_kyXoOS54wUzS82yUKqnQ70\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDAxIiwibm9uY2UiOiJkZnNHRHYyTkVrMnAzYndDU3pqUFd1VmljSUxYSjdnVzFjV0xRQkltcFl3IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL2k4WnJQWmprX1ktcDE3bzJfZEt1OTlaNWRTQmlmVEZwLUVzQ3pSd2pjRmMvNTc4In0\",\"payload\":\"e30\",\"signature\":\"CigVBit8h-3juGM_z_LycpRPIFXhuX0TvCpVi2Ef-Ka__fvCur_r-JgzmIoxM8UksCmV3QcaT8anBT05GYnuKHkocRMv7a0swSG5HWzpi39YHM39z2k5ayXHRNcow5gvBMBosaXMRk_jZ77xArOiOykycnG7wbRLTD3GOHkUUqLxBDX4YQQscQ-Jid_kgVZEyeuf2XejlaChCDCGqL2Z3cBTBZFYIX0o4oiEA6TsGqvTyJBhyMexdM5_OlKw5u_F3d6q-c93V1opw-9vyjCP7-4wPSkkBT5uSZQzeVdXfZ-QGK2oD74Ju_QMasdfW-12340k7ePRFhsC21ipU-pXig\"}";
        final String CHALLENGE_URL = "/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/578";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/578\"," + System.lineSeparator() +
                "  \"token\": \"P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "jWFqKg3AkFN0Fg9cP5pwIrCU8gn0JruLHOQ0XftVNQU";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/578";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI";
        final String CHALLENGE_FILE_CONTENTS = "P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI.952Xm_XyluK_IpyAn6NKkgOGuXbeWn8qoo0Bs9I8mFg";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-05-30T10:29:36-04:00\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/577\"," + System.lineSeparator() +
                "      \"token\": \"drmkP7AAB0Uv3LC-wS8GcQchsYIvCp560duP_hej9iw\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/578\"," + System.lineSeparator() +
                "      \"token\": \"P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://iraclzlcqgaymrc.com:5002/.well-known/acme-challenge/P34a6nt-4Ko2apwGYFOUK-DXS_BiTcg9hAyVxtg5BCI\"," + System.lineSeparator() +
                "          \"hostname\": \"iraclzlcqgaymrc.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"127.0.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"127.0.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/i8ZrPZjk_Y-p17o2_dKu99Z5dSBifTFp-EsCzRwjcFc/579\"," + System.lineSeparator() +
                "      \"token\": \"YMPTs8LpgdDA883WALOI_kyXoOS54wUzS82yUKqnQ70\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/401/201";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"Error finalizing order :: invalid public key in CSR: unknown key type *dsa.PublicKey\"," + System.lineSeparator() +
                "  \"status\": 400" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "YpsZ4fckMfRjeRAFcJLoNecfDVXyYhxVLAfydrR1xEw";
        final String FINALIZE_LOCATION = "";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_RESPONSE_BODY)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 400, true)
                .build();
        return server;
    }

    private ClientAndServer setupTestRevokeCertificate() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"," + System.lineSeparator() +
                "  \"yNEulSQUUIA\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "9_EfNyD56W72QkvGAqF84DoLVSVayjjPH-CtMarbVaI";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiI5X0VmTnlENTZXNzJRa3ZHQXFGODREb0xWU1ZheWpqUEgtQ3RNYXJiVmFJIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"pa1g7ZBPGet7I11kEu942eKdyWsCpj2Ri1pAGjuLfmET9h0qwFS7h1jIurE-1Whz77LrKW8Mqz6lNM6hLy81Qnr56oLVwcsDCYhRgPnpmznBKzWlXtBKw-QXqho3h2K9uvXjG5mAImdntPb9uaG97rb2hUsOTES8C7JfaxeZXkEVx-1JgHJs3jWQ55-gBpqlpo0pWGdEnTEqmy5pyYhCG4ydH15jQe7uB977nPdrtlsRHc5_TrT9OVmfHRvJA9mvdHkf8mU9C1eSGTdLsNJXHyaVbrv_DdOJeRTLNJuTgHfzQDteSzNcSGBVI-JHa0Fs407BKcHK45_4RkolvWMxDA\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "n13g7hLxpXHWocmPsq_Qx-i5nvJF1OzSqPQ7naadMZw";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJuMTNnN2hMeHBYSFdvY21Qc3FfUXgtaTVudkpGMU96U3FQUTduYWFkTVp3IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvcmV2b2tlLWNlcnQifQ\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZaekNDQkUtZ0F3SUJBZ0lUQVAtWWVJSDJiVjRkWDZhMXVOb3JxNk5PWVRBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T0RBME16QXhPREEyTkRCYUZ3MHhPREEzTWpreE9EQTJOREJhTUI0eEhEQWFCZ05WQkFNVEUydHNhV3Q2Wld0dGJHcDFkM2hyYlM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDWlhuRVBXRXlYRDl0RUpyejB5T3hpNTRuNWR0RTBsOEJzRkt2OGk0bXJmdlMtYXhiaF9OUzdMb3Y0anN5Zy0tLVN6am9xQ3pJbkY4OExQVWxGanFPVlVwYkdhWjM1MWlYN1FkN216bXBsdkFSY2RhdnZXVXRrdjRXN2ZQOGF0N3VsODJaanBmc0VrS2pGcXJ1czZkZFNfQkxXeGNxblhoS3NrdUstZ3MzZ2F3SjFuTU93b01VeGJpYm5EamdpQ1JIVm9wRm5WS0NhMUttWG42MkFBTmUySnNSQTZySlJFZFE0TnE4MVRBZFpieGwyTXdjVnFUY1pYX1BBTVB5RlBCM1EtS0o0VlhPR3R2SVNTb2J1cThUaHFvWXJzeGJ6dXcwMnZYdnd4RzZPaUs3UlFobm9wOHNpdWNIZ0RsaUVlQ25BYWNkZFdRalBieTh0ajBEZzlOTTNBZ01CQUFHamdnS2JNSUlDbHpBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01Bd0dBMVVkRXdFQl93UUNNQUF3SFFZRFZSME9CQllFRk5xM0VGWmk3dDhYT1Z0aUw4YjBjRGJ3a2szWU1COEdBMVVkSXdRWU1CYUFGUHQ0VHhMNVlCV0RMSjhYZnpRWnN5NDI2a0dKTUdRR0NDc0dBUVVGQndFQkJGZ3dWakFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRvME1EQXlMekF3QmdnckJnRUZCUWN3QW9Za2FIUjBjRG92TDJKdmRXeGtaWEk2TkRRek1DOWhZMjFsTDJsemMzVmxjaTFqWlhKME1CNEdBMVVkRVFRWE1CV0NFMnRzYVd0NlpXdHRiR3AxZDNocmJTNWpiMjB3SndZRFZSMGZCQ0F3SGpBY29CcWdHSVlXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOeWJEQmhCZ05WSFNBRVdqQllNQWdHQm1lQkRBRUNBVEJNQmdNcUF3UXdSVEFpQmdnckJnRUZCUWNDQVJZV2FIUjBjRG92TDJWNFlXMXdiR1V1WTI5dEwyTndjekFmQmdnckJnRUZCUWNDQWpBVERCRkVieUJYYUdGMElGUm9iM1VnVjJsc2REQ0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCM0FCYm9hY0hSbGVyWHdfaVhHdVB3ZGdIM2pPRzJuVEdvVWhpMmczOHhxQlVJQUFBQll4ZnpJLVVBQUFRREFFZ3dSZ0loQUlIMEtzUEJjdTBWSUZuSWswdHc0QVZwbW9vMl9jT2ZyRzdDLXN6OGZNMFRBaUVBa3NKbXF4cXlUWGFXZDc5dVNKQlNBTWJWNGpmdHVqbktCY2RhT1JCWFZMWUFkUURkbVRUOHBlY2tnTWxXYUgyQk5Ka0lTYkpKOTdWcDJNZThxejljd2ZOdVpBQUFBV01YOHlQbEFBQUVBd0JHTUVRQ0lGS2paSFc1YkhTZnF1ZXo4TXlWXzhsRVU4TzExQWczVWVyMEFraVVfT255QWlBSkQ2a3FsbVhfVnhOTi1MZ3o1TEJFalFvc2hReURfMFhOOXdDM2FMMFozREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBWndQMGMyTjdReTJBV3R2cDRtd25zZ2pWMmMyY3IzMFJCTTRNNkZCblM5QlEwSU13LWRMT3BhcVAxNEM0N1BYa2M4ZmVyRmZZTFVsWW9NWkFIMHlscUFUemFxd3dnZ0V4ZmF3UlhKM2s4Z1BZWHFuSXdtdDFMNkpNZ0RuZjd6MlJxci1sTlZJNUg4REFpbnFDSjJLRmdtVHh2U1JudHdkYkh2X1J6TUFJRWhTOVp2SnpQOHRRWHBjclRHeWxha0VqWndnV1lOQWs4WTdRcnhfMWhoM0E2YWpXWWNhb1FUTzJVOS1pMThaNnB2TzFwRlZSZEo0ZUozamJrVzR0UUNJVDkxeGtsWFlfT1gyZF9qc0Z3TzFBaTNEV19Eb1ViMGtPUmFaMkswZjZJZF9BczREOU5USDVXSDdEX2FrMm42T2l2V2dpTHBqZ0pxRUgzNWtPN0hWdGNnIn0\",\"signature\":\"U6822aPK85QdIwsJH6ekvg-LkmvjBlLmJmk8OViNYr79GNTbu3LBO-x9p2_R3deKotShjYE3WpcmzqcW9xpHg-FRSWgcIFczS_0EAX9d-OhI4LFzQroHyTXcEev0OruiMq_4tZrGjy1CFFfdaaXyRbpDqnP4vC_Tq2KyUHhV6LbhHhg11qaQjov3z-0jMM6eKGybmne6yDrE2lG6uKZscWzYqwGi5gkQ_iBHCb_qzYYphYs8IZLPTt6T8PAIDmRpsRCHXzgDCk0QVhj-Gl7y2H2xEn_BknKT-oPa33zSICovn5cR6utf788FRz9oh8t7tIpOAvVStwVSrb6BV6WOUQ\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "poBc-xx1Oxnprg_hgWFZI_0Ji-4qgEpAnGrAdxEP6sU";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestRevokeCertificateWithReason() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"FpVd7yM-nVU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "wSrof9-zav_U5arHV7tJPiMZsBkUM1oCTLSWsKXPC5Y";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiJ3U3JvZjktemF2X1U1YXJIVjd0SlBpTVpzQmtVTTFvQ1RMU1dzS1hQQzVZIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"lNHB8zNMAGmTnnWS1dpRvuJc285uRheAIwhx4eKk5ZA9hxQmp6jPKBk9TdmeUgB-vHRguy7eJq0-bl4MItWRz0gQwqTIWCo7nLktFDDlFCixrZ83BRdGMMNLXoDXL6GxwbHRCtmATLYUtOh8zJ2QLAK6eiy_VUhgH2b-d74VoUyo0OPEvj5-W87UifrpoKeBjfV7h549EY7CbTkq0acsRjZwRWOPhZn43UGhO342nm619igjv3U1MRm8gahE5bG7di8PF21osAACWx77ejenIeBYWmc1AHSQnSsOx7l_1dFyW11uplYwwnmBuDJVgqzzTOP6_ZfB-YDk29VZqoirdA\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "1o12UbHgfvYtgWkPj8OMf1eriXwnDFTRNMoo4ScmDRM";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiIxbzEyVWJIZ2Z2WXRnV2tQajhPTWYxZXJpWHduREZUUk5Nb280U2NtRFJNIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvcmV2b2tlLWNlcnQifQ\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZaekNDQkUtZ0F3SUJBZ0lUQVBfNDBNVEh3LWw1M3lpOWVOMnptclFkX1RBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T0RBME16QXhPRFF4TURoYUZ3MHhPREEzTWpreE9EUXhNRGhhTUI0eEhEQWFCZ05WQkFNVEUyaHRlSFJ1ZFd0c2JHaDRlR3hpYUM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDWUpyX3BaQkNTeV9LZHdLd1c0TDdyNnhWYVB1R0dna1JKY3lnTE5EWUhNd2JObm9zM3FnckpEMk0tRW5HOWlrSmlIRzd5VUtfVHRGNWZrVFA3UEROUzNlallkVTl1RTFHeTM1VTcyVGVzbVpzSC1aNy11NHJsc1JxdzVXcURDUjBGeW1PR0xuUEpVa3hGN29PRlFHc1lwZ3h3T1JVV0g5TlBEUzZTT3RTWF9XbUJ0S015VGM5QW9GRjBlRHM3NlBmOWl5eXZONjh4ejF6Y3g5aENnbDB5ZVNXTFhUNHV1SUJibHIxNXZhdzdCVVFNMnBGdE9aNGFIcWRiTDUtQ05TOWVxNUk2WTRpMW1yQVBEWklkN2xMOHAxY2tQLXI0dlh0a0VVdmxEaXFNMzdiRlB3enZDMWVVeGtOanNTdnQ0OGh4TTBtMU82cHZhTVB2Qm1CWGxHOUZBZ01CQUFHamdnS2JNSUlDbHpBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01Bd0dBMVVkRXdFQl93UUNNQUF3SFFZRFZSME9CQllFRkl3VXBFcGpUbmhUTl9XN3JlckkwT3V2alVMck1COEdBMVVkSXdRWU1CYUFGUHQ0VHhMNVlCV0RMSjhYZnpRWnN5NDI2a0dKTUdRR0NDc0dBUVVGQndFQkJGZ3dWakFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRvME1EQXlMekF3QmdnckJnRUZCUWN3QW9Za2FIUjBjRG92TDJKdmRXeGtaWEk2TkRRek1DOWhZMjFsTDJsemMzVmxjaTFqWlhKME1CNEdBMVVkRVFRWE1CV0NFMmh0ZUhSdWRXdHNiR2g0ZUd4aWFDNWpiMjB3SndZRFZSMGZCQ0F3SGpBY29CcWdHSVlXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOeWJEQmhCZ05WSFNBRVdqQllNQWdHQm1lQkRBRUNBVEJNQmdNcUF3UXdSVEFpQmdnckJnRUZCUWNDQVJZV2FIUjBjRG92TDJWNFlXMXdiR1V1WTI5dEwyTndjekFmQmdnckJnRUZCUWNDQWpBVERCRkVieUJYYUdGMElGUm9iM1VnVjJsc2REQ0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCMUFOMlpOUHlsNXlTQXlWWm9mWUUwbVFoSnNrbjN0V25ZeDd5clAxekI4MjVrQUFBQll4Z1NzYVFBQUFRREFFWXdSQUlnTUFGb19yNFl0aWNfc1lpVmxpaE10ZGZSZDFnclNYSUl1U2pwQzNZT1NOZ0NJRzdMWTlkMGl2cVV2czJ3Y0Z1Q0tNZkFsdDFNWTNvcjR6cGJlelFsNWpvREFIY0FGdWhwd2RHVjZ0ZkQtSmNhNF9CMkFmZU00YmFkTWFoU0dMYURmekdvRlFnQUFBRmpHQkt4cFFBQUJBTUFTREJHQWlFQTRYSmZVd3JVbkxWUGxRbF9IVVFxakRUVkFRdDJIN29BdXNrWUhiT3EtYTRDSVFEcGZwa3pNbkxudlNxay02QU5ZRWRKb0p5Q0M3M1ZwdHo0WG1MVnJMNHNtekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBc1VEMUJ6M2NWQzA4NXF4a2VkYzJqd3FUSEk0UF9OaERrQVFmSGhrQ0VlaFoyVTVmRE1YWXFwZDh0UUluZUdoZU1ZTkQ4OWRFQXYyXzI5SXNGXzhKNC1uSURrLU1XQkFsQm43VUtES2xDbEdza0RDenJPajF6clJwOUtscTNLaElFSkUzT01nTGIyM3pNbERLeWRIcXA5OGtTc25hQmFoS1VlV3l1WXcxdmNwemZ3TjE0UG9xMW1jRnJWUFAxcWRBNG1NMTVFVHgyV0tZdTFWaWIySVVESmx2STNYbUg5SFR5ODZYRTRMNXFTd20xalJFbzZ5a3FDTmhSMHJMeHhHeXhDRldWVXVLNG9SaFR3YmF0VzEzR3JvSlhGdGNQeVVuRGJkSU9iRzIwLV9DME9ZMk9Rc1pWQTNWTC1IQ2c3ckt6QnZOSTNlaVkzVVNMYVBMM1I0dWhnIn0\",\"signature\":\"kx2BxYoqybtb6McNnBUjt2YJwsZzB3je-9uHR4-T4QMEGqpzqhdpSqeB6m_owM9LoKfO5DKU_FZ6u5Q4siKQ-x4BvDibFBRKjB0eHkWc9Jho0yB_2N4yimIf4vka77aiaZFXXUtYnlNzmRcAvjo0_nz8U-wfY8lwqHCfAthYfB6gVcy4skLYE-W9f_5ivCnzibY-Mzgu9cIE7KoU0ODfaLxwEa7IzbrIJDXdrZQoYH9I5HEKxm1r-GFjFIv8BsYqacBJKWUkVQQXKIQw6uxt6mZ-k8GVFJumqPS0eLx2cAlq2yZ33WsvUrQSLXd9yjEtpcUtiX0zqE8jbO_3P23dpQ\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "q4qaFhcWgftkiRaaeEZskz_fp9ue2OJGRDW3mYBGCNk";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestChangeAccountKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"DSKtJkFv-s0\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "0Zn9A9Ist7RRgrEKzkYu8mRbWWlxbjs_vIoHienpsRA";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoNWlULUY4UzZMczJLZlRMNUZpNV9hRzhpdWNZTl9yajJVXy16ck8yckpxczg2WHVHQnY1SDdMZm9vOWxqM3lsaXlxNVQ2ejdkY3RZOW1rZUZXUEIxaEk0Rjg3em16azFWR05PcnM5TV9KcDlPSVc4QVllNDFsMHBvWVpNQTllQkE0ZnV6YmZDTUdONTdXRjBfMjhRRmJuWTVXblhXR3VPa0N6QS04Uk5IQlRxX3Q1a1BWRV9jNFFVemRJcVoyZG54el9FZ05jdU1hMXVHZEs3YmNybEZIdmNrWjNxMkpsT0NEckxEdEJpYW96ZnlLR0lRUlpheGRYSlE2cl9tZVdHOWhmZUJuMTZKcG5nLTU4TFd6X0VIUVFtLTN1bl85UVl4d2pIY2RDdVBUQ1RXNEFwcFdnZ1FWdE00ZTd6U1ZzMkZYczdpaVZKVzhnMUF1dFFINU53Z1EifSwibm9uY2UiOiIwWm45QTlJc3Q3UlJnckVLemtZdThtUmJXV2x4YmpzX3ZJb0hpZW5wc1JBIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"T0fWfnKgHSv44oU9Ye1icGJIssaCHFoIVVVN4451om0WNFgvqtvvUtUbr5UiZ6it3GHnSl9gMA3nHei7tRs8pIJYKRxM3hVg2YQiDwwtdgdDZoK0oww7fZ5NO4uhiI9mPkRdUipUNe3LM0slQjLhP25JiBGvdVYWLtScEIn0bq-DhtcB3F6Abq7C_75qMUcUn7XMpw_BevvYKKuQC9wLtWnN_O9r5cf8uH2w9ZViy5XK_4FXpwrKvG-4x67LCFD9MoL059gynWNGNFnQHWlTAJm7aN0941JrfwpSWqcJT6UHjagY3Mp6PSGaQGpy5qfulNXdIR1B7JEyyjsAmEV8Nw\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "4orQIw6HjOa-8X1HzkpiOdEuIXRmruVcT518zICV3to";

        final String ACCT_PATH = "/acme/acct/398";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 398," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"l5i-D4_48ZXGR3MF4VIhiBzSpGctEfCYu3l3cVPo215a3YDxZhLwCwH5x0FYesd4_uhfyJJcojntrigoaphe-Nm2K2SeBOws6c6lAb0zmN8gFPRG2wUYYGOJpSADtSWC6iZQsCronaHnk3pGutWvgumMniT0Rw8dEEVd5k36MfkknqZGT6ewOHxh0mz3kbVZy3wuAtG1sK13tokF4Qa3Qf9BsGkWcJ8ukpQ7YyDSJ_BnxjK8DgPbs48qH4f0QZZxXitavPDGkqUmLbxRAj7UeolevwkUv5nkV6X7tWdm2alZTrRNADR7oe8jmotIeDX1GSgE8T7VJion9sSTJKiyBw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-04-27T14:27:35-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE = "0I0Wx7k59VLykloVFtY_QoKXDg8Z2s-v6bWj28RVjaQ";

        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 398," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"l5i-D4_48ZXGR3MF4VIhiBzSpGctEfCYu3l3cVPo215a3YDxZhLwCwH5x0FYesd4_uhfyJJcojntrigoaphe-Nm2K2SeBOws6c6lAb0zmN8gFPRG2wUYYGOJpSADtSWC6iZQsCronaHnk3pGutWvgumMniT0Rw8dEEVd5k36MfkknqZGT6ewOHxh0mz3kbVZy3wuAtG1sK13tokF4Qa3Qf9BsGkWcJ8ukpQ7YyDSJ_BnxjK8DgPbs48qH4f0QZZxXitavPDGkqUmLbxRAj7UeolevwkUv5nkV6X7tWdm2alZTrRNADR7oe8jmotIeDX1GSgE8T7VJion9sSTJKiyBw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-04-27T14:27:35-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "AkKqbV-WR4_5TI0QDZ_d7AfQv9fxDFB4hJvfgmeGJ0Q";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY, CHANGE_KEY_REPLAY_NONCE, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .build();
        return server;
    }

    private ClientAndServer setupTestChangeAccountKeySpecifyCertificateAndPrivateKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"LSx0inDH8oU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_1 = "-zpm4Yqvm2BRZmhYJqaUNf8ZL85ZFgECqn5_MFyr3YI";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxYVFHM05QZ3RBLVdsaDdWR1hTcXh4MlZkNEFYVXdqdHprVTF6blBjcGtwMUZ3aGhVajh0dm9sSnVmdmpIUUNNWXV3eERvRFY4RWoyb0E4Tld6YlJaRzd5ZW1YbmozcVUyNmY3c2N3dWN2WFo1MDY3d0lZQVhvY3NOV0Y2RzJvVXdyc1lpc1NVVU1fWmVoUHVrX0twOHU0WmRnVVN6ZDY0eUp4Tno0ZHR3Skh6MUx2ZFpiYW1FNnZVeWhPbHNOd3hrdlR5YWdWX3lQeVdCMnJ0NVdzcTVTeXNCanNsM09fOVRySVdpeXcyeVA0UC1Od2dDVjFxRVBqZmNvQTJJbkY4SHQ0MlIyY25CakNlNVVlMHlJWkFLbTVEWU15QmUtVFBJeDlhbUVjUXppMHZrNGc4bG1STWRmNC1HLURKSVFpU1dnQ2ZraGdGS1M3amRqY3d5ZXI4cXcifSwibm9uY2UiOiItenBtNFlxdm0yQlJabWhZSnFhVU5mOFpMODVaRmdFQ3FuNV9NRnlyM1lJIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"FwBGzA4MVoALWzcrPVV74nDJm2tCVLrAIcBdoHNuENoBmQLXZLrN06y_0l8S9DthtuhyDKrIVj7IP1JO0KzlMx2RBrlW7Yw4DyLmU10Wvi5ul0XHZ-aO_sV5dhxcRxCd4_CpS0klN_6oorBzwVX3zCfgiY2UY0y4KqH2CfLZuy9uiYjaV89-hqOtiff96KFuuTCFEp_tZfLwsieN2jOnokygeGAhlj7fHZA_9_nfUrZNzDseLJrr0g192jG6Xyd7vBXvC-WOmaRMp-WpcP0w5of0_s9IYGEsttif8X8Pc6er_WVi24m3-Q-Rbv2Iae0bG7hsy74dR1w4ewzJne8VGw\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "JbJRXVqi7Qnmqzr5-ROrmkPvhOVGX7jPBETMFS2cL-w";

        final String ACCT_PATH = "/acme/acct/412";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDEyIiwibm9uY2UiOiJKYkpSWFZxaTdRbm1xenI1LVJPcm1rUHZoT1ZHWDdqUEJFVE1GUzJjTC13IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUva2V5LWNoYW5nZSJ9\",\"payload\":\"eyJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltcDNheUk2ZXlKbElqb2lRVkZCUWlJc0ltdDBlU0k2SWxKVFFTSXNJbTRpT2lKcFltb3pWVmR4YmpORVZscFVkelYzVG5SNGNGZHpSUzFwTVRKa1NEVklVR3RNY0hWUFRIQklkVkExUlVkVldFZFhVMWRpTFVsMVVHcDBSRmxVZHpORVRGVkdPRzlzYkdWNU9VRkZhVVE1TVdsMWJtMUZNbWc1VDA4eVNYQmhNRU5MVkRnME4xWlJjekpVU1hVNVV6QnVlV05KWkY5d05WQkxVamxmTVVRMk5WbEZRVlJTWW5kS2ExODFTbVJKWW5kaFR6VnJXRkJXYWtOS1NFVXdXVlIzZWs0d1prNHdOMUYxWkhOalJHVkRhV3BhWTBkRll6bHZSRkU1YlZGM1NHbFJaamxDU0dKS2JuQk5XVGt4VTE5SllWSXhTWGxoUzNKaFQyUXhSR1JtWDBOek0wMVBZMmh1VkZwTlIzcGpjVFJaVTFwVFRWcFdURVpsUkRoR2JUTlNNMkZ3VGpKcWJHVnJZVEJqWDNoaFdHbEtRMVl0WWtocVkwbHFSVlJIV0c1VUxXbHpiak5HWVZsaFdXRmtTbEJQUkVKUFVtWkhkRTFwWldzMVlVZzBNa2x5TTNwcGEwZE9NbkZ5VXpkMVdUaEliMVZGTmxFaWZTd2lkWEpzSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdmEyVjVMV05vWVc1blpTSjkiLCJwYXlsb2FkIjoiZXlKaFkyTnZkVzUwSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdllXTmpkQzgwTVRJaUxDSnVaWGRMWlhraU9uc2laU0k2SWtGUlFVSWlMQ0pyZEhraU9pSlNVMEVpTENKdUlqb2lhV0pxTTFWWGNXNHpSRlphVkhjMWQwNTBlSEJYYzBVdGFURXlaRWcxU0ZCclRIQjFUMHh3U0hWUU5VVkhWVmhIVjFOWFlpMUpkVkJxZEVSWlZIY3pSRXhWUmpodmJHeGxlVGxCUldsRU9URnBkVzV0UlRKb09VOVBNa2x3WVRCRFMxUTRORGRXVVhNeVZFbDFPVk13Ym5salNXUmZjRFZRUzFJNVh6RkVOalZaUlVGVVVtSjNTbXRmTlVwa1NXSjNZVTgxYTFoUVZtcERTa2hGTUZsVWQzcE9NR1pPTURkUmRXUnpZMFJsUTJscVdtTkhSV001YjBSUk9XMVJkMGhwVVdZNVFraGlTbTV3VFZrNU1WTmZTV0ZTTVVsNVlVdHlZVTlrTVVSa1psOURjek5OVDJOb2JsUmFUVWQ2WTNFMFdWTmFVMDFhVmt4R1pVUTRSbTB6VWpOaGNFNHlhbXhsYTJFd1kxOTRZVmhwU2tOV0xXSklhbU5KYWtWVVIxaHVWQzFwYzI0elJtRlpZVmxoWkVwUVQwUkNUMUptUjNSTmFXVnJOV0ZJTkRKSmNqTjZhV3RIVGpKeGNsTTNkVms0U0c5VlJUWlJJbjE5Iiwic2lnbmF0dXJlIjoiZk01TnVDVlpXZVJVYVQwMUI5UlRHeEZ4TGt0S2toN2FxWmZUZnBxLVZORnBqOVhzWklwZXpXM0Z3TTB2UjRoTjg4Uk1rNzd6WU5OY01GLUk5MDRTRWJnYm0wMEd1T0xfeEJtSUx3aXR0X2pFQTkyS3o5aFhibHJ0ZVRVNnlDOWlBcTBEakFmUnlzTjBLMGgySy1ob1B3cng5b21mVEdkY3ZoenlBWnNsVTRILXFLUzFKM1c5QzZqOWRwU29pZmdRTVRLN2Z6NDNINUd2aXlxLWJ6TFpKOGNBbDh0ZkJna3NNMGl2NHRMcjdtdDlZNG1KTUZqUTM4V1RNUi16MjJCZGJoSFNGd2k2UTEtRllJR1dvWHJXTDRzOENlUi1zeTJac3BYMXkyNnR0NlNlUGFCRjA0emJKY3Fzd2V4ak9rdmlUekNtd0paWXd3SnhTcG5NM1NMWXd3In0\",\"signature\":\"VkoApu2ivP80M0UywJaQHojmcFayf-h7zt_jv19artXbWZZtZ50MfSlA20d0-iy8r1W_Bi3uTgOqVx54ntv2x1cdgFuJjmEEenPiuvL9xcN13zc5P9-JxZFBvdbL1W5Bb4Dp3OZ9LoWNDbqzvuqOxqNqcaf210s5uJ-Cm4BFuFMhxZfG_BAvNpFOZGHGcNn2T8qjM0LcaiduUAc0d2FvILpMdglsm98gXleR6n3Wky5EWhJS3tToKoiLaj8_BwMeqaLB-T461jNbscGCMmmevPX8kDcwNyXgUxilpNdUpyMOHrGnL2s-9Gdc-LT7zV5HNPCbCsO3CKbssBw9rcZ99Q\"}";
        final String CHANGE_KEY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"id\": 412," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"ibj3UWqn3DVZTw5wNtxpWsE-i12dH5HPkLpuOLpHuP5EGUXGWSWb-IuPjtDYTw3DLUF8olley9AEiD91iunmE2h9OO2Ipa0CKT847VQs2TIu9S0nycId_p5PKR9_1D65YEATRbwJk_5JdIbwaO5kXPVjCJHE0YTwzN0fN07QudscDeCijZcGEc9oDQ9mQwHiQf9BHbJnpMY91S_IaR1IyaKraOd1Ddf_Cs3MOchnTZMGzcq4YSZSMZVLFeD8Fm3R3apN2jleka0c_xaXiJCV-bHjcIjETGXnT-isn3FaYaYadJPODBORfGtMiek5aH42Ir3zikGN2qrS7uY8HoUE6Q\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-05-01T13:23:09-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_1 = "5ortix1fBJLJp7HSVd9xWNsXV6R5-Huiq8-MXGOw-JQ";

        final String QUERY_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNDEyIiwibm9uY2UiOiI1b3J0aXgxZkJKTEpwN0hTVmQ5eFdOc1hWNlI1LUh1aXE4LU1YR093LUpRIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC80MTIifQ\",\"payload\":\"e30\",\"signature\":\"hg_Ev3Dqzy5WFJjvj6Rjed69N9UuwmkefOutaIsHmsDcLVt_wbCrWVGCftc7OuG1BQ9KDaa7P5gBaFYLU0-E9g2JeCCfffktcz5Pvqy2eidY1qHhVoXSzWGpTyVaZ97vvSg1aElan0CizmLiWMBL3e2KxOqWh3tryr0hPNNtETZ0nkM7y-CZRCJcT5RGCZYPS34qyT3Ro6vzM6_w9aXn6jr3D6OymuDoTJJePuUyz2i289vk2LVL8c0AJBHdIUOQhS7LgFCZRsmNnzbuxmSV4VvAPXyTvnkA0xGCznoIsP6BtSfYGcxBRc2vZ4pMP5Ji8YXveHWKrm0D3ZbdgAd7WQ\"}";
        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 412," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"ibj3UWqn3DVZTw5wNtxpWsE-i12dH5HPkLpuOLpHuP5EGUXGWSWb-IuPjtDYTw3DLUF8olley9AEiD91iunmE2h9OO2Ipa0CKT847VQs2TIu9S0nycId_p5PKR9_1D65YEATRbwJk_5JdIbwaO5kXPVjCJHE0YTwzN0fN07QudscDeCijZcGEc9oDQ9mQwHiQf9BHbJnpMY91S_IaR1IyaKraOd1Ddf_Cs3MOchnTZMGzcq4YSZSMZVLFeD8Fm3R3apN2jleka0c_xaXiJCV-bHjcIjETGXnT-isn3FaYaYadJPODBORfGtMiek5aH42Ir3zikGN2qrS7uY8HoUE6Q\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-05-01T13:23:09-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "-h3pLGKVb_5caGHOmPgCGhjTzpPrqfuQkLT4ErBdUQs";

        final String CHANGE_KEY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 412," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"iKC6TwkxQ4Pv17IWQBVvmiOEe8_Ess441IE71BZyu9k\"," + System.lineSeparator() +
                "    \"y\": \"tAbS0NqJGuAU8D6YtQ9LEobRGTSeM28gu4ggW509D58\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-05-01T13:23:09-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_2 = "ziXuIerYNvIMRrWgo6KMzxdryqrqpraCekAV1UIVdMA";

        final String QUERY_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"id\": 412," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"iKC6TwkxQ4Pv17IWQBVvmiOEe8_Ess441IE71BZyu9k\"," + System.lineSeparator() +
                "    \"y\": \"tAbS0NqJGuAU8D6YtQ9LEobRGTSeM28gu4ggW509D58\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@example.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-05-01T13:23:09-04:00\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_3 = "mSvE5Sp2a0e82h8yz6aS-6rYowm8K4pUWj6gKwUvxfc";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"iXia3_B0CrU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_2 = "FQnB3uNSbu0Yglr0NRhsjPx-au_wiOUv15pRscS667g";

        final String QUERY_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ6azltdDczT2tSVG5wTXBXeEJJNTZaZl85dEdidkpIclZFazlDZlJNTHVZTnVEZjVTbHhMbnVGNE84NG50T19KV1R6bGR1bkdHVkJfWUtvMWxEV3N0ZUtkWmhseE9Da1JKV3JtTnlla3paanpGZGJDeXNKMXZEb3hxTlA2Si1lUXc0UlYzS0hISVhXUThjblliWkprR2JNNWVlV016cTNsMUd3dnY0UXhZNHRvSEE5cTBENGpsTVBFOEVrXzRSTzVxdFhKWnlZTThuQWVCM3pkM0JwZkhSemxhWWxnb1JtQ3VRXzdWdFFHYm10YkNqcHFUTmVydjY2ZDE2WTFNQlU2dk9jdnFrTERFbFgxa1JVdy1fRWMydVc0emk5bDBvaGdxQWNxMExaY3pydHAzblg0UGZiMzhwSzFJVVppMlQtVzROM1JxbUtCTUE0YjRLRkdFT2xJencifSwibm9uY2UiOiJGUW5CM3VOU2J1MFlnbHIwTlJoc2pQeC1hdV93aU9VdjE1cFJzY1M2NjdnIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXSwib25seVJldHVybkV4aXN0aW5nIjp0cnVlfQ\",\"signature\":\"aLiAFw96zmh0LGFRJRYfCxQoraQ9s1kFraZG4mnjP65rpMrTgu3lo-tN36Ne38CRrRcV8rP-dBizK4-6Weu9NJhiqAUN4UQvdbJJXCqze18MRAgPdIp83pMkVJ9t7_Vl_mthfajbtFIM5IJII5uCjVwnB0r19ZX41MkKu8XzfdNV4wqk4BGCulKHV3MVFiKDWCBeKcUqvcpIkJKDynzUrpwuEKrSWPTf4oA9ZCUOiTY8EQMa5maR1ilNFaDRehdbeq490M1SlL-toNYsCtc459UCycsUgIWWhgRKLah5ik-RBNIwId0Q0poRXHTODJZF8yPU3DmxUoemMdPWQr3Xtw\"}";

        final String QUERY_ACCT_RESPONSE_BODY_4 = "";

        final String QUERY_ACCT_REPLAY_NONCE_4 = "wKXaMYGas3sprWWgzG0AvbIF3-cY049aSLQ4MnM7m0M";

        final String ACCT_PATH_2 = "/acme/acct/413";
        final String ACCT_LOCATION_2 = "http://localhost:4001" + ACCT_PATH_2;

        final String CHANGE_KEY_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"New key is already in use for a different account\"," + System.lineSeparator() +
                "  \"status\": 409" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_3 = "iii3WryFoxDQaU_QQ0KVt352rBcBkWPmsHmeKxbKjAY";

        server = new AcmeMockServerBuilder()
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse(CHANGE_KEY_REQUEST_BODY_1, CHANGE_KEY_RESPONSE_BODY_1, CHANGE_KEY_REPLAY_NONCE_1, 200)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_2, QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_2, CHANGE_KEY_REPLAY_NONCE_2, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_3, QUERY_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_4, QUERY_ACCT_RESPONSE_BODY_4, QUERY_ACCT_REPLAY_NONCE_4, ACCT_LOCATION_2, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_3, CHANGE_KEY_REPLAY_NONCE_3, 409)
                .build();
        return server;
    }

    private AcmeAccount populateBasicAccount(String alias) throws Exception{
        AcmeAccount account = populateBasicBuilder()
                .setKey(aliasToCertificateMap.get(alias), aliasToPrivateKeyMap.get(alias))
                .build();
        return account;
    }

    private class SimpleAcmeClient extends AcmeClientSpi {

        public AcmeChallenge proveIdentifierControl (AcmeAccount account, List <AcmeChallenge> challenges) throws AcmeException {
            AcmeChallenge selectedChallenge = null;
            for (AcmeChallenge challenge : challenges) {
                if (challenge.getType() == AcmeChallenge.Type.HTTP_01) {
                    client.setDispatcher(createChallengeResponse(account, challenge));
                    selectedChallenge = challenge;
                    break;
                }
            }
            return selectedChallenge;
        }

        public void cleanupAfterFailedChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
            // do nothing
        }

        private Dispatcher createChallengeResponse(AcmeAccount account, AcmeChallenge challenge) {
            return new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                    String path = recordedRequest.getPath();
                    if (path.equals("/.well-known/acme-challenge/" + challenge.getToken())) {
                        try {
                            return new MockResponse()
                                    .setHeader("Content-Type", "application/octet-stream")
                                    .setBody(challenge.getKeyAuthorization(account));
                        } catch (AcmeException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    return new MockResponse()
                            .setBody("");
                }
            };
        }
    }

    /**
     * Class used to build up a mock Let's Encrypt server instance.
     */
    private class AcmeMockServerBuilder {

        AcmeMockServerBuilder() {
            server = new ClientAndServer(4001);
        }

        public AcmeMockServerBuilder addDirectoryResponseBody(String directoryResponseBody) {
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath("/directory")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withBody(directoryResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addNewNonceResponse(String newNonce) {
            server.when(
                    request()
                            .withMethod("HEAD")
                            .withPath("/acme/new-nonce")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Replay-Nonce", newNonce)
                                    .withStatusCode(204));
            return this;
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody,
                                                                     String newAccountReplayNonce, String newAccountLocation, int newAccountStatusCode) {
            return addNewAccountRequestAndResponse(expectedNewAccountRequestBody, newAccountResponseBody, newAccountReplayNonce, newAccountLocation,
                    newAccountStatusCode, false);
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody, String newAccountReplayNonce,
                                                                     String newAccountLocation, int newAccountStatusCode, boolean useProblemContentType) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedNewAccountRequestBody, "/acme/new-acct", newAccountResponseBody, newAccountReplayNonce,
                    link, newAccountLocation, newAccountStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder updateAccountRequestAndResponse(String expectedUpdateAccountRequestBody, String updateAccountResponseBody, String updateAccountReplayNonce,
                                                                     String accountUrl, int updateAccountStatusCode) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedUpdateAccountRequestBody, accountUrl, updateAccountResponseBody, updateAccountReplayNonce,
                    link, "", updateAccountStatusCode, false);
        }

        public AcmeMockServerBuilder orderCertificateRequestAndResponse(String expectedOrderCertificateRequestBody, String orderCertificateResponseBody, String orderCertificateReplayNonce,
                                                                        String orderLocation, int orderCertificateStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse(expectedOrderCertificateRequestBody, "/acme/new-order", orderCertificateResponseBody, orderCertificateReplayNonce,
                    "", orderLocation, orderCertificateStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addAuthorizationResponseBody(String expectedAuthorizationUrl, String authorizationResponseBody) {
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath(expectedAuthorizationUrl)
                            .withBody(""),
                    Times.exactly(10))
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withBody(authorizationResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addChallengeRequestAndResponse(String expectedChallengeRequestBody, String expectedChallengeUrl, String challengeResponseBody,
                                                                    String challengeReplayNonce, String challengeLocation, String challengeLink,
                                                                    int challengeStatusCode, boolean useProblemContentType, String verifyChallengePath,
                                                                    String challengeFileContents, String expectedAuthorizationUrl, String authorizationResponseBody) {
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(expectedChallengeUrl)
                            .withHeader("Content-Type", "application/jose+json")
                            .withBody(expectedChallengeRequestBody),
                    Times.once())
                    .callback(request -> {
                        HttpResponse response = response()
                                .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                                .withHeader("Replay-Nonce", challengeReplayNonce)
                                .withBody(challengeResponseBody)
                                .withStatusCode(challengeStatusCode);
                        if (! challengeLocation.isEmpty()) {
                            response = response.withHeader("Location", challengeLocation);
                        }
                        if (! challengeLink.isEmpty()) {
                            response = response.withHeader("Link", challengeLink);
                        }

                        byte[] challengeResponseBytes = null;
                        try {
                            URL verifyChallengeUrl = new URL(client.url(verifyChallengePath).toString());
                            HttpURLConnection connection = (HttpURLConnection) verifyChallengeUrl.openConnection();
                            connection.setRequestMethod("GET");
                            connection.connect();
                            try (InputStream inputStream = new BufferedInputStream(connection.getResponseCode() < 400 ? connection.getInputStream() : connection.getErrorStream())) {
                                challengeResponseBytes = IOUtils.toByteArray(inputStream);
                            }
                        } catch (Exception e) {
                            //
                        }
                        if (challengeFileContents.equals(new String(challengeResponseBytes, StandardCharsets.UTF_8))) {
                            addAuthorizationResponseBody(expectedAuthorizationUrl, authorizationResponseBody);
                        }
                        return response;
                    });
            return this;
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String finalizeOrderLocation, int finalizeStatusCode) {
            return addFinalizeRequestAndResponse(finalResponseBody, finalizeReplayNonce, finalizeUrl, finalizeOrderLocation, finalizeStatusCode, false);
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String orderLocation, int finalizeStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse("", finalizeUrl, finalResponseBody, finalizeReplayNonce, "",
                    orderLocation, finalizeStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addCertificateRequestAndResponse(String certificateUrl, String certificateResponseBody, int certificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/pem-certificate-chain")
                    .withBody(certificateResponseBody)
                    .withStatusCode(certificateStatusCode);
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath(certificateUrl)
                            .withBody(""),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addCheckOrderRequestAndResponse(String orderUrl, String checkCertificateResponseBody, int checkCertificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/json")
                    .withBody(checkCertificateResponseBody)
                    .withStatusCode(checkCertificateStatusCode);
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath(orderUrl)
                            .withBody(""),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addRevokeCertificateRequestAndResponse(String expectedRevokeCertificateRequestBody, String revokeCertificateReplayNonce, int revokeCertificateStatusCode) {
            return addPostRequestAndResponse(expectedRevokeCertificateRequestBody, "/acme/revoke-cert", "", revokeCertificateReplayNonce,
                    "", "", revokeCertificateStatusCode, false);
        }

        public AcmeMockServerBuilder addChangeKeyRequestAndResponse(String expectedChangeKeyRequestBody, String changeKeyResponseBody, String changeKeyReplaceNonce, int changeKeyResponseCode) {
            return addPostRequestAndResponse(expectedChangeKeyRequestBody, "/acme/key-change", changeKeyResponseBody, changeKeyReplaceNonce,
                    "", "", changeKeyResponseCode, false);
        }

        public AcmeMockServerBuilder addPostRequestAndResponse(String expectedPostRequestBody, String postPath, String responseBody, String replayNonce, String link, String location, int responseCode, boolean useProblemContentType) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Replay-Nonce", replayNonce)
                    .withStatusCode(responseCode);
            if (! responseBody.isEmpty()) {
                response = response
                        .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                        .withBody(responseBody);

            }
            if (! link.isEmpty()) {
                response = response.withHeader("Link", link);
            }
            if (! location.isEmpty()) {
                response = response.withHeader("Location", location);
            }
            HttpRequest request = request()
                    .withMethod("POST")
                    .withPath(postPath) ;
            if (! expectedPostRequestBody.isEmpty()) {
                request = request.withBody(expectedPostRequestBody);
            }
            server.when(
                    request,
                    Times.once())
                    .respond(response);

            return this;
        }

        public ClientAndServer build() {
            return server;
        }
    }
}
