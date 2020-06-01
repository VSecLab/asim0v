package com.asimov.executor;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.constraints.NotNull;

import com.asimov.executor.exception.ExecutorCustomException;
import com.asimov.executor.gateway.ExecutorGateway;
import com.asimov.executor.service.ExecutorService;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.arteam.simplejsonrpc.client.JsonRpcClient;
import com.github.arteam.simplejsonrpc.client.Transport;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;

import io.digitalstate.stix.bundle.Bundle;
import io.digitalstate.stix.bundle.BundleableObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.AttackPattern;

@SpringBootTest
@ActiveProfiles("local")
class ExecutorApplicationTests {

        @Autowired
        ExecutorService service;
        @Autowired
        ExecutorGateway gateway;

        @Test
        void contextLoads() {
                System.out.println("test");
        }

        @Test
        public void bundleTest() throws StixParserValidationException, IOException, ExecutorCustomException {
                ObjectMapper mapper = new ObjectMapper();
                mapper.configure(Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true);
                JsonNode bundleJSON = mapper.readTree(new ClassPathResource("bundle.json").getInputStream());
                Bundle bundle = (Bundle) StixParsers.parseBundle(bundleJSON.toPrettyString());
                ImmutableList<BundleableObject> list = bundle.getObjects().asList();
                List<String> postModules = new ArrayList<>();
                for (BundleableObject bundleableObject : list) {
                        if (bundleableObject instanceof AttackPattern) {
                                AttackPattern attack = null;
                                try {
                                        attack = (AttackPattern) StixParsers
                                                        .parseObject(bundleableObject.toJsonString());
                                } catch (StixParserValidationException | IOException e) {
                                        throw new ExecutorCustomException("error parsing attack pattern from bundle",
                                                        e.getCause());
                                }
                                attack.getExternalReferences().forEach(x -> {
                                        if (x.getSourceName().equals("mitre-attack")) {
                                                postModules.add(x.getExternalId().get());
                                        }
                                });
                        }
                }
                System.out.println(postModules);
        }

        @Test
        public void rpcClientTest() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
                ObjectMapper mapper = new ObjectMapper();
                mapper.getTypeFactory().constructMapType(HashMap.class, String.class, JsonNode.class);
                String basicAuth = "Basic " + Base64.encodeBase64String("123:123".getBytes());
                JsonRpcClient client = new JsonRpcClient(new Transport() {

                        SSLContextBuilder builder = new SSLContextBuilder().loadTrustMaterial(null,
                                        new TrustSelfSignedStrategy());
                        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
                                        SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build();

                        @NotNull
                        @Override
                        public String pass(@NotNull String request) throws IOException {
                                HttpPost post = new HttpPost("https://localhost:55553/api/v1/json-rpc");
                                post.setEntity(new StringEntity(request, Charsets.UTF_8));
                                post.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString());
                                post.setHeader(HttpHeaders.AUTHORIZATION, basicAuth);
                                try (CloseableHttpResponse httpResponse = httpClient.execute(post)) {
                                        return EntityUtils.toString(httpResponse.getEntity(), Charsets.UTF_8);
                                }
                        }
                }, mapper);
                @org.jetbrains.annotations.NotNull
                Map<String, JsonNode> res = client.createRequest().method("module.info").id(1)
                                .params(new String[] { "post", "linux/purple/t1016" })
                                // .params(new String[] { "exploit", "windows/smb/ms08_067_netapi" })
                                // .returnAsMap(Map.class,RequestResponse.class)
                                .returnAsMap(HashMap.class, JsonNode.class).execute();
                System.out.println(res);

        }
        @Test
         void gatewayCommandTest() {
                Map<String, JsonNode> response = gateway.executeCommand("module.info", new String[] { "post", "linux/purple/t1016" });
                JsonNode options = response.get("options");
        }

}
