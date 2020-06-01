package com.asimov.executor.gateway;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import javax.validation.constraints.NotNull;

import com.asimov.executor.exception.ExecutorCustomException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.arteam.simplejsonrpc.client.JsonRpcClient;
import com.github.arteam.simplejsonrpc.client.Transport;
import com.google.common.base.Charsets;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;

@ConfigurationProperties(prefix = "metasploit")
public class MetasploitConfiguration {

  Logger logger = LoggerFactory.getLogger(ExplorerConfiguration.class);
  String address;
  int port;
  String endpoint;
  String username;
  String password;

  @Bean
  public JsonRpcClient jsonRpcClient() throws ExecutorCustomException {
    ObjectMapper mapper = new ObjectMapper();
    mapper.getTypeFactory().constructMapType(HashMap.class, String.class, JsonNode.class);

    String basicAuth = "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    JsonRpcClient rpcClient = null;
    try {
      rpcClient = new JsonRpcClient(new Transport() {
        // trust metasploit RPC interface self-signed certificate
        SSLContextBuilder builder = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy());
        // ignore cert issuer CN mismatch
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), new NoopHostnameVerifier());
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build();

        @NotNull
        @Override
        public String pass(@NotNull String request) throws IOException {
          URI uri = null;
          try {
            uri = new URI("https://" + address + ":" + port + endpoint);
          } catch (URISyntaxException e) {
            logger.error("error while creating metasploit URL with address {}, port {}, endpoint {}", address, port, endpoint);
            throw new RuntimeException("configuration error in metasploit properties", e);
          }
          HttpPost post = new HttpPost(uri);
          post.setEntity(new StringEntity(request, Charsets.UTF_8));
          post.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString());
          post.setHeader(HttpHeaders.AUTHORIZATION, basicAuth);
          try (CloseableHttpResponse httpResponse = httpClient.execute(post)) {
            return EntityUtils.toString(httpResponse.getEntity(), Charsets.UTF_8);
          }
        }
      }, mapper);
    } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
      throw new ExecutorCustomException("failed init of JSON RPC Client ", e.getCause());
    }
    return rpcClient;

  }

  public String getAddress() {
    return address;
  }

  public void setAddress(String address) {
    this.address = address;
  }

  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}