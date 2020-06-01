package com.asimov.executor.gateway;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;

@ConfigurationProperties(prefix = "explorer")
public class ExplorerConfiguration {

  Logger logger = LoggerFactory.getLogger(ExplorerConfiguration.class);
  String address;
  int port;
  String endpoint;

  @Bean
  public CloseableHttpClient httpClient() {
    RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(3 * 1000).build();
    return HttpClientBuilder.create().setDefaultRequestConfig(requestConfig).build();
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
}