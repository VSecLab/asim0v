package com.asimov.dataloader.repository;

import org.apache.http.HttpHost;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@ConfigurationProperties(prefix = "elasticsearch")
public class RestClientConfig {

    Logger logger = LoggerFactory.getLogger(RestClientConfig.class);
    String address;
    int port;

    @Bean(destroyMethod = "close")
    @Primary
    public RestHighLevelClient elasticsearchClient() {
        logger.info("using following address {} and port {}", address, port);

        RestClientBuilder builder = RestClient.builder(new HttpHost(address, port, "http"));
        return new RestHighLevelClient(builder);
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
}