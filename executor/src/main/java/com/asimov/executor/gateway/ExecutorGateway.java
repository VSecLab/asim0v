package com.asimov.executor.gateway;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.validation.constraints.NotNull;

import com.asimov.executor.exception.ExecutorCustomException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.arteam.simplejsonrpc.client.JsonRpcClient;
import com.github.arteam.simplejsonrpc.client.Transport;
import com.google.common.base.Charsets;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

@Service
@EnableConfigurationProperties({ ExplorerConfiguration.class, MetasploitConfiguration.class })
public class ExecutorGateway {

    @Autowired
    private CloseableHttpClient client;
    @Autowired
    private JsonRpcClient rpcClient;
    @Autowired
    private ExplorerConfiguration explorerConfiguration;
    final Logger logger = LoggerFactory.getLogger(ExecutorGateway.class);

    public Map<String, JsonNode> executeCommand(String method, Object[] params) {
        logger.info("executing metasploit method {}, having params {}", method, params);
        Map<String, JsonNode> res = rpcClient.createRequest().method(method).id(1).params(params)
                .returnAsMap(HashMap.class, JsonNode.class).execute();
                logger.debug("metasploit result {}", res);
        return res;
    }

    public String retrieveBundle(final String cve) throws ExecutorCustomException {

        URI request = null;
        String stringResponse = null;
        try {
            request = new URI("http://" + explorerConfiguration.getAddress() + ":" + explorerConfiguration.getPort()
                    + explorerConfiguration.getEndpoint() + cve);
            logger.info("Trying to perform request {} for cve {}", request, cve);
            final HttpUriRequest httprequest = new HttpGet(request);
            final HttpResponse response = client.execute(httprequest);
            logger.info("Retrieving bundle for cve {} ended with Status Code {}", cve, response.getStatusLine());
            stringResponse = EntityUtils.toString(response.getEntity());
        } catch (ParseException | IOException | URISyntaxException e) {
            logger.error("error while retrieving bundle for cve", e.getMessage());
            throw new ExecutorCustomException(e.getMessage(), e.getCause());
        }
        return stringResponse;
    }
}