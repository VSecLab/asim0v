package com.asimov.dataloader.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.asimov.dataloader.repository.RestClientConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import io.digitalstate.stix.sdo.objects.Vulnerability;
import io.digitalstate.stix.sdo.types.ExternalReferenceType;

/**
 * DataLoaderService
 */
@Service
@EnableConfigurationProperties(RestClientConfig.class)
public class DataLoaderService {

        @Autowired
        RestHighLevelClient esclient;
        Logger logger = LoggerFactory.getLogger(DataLoaderService.class);
        ObjectMapper mapper = new ObjectMapper();

        public Vulnerability parse(JsonNode cveNode) {
                String vulnerabilityName = cveNode.get("CVE_data_meta").get("ID").asText();
                List<String> descriptions = cveNode.get("description").withArray("description_data")
                                .findValuesAsText("value");
                List<String> problemTypesData = cveNode.get("problemtype").withArray("problemtype_data")
                                .findValuesAsText("value");

                JsonNode otherReferences = cveNode.get("references").withArray("reference_data");
                ObjectNode externalReference = mapper.createObjectNode().put("source_name", "cve")
                                .put("external_id", vulnerabilityName);
                ArrayNode externalReferences = mapper.createArrayNode().add(externalReference);
                Vulnerability vulnerability = Vulnerability.builder()
                                .name(
                                vulnerabilityName)
                                .description(descriptions.stream().map(x -> x).collect(Collectors.joining(" | ")))
                                .addAllExternalReferences(mapper.convertValue(externalReferences, ArrayList.class))
                                .customProperties(Map.of("x_CWE",
                                                problemTypesData.stream().map(x -> x)
                                                                .collect(Collectors.toCollection(ArrayList::new)),
                                                "x_data_type", cveNode.get("data_type").asText(),
                                                "x_references",mapper.convertValue(otherReferences,ArrayList.class)))
                                .build();
                return vulnerability;

        }

        public BulkResponse bulkLoadRequest(List<Vulnerability> vulnerabilities) {
                BulkRequest request = new BulkRequest();
                for (Vulnerability vulnerability : vulnerabilities) {
                        IndexRequest indexRequest = new IndexRequest("cve").source(vulnerability.toJsonString(),
                                        XContentType.JSON);
                        request.add(indexRequest);
                }
                BulkResponse bulkResponse = null;
                try {
                         bulkResponse = esclient.bulk(request, RequestOptions.DEFAULT);
                } catch (IOException e) {
                        logger.error("error while inserting data", e);
                }
                return bulkResponse;

        }
}