package com.asimov.dataloader.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import com.asimov.dataloader.repository.ElasticSeachRestClientConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.elasticsearch.client.RestHighLevelClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import io.digitalstate.stix.custom.StixCustomObject;
import io.digitalstate.stix.custom.objects.CustomObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.AttackPattern;
import io.digitalstate.stix.sdo.objects.CourseOfAction;
import io.digitalstate.stix.sdo.objects.Vulnerability;
import io.digitalstate.stix.sro.objects.Relationship;

/**
 * DataLoaderService
 */
@Service
@EnableConfigurationProperties(ElasticSeachRestClientConfig.class)
public class DataLoaderService {

        @Autowired
        RestHighLevelClient esclient;
        Logger logger = LoggerFactory.getLogger(DataLoaderService.class);
        ObjectMapper mapper = new ObjectMapper();

        public StixCustomObject parse(Map<String, Object> cweFromCSV) {
                Map<String, Object> cweMap = cweFromCSV.entrySet().stream()
                                .filter(x -> !x.getKey().matches("^.*?(Name|Description).*$"))
                                .collect(Collectors.toMap(
                                                entry -> "x_" + entry.getKey().toLowerCase().replaceAll(" ", "_"),
                                                entry -> entry.getValue()));
                // cweMap.put("id", "x-cwe--".concat(UUID.randomUUID().toString()));
                cweMap.put("id", "x-cwe--".concat(UUID.nameUUIDFromBytes(("CWE"+(String)cweMap.get("x_cwe-id")).getBytes()).toString()));
                cweMap.put("type", "x-cwe");
                cweMap.put("external_references", List.of(Map.of("external_id", cweMap.get("x_cwe-id"), "source_name",
                "cwe", "url",
                "https://cwe.mitre.org/data/definitions/" + cweMap.get("x_cwe-id") + ".html")));
                cweMap.put("name", cweFromCSV.get("Name"));
                cweMap.put("description", cweFromCSV.get("Description"));
                cweMap.put("x_cwe-id", "CWE-"+cweMap.get("x_cwe-id"));
                String cweJSON = null;
                StixCustomObject stixCustomObject = null;
                try {
                        cweJSON = mapper.writeValueAsString(cweMap);
                        stixCustomObject = StixParsers.parse(cweJSON, CustomObject.class);
                } catch (StixParserValidationException | IOException e) {
                        logger.error("Parsed CWE is not a valid JSON", e);
                }
                return stixCustomObject;
        }

        public Vulnerability parseVulnerability(JsonNode cveNode) {
                String vulnerabilityName = cveNode.get("CVE_data_meta").get("ID").asText();
                List<String> descriptions = cveNode.get("description").withArray("description_data")
                                .findValuesAsText("value");
                List<String> problemTypesData = cveNode.get("problemtype").withArray("problemtype_data")
                                .findValuesAsText("value");

                JsonNode otherReferences = cveNode.get("references").withArray("reference_data");
                ObjectNode externalReference = mapper.createObjectNode().put("source_name", "cve").put("external_id",
                                vulnerabilityName);
                ArrayNode externalReferences = mapper.createArrayNode().add(externalReference);
                Vulnerability vulnerability = Vulnerability.builder().name(vulnerabilityName)
                                .description(descriptions.stream().map(x -> x).collect(Collectors.joining(" | ")))
                                .addAllExternalReferences(mapper.convertValue(externalReferences, ArrayList.class))
                                .customProperties(Map.of("x_CWE",
                                                problemTypesData.stream().map(x -> x)
                                                                .collect(Collectors.toCollection(ArrayList::new)),
                                                "x_data_type", cveNode.get("data_type").asText(), "x_references",
                                                mapper.convertValue(otherReferences, ArrayList.class)))
                                .id("vulnerability--".concat(UUID.nameUUIDFromBytes(vulnerabilityName.getBytes()).toString()))
                                .build();
                return vulnerability;

        }

        public AttackPattern parseAttackPattern(JsonNode attackPatternNode) {
                AttackPattern attackPattern = null;
                try {
                        attackPattern = (AttackPattern) StixParsers.parseObject(attackPatternNode.toString());
                } catch (StixParserValidationException | IOException e) {
                        logger.error("Parsed AttackPattern is not a valid JSON", e);
                }
                return attackPattern;
        }

        public Relationship parseRelationship(JsonNode relationshipNode) {
                Relationship relationship = null;
                try {
                        relationship = (Relationship) StixParsers.parseObject(relationshipNode.toString());
                } catch (StixParserValidationException | IOException e) {
                        logger.error("Parsed Relationship is not a valid JSON", e);
                }
                return relationship;
        }

        public CourseOfAction parseCourseOfAction(JsonNode courseOfActionNode) {
                CourseOfAction courseOfAction = null;
                try {
                        courseOfAction = (CourseOfAction) StixParsers.parseObject(courseOfActionNode.toString());
                } catch (StixParserValidationException | IOException e) {
                        logger.error("Parsed CourseOfAction is not a valid JSON", e);
                }
                return courseOfAction;
        }

}