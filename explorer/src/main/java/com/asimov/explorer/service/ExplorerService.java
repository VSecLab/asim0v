package com.asimov.explorer.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.asimov.explorer.exception.ExplorerCustomException;
import com.asimov.explorer.repository.ElasticSeachRestClientConfig;
import com.asimov.explorer.repository.ExplorerRepository;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import io.digitalstate.stix.custom.objects.CustomObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.AttackPattern;
import io.digitalstate.stix.sdo.objects.Vulnerability;

/**
 * ExplorerService
 */
@Service
@EnableConfigurationProperties(ElasticSeachRestClientConfig.class)
public class ExplorerService {

        @Autowired
        ExplorerRepository repository;
        Logger logger = LoggerFactory.getLogger(ExplorerService.class);

        public Vulnerability findVulnerability(String cve) throws ExplorerCustomException {
                SearchResponse searchResponse = repository.search("name.keyword", new String[] { cve }, "cve");
                SearchHits searchHits = searchResponse.getHits();
                SearchHit[] hits = searchHits.getHits();
                logger.info("found {} vulnerabilities", hits.length);
                Vulnerability vulnerability = null;
                if (hits.length != 0) {
                        try {
                                vulnerability = (Vulnerability) StixParsers.parseObject(hits[0].getSourceAsString());
                        } catch (StixParserValidationException | IOException e) {
                                logger.error("parsing exception after fetching vulnerability",
                                                hits[0].getSourceAsString(), e);
                                throw new ExplorerCustomException("Parsing Error, wrong data on elasticsearch?", e);

                        }
                }
                return vulnerability;

        }

        public List<CustomObject> findCWE(Vulnerability vulnerability) throws ExplorerCustomException {
                List<CustomObject> cwes = null;
                ArrayList<String> cwe = (ArrayList<String>) vulnerability.getCustomProperties().get("x_CWE");
                // handle NVD-CWE-Other, NVD-CWE-noinfo es. CVE-2018-9844
                SearchResponse cweSearch = repository.search("x_cwe-id.keyword", cwe.toArray(new String[cwe.size()]),
                                "cwe");
                SearchHits cweSearchHits = cweSearch.getHits();
                SearchHit[] cweHits = cweSearchHits.getHits();
                logger.info("found {} weakness", cweHits.length);
                cwes = Arrays.stream(cweHits).map(x -> {
                        try {
                                return (CustomObject) StixParsers.parse(x.getSourceAsString(), CustomObject.class);
                        } catch (StixParserValidationException | IOException e) {
                                logger.error("parsing exception after fetching weakness", e);
                        }
                        throw new RuntimeException("Parsing Error, wrong data on elasticsearch?");
                }).collect(Collectors.toList());
                List<CustomObject> distinctCWEs = cwes.stream()
                                .collect(Collectors.collectingAndThen(Collectors.toCollection(
                                                () -> new TreeSet<>(Comparator.comparing(CustomObject::getId))),
                                                ArrayList::new));
                return distinctCWEs;

        }

        public List<AttackPattern> findCapecAttacks(List<CustomObject> cwes) throws ExplorerCustomException {
                List<String> cwesID = cwes.stream().map(x -> (String) x.getCustomObjectProperties().get("x_cwe-id"))
                                .collect(Collectors.toList());
                SearchResponse searchResponse = repository.search("external_references.external_id.keyword",
                                cwesID.toArray(new String[] {}), "capec_attackpattern");
                SearchHits searchHits = searchResponse.getHits();
                SearchHit[] hits = searchHits.getHits();
                logger.info("found {} capec attacks", hits.length);
                List<AttackPattern> capecAttacks = Arrays.stream(hits).map(x -> {
                        try {
                                return (AttackPattern) StixParsers.parse(x.getSourceAsString(), AttackPattern.class);
                        } catch (StixParserValidationException | IOException e) {
                                logger.error("parsing exception after fetching capec attack pattern", e);

                        }
                        throw new RuntimeException("Parsing Error, wrong data on elasticsearch?");
                }).collect(Collectors.toList());
                return capecAttacks;
        }

        public List<AttackPattern> findMitreAttacks(List<AttackPattern> capecAttacks) throws ExplorerCustomException {
                List<String> capecIds = capecAttacks.stream()
                                .map(x -> x.getExternalReferences().asList().get(0).getExternalId().get())
                                .collect(Collectors.toList());
                SearchResponse capecSearchResponse = repository.search("external_references.external_id.keyword",
                                capecIds.toArray(new String[] {}), "attackpattern");
                SearchHits capecSearchHits = capecSearchResponse.getHits();
                SearchHit[] capecHits = capecSearchHits.getHits();
                logger.info("found {} mitre attacks", capecHits.length);
                List<AttackPattern> techniques = Arrays.stream(capecHits).map(x -> {
                        try {
                                return (AttackPattern) StixParsers.parse(x.getSourceAsString(), AttackPattern.class);
                        } catch (StixParserValidationException | IOException e) {
                                logger.error("parsing exception after fetching mitre attack pattern", e);
                        }
                        throw new RuntimeException("Parsing Error, wrong data on elasticsearch?");
                }).collect(Collectors.toList());
                return techniques;
        }

}