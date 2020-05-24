package com.asimov.explorer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import com.asimov.explorer.repository.ExplorerRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.Assert;

import io.digitalstate.stix.bundle.Bundle;
import io.digitalstate.stix.bundle.BundleableObject;
import io.digitalstate.stix.common.StixCommonProperties;
import io.digitalstate.stix.custom.StixCustomObject;
import io.digitalstate.stix.custom.objects.CustomObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.json.converters.dehydrated.DomainObjectConverter;
import io.digitalstate.stix.sdo.DomainObject;
import io.digitalstate.stix.sdo.objects.Vulnerability;
import io.digitalstate.stix.sro.RelationshipObject;
import io.digitalstate.stix.sro.objects.Relationship;
import io.digitalstate.stix.sro.objects.RelationshipSro;

@SpringBootTest
@ActiveProfiles("local")
class ExplorerApplicationTests {

	@Autowired
	RestHighLevelClient esclient;

	@Autowired
	ExplorerRepository repository;

	@Test
	void contextLoads() {
		System.out.println("test");
	}

	@Test
	void searchCVETest() throws IOException {
		SearchResponse searchResponse = repository.search("name", "CVE-2018-9844", "cve");
		SearchHits searchHits = searchResponse.getHits();
		if (searchHits.getTotalHits().value != 0) {
			SearchHit[] hits = searchHits.getHits();
			System.out.println(hits[0].getSourceAsString());
			Vulnerability vulnerability = (Vulnerability) StixParsers.parseObject(hits[0].getSourceAsString());
			vulnerability.getCustomProperties().get("x_CWE");
			System.out.println(vulnerability.toJsonString());
			assertEquals(vulnerability.toJsonString(), hits[0].getSourceAsString(), "parsed vs elasticsearch");
		}
	}

	@Test
	public void bundleTest() throws StixParserValidationException, IOException {
		JsonNode bundleJSON = new ObjectMapper().readTree(new ClassPathResource("bundle.json").getInputStream());
		BundleableObject bundle = StixParsers.parseObject(bundleJSON.toPrettyString());
		System.err.println(bundle.toJsonString());
	}

	@Test
	public void queryORTest() throws IOException {
		SearchRequest searchRequest = new SearchRequest("cwe");
		SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
		searchSourceBuilder.query(QueryBuilders.queryStringQuery("x_cwe-id:'307'OR'521'"));
		searchRequest.source(searchSourceBuilder);
		SearchResponse searchResponse = esclient.search(searchRequest, RequestOptions.DEFAULT);
		searchResponse.getHits().getHits();
		SearchHits searchHits = searchResponse.getHits();
		SearchHit[] hits = searchHits.getHits();
		System.out.println(hits.length);
		for (SearchHit searchHit : hits) {
			System.out.println(searchHit.getSourceAsString());
		}

	}

	@Test
	void searchCVE_CWE_Test() throws IOException {
		SearchResponse searchResponse = repository.search("name", "'CVE-2018-16703'", "cve");
		SearchHits searchHits = searchResponse.getHits();
		SearchHit[] hits = searchHits.getHits();
		Vulnerability vulnerability = (Vulnerability) StixParsers.parseObject(hits[0].getSourceAsString());
		ArrayList<String> cwe = (ArrayList<String>) vulnerability.getCustomProperties().get("x_CWE");
		// handle NVD-CWE-Other, NVD-CWE-noinfo es. CVE-2018-9844
		SearchResponse cweSearch = repository.search("x_cwe-id",
				cwe.stream().map(x -> "'" + x.substring(4) + "'").collect(Collectors.joining(" OR ")), "cwe");
		searchHits = cweSearch.getHits();
		hits = searchHits.getHits();
		List<CustomObject> cwes = Arrays.stream(hits).map(x -> {
			try {
				return (CustomObject) StixParsers.parse(x.getSourceAsString(), CustomObject.class);
			} catch (StixParserValidationException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}).collect(Collectors.toList());
		System.out.println(cwes.size());
		// cwes.forEach(x -> System.out.println(x.toJsonString()));
		// Relationship relationship = Relationship.builder().relationshipType("uses")
		// .sourceRef(vulnerability)
		// .targetRef(weakness).build();

		// Bundle bundle = Bundle.builder().addObject(vulnerability);
	}

	@Test
	void searchTest_NotFound() throws IOException {
		SearchRequest searchRequest = new SearchRequest("cve");
		SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
		searchSourceBuilder.query(QueryBuilders.queryStringQuery("name:xxxx"));
		searchRequest.source(searchSourceBuilder);
		SearchResponse searchResponse = esclient.search(searchRequest, RequestOptions.DEFAULT);
		SearchHits searchHits = searchResponse.getHits();
		assertEquals(0, searchHits.getTotalHits().value, "expected 0 hits from the search");
	}
}
