package com.asimov.explorer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.asimov.explorer.exception.ExplorerCustomException;
import com.asimov.explorer.repository.ExplorerRepository;
import com.asimov.explorer.service.ExplorerService;

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
import org.springframework.test.context.ActiveProfiles;

import io.digitalstate.stix.bundle.Bundle;
import io.digitalstate.stix.custom.objects.CustomObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.AttackPattern;
import io.digitalstate.stix.sdo.objects.Vulnerability;
import io.digitalstate.stix.sro.objects.Relationship;

@SpringBootTest
@ActiveProfiles("local")
class ExplorerApplicationTests {

	@Autowired
	RestHighLevelClient esclient;
	@Autowired
	ExplorerRepository repository;
	@Autowired
	ExplorerService service;

	@Test
	void contextLoads() {
		System.out.println("test");
	}

	@Test
	void searchCVETest() throws IOException, ExplorerCustomException {
		SearchResponse searchResponse = repository.search("name.keyword", new String[] { "CVE-2018-16703" }, "cve");
		SearchHits searchHits = searchResponse.getHits();
		SearchHit[] hits = searchHits.getHits();
		System.out.println(hits[0].getSourceAsString());
		Vulnerability vulnerability = (Vulnerability) StixParsers.parseObject(hits[0].getSourceAsString());
		vulnerability.getCustomProperties().get("x_CWE");
		System.out.println(vulnerability.toJsonString());
		assertEquals(vulnerability.toJsonString(), hits[0].getSourceAsString(), "parsed vs elasticsearch");
	}

	@Test
	public void queryORTest() throws IOException {
		// SearchRequest searchRequest = new SearchRequest("cwe");
		SearchRequest searchRequest = new SearchRequest("cwe");
		SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
		// searchSourceBuilder.query(QueryBuilders.queryStringQuery("x_cwe-id:'307'"));
		searchSourceBuilder.query(QueryBuilders.termsQuery("x_cwe-id.keyword", new String[] { "CWE-307", "CWE-521" }));
		// searchSourceBuilder.query(QueryBuilders.termQuery("name.keyword","CVE-2018-16703"));
		// searchSourceBuilder.query(QueryBuilders.queryStringQuery("x_cwe-id:'307' OR
		// '521'"));
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
	public void findAttack_Test() throws ExplorerCustomException {
		Vulnerability vulnerability = service.findVulnerability("CVE-2018-16703");
		List<CustomObject> cwes = service.findCWE(vulnerability);
		List<AttackPattern> capecAttacks = service.findCapecAttacks(cwes);
		List<AttackPattern> mitreAttacks = service.findMitreAttacks(capecAttacks);
		mitreAttacks.forEach(x -> System.out.println(x.getExternalReferences()));
		List<Relationship> relationships = new ArrayList<>();
		for (AttackPattern attackPattern : capecAttacks) {
			Relationship relationship = Relationship.builder().sourceRef(attackPattern).relationshipType("targets")
					.targetRef(vulnerability).build();
			relationships.add(relationship);
		}

		for (AttackPattern capecAttack : capecAttacks)
			for (AttackPattern attackPattern : mitreAttacks) {
				String capecID = capecAttack.getExternalReferences().asList().get(0).getExternalId().get();
				List<Optional<String>> refs = attackPattern.getExternalReferences().asList().stream()
						.map(x -> x.getExternalId()).collect(Collectors.toList());
				List<String> filteredList = refs.stream().filter(Optional::isPresent).map(Optional::get)
						.collect(Collectors.toList());
				if (filteredList.contains(capecID)) {
					Relationship relationship = Relationship.builder().sourceRef(attackPattern)
							.relationshipType("related-to").targetRef(capecAttack).build();
					relationships.add(relationship);
				}
			}

		Bundle bundle = Bundle.builder().addObjects(vulnerability).addAllObjects(relationships)
				.addAllObjects(mitreAttacks).addAllObjects(capecAttacks).build();
		System.out.println(bundle.toJsonString());
	}

	@Test
	void searchCVE_CWE_Test() throws IOException, ExplorerCustomException {
		SearchResponse searchResponse = repository.search("name.keyword", new String[] { "CVE-2018-16703" }, "cve");
		SearchHits searchHits = searchResponse.getHits();
		SearchHit[] hits = searchHits.getHits();
		Vulnerability vulnerability = (Vulnerability) StixParsers.parseObject(hits[0].getSourceAsString());
		ArrayList<String> cwe = (ArrayList<String>) vulnerability.getCustomProperties().get("x_CWE");
		// handle NVD-CWE-Other, NVD-CWE-noinfo es. CVE-2018-9844
		SearchResponse cweSearch = repository.search("x_cwe-id.keyword", cwe.toArray(new String[cwe.size()]), "cwe");
		// cwe.stream().map(x -> "'" + x.substring(4) +
		// "'").collect(Collectors.joining("OR")), "cwe");
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
		cwes.forEach(x -> System.out.println(x.getId()));
		List<CustomObject> distinctCWEs = cwes.stream()
				.collect(Collectors.collectingAndThen(
						Collectors.toCollection(() -> new TreeSet<>(Comparator.comparing(CustomObject::getId))),
						ArrayList::new));
		System.out.println("distinct");
		distinctCWEs.forEach(x -> System.out.println(x.getId()));

		// distinctCWEs.
		// repository.search("external_references.external_id", value,
		// elasticSearchIndex);

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
