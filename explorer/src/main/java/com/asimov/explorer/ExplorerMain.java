package com.asimov.explorer;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.asimov.explorer.exception.ExplorerCustomException;
import com.asimov.explorer.repository.ExplorerRepository;
import com.asimov.explorer.service.ExplorerService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.digitalstate.stix.bundle.Bundle;
import io.digitalstate.stix.custom.objects.CustomObject;
import io.digitalstate.stix.sdo.objects.AttackPattern;
import io.digitalstate.stix.sdo.objects.Vulnerability;
import io.digitalstate.stix.sro.objects.Relationship;

@SpringBootApplication
@RestController
public class ExplorerMain {

	Logger logger = LoggerFactory.getLogger(ExplorerMain.class);

	@Autowired
	ExplorerService service;
	@Autowired
	private Environment env;

	ObjectMapper mapper = new ObjectMapper();

	@RequestMapping("/hello")
	public String hello(@RequestParam(defaultValue = "default") final String name) {
		logger.info("this is a test message");
		return "Hello " + name;
	}

	@RequestMapping("/search")
	public String buildSTIXFor(String cve) throws ExplorerCustomException {
		Vulnerability vulnerability = service.findVulnerability(cve);
		if (vulnerability == null) {
			return "{\"error\":\"vulnerability not found\"}";
		}
		List<CustomObject> cwes = service.findCWE(vulnerability);
		List<AttackPattern> capecAttacks = service.findCapecAttacks(cwes);
		List<AttackPattern> mitreAttacks = service.findMitreAttacks(capecAttacks);
		mitreAttacks.forEach(x -> System.out.println(x.getExternalReferences()));
		List<Relationship> relationships = new ArrayList<>();
		for (AttackPattern attackPattern : capecAttacks) {
			Relationship relationship = Relationship.builder().sourceRef(attackPattern)
										.relationshipType("targets")
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
												.relationshipType("related-to")
												.targetRef(capecAttack).build();
					relationships.add(relationship);
				}
			}

		Bundle bundle = Bundle.builder().addObjects(vulnerability).addAllObjects(relationships)
				.addAllObjects(mitreAttacks).addAllObjects(capecAttacks).build();
		return bundle.toJsonString();
	}

	public static void main(final String[] args) {
		SpringApplication.run(ExplorerMain.class, args);
	}

}
