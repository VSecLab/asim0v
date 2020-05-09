package com.asimov.explorer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.asimov.explorer.repository.ExplorerRepository;
import com.asimov.explorer.service.ExplorerService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.digitalstate.stix.custom.StixCustomObject;
import io.digitalstate.stix.sdo.DomainObject;
import io.digitalstate.stix.sdo.objects.AttackPattern;
import io.digitalstate.stix.sdo.objects.CourseOfAction;
import io.digitalstate.stix.sro.objects.Relationship;

@SpringBootApplication
@RestController
public class ExplorerMain {

	Logger logger = LoggerFactory.getLogger(ExplorerMain.class);

	@Autowired
	ExplorerService explorerService;
	@Autowired
	ExplorerRepository explorerRepository;
	@Autowired
	private Environment env;

	ObjectMapper mapper = new ObjectMapper();

	@RequestMapping("/hello")
	public String hello(@RequestParam(defaultValue = "default") final String name) {
		logger.info("this is a test message");
		return "Hello " + name;
	}

	@RequestMapping("/search")
	public String search(String index, String field, String value) {
		logger.info("searching {}, {}, {}", index, field, value);
		SearchResponse search = explorerRepository.search(field, value, index);
		SearchHits searchHits = search.getHits();
		SearchHit[] hits = searchHits.getHits();
		hits[0].getSourceAsString();
		return hits[0].getSourceAsString();
	}

	public static void main(final String[] args) {
		SpringApplication.run(ExplorerMain.class, args);
	}

}
