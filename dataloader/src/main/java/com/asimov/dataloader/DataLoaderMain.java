package com.asimov.dataloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.asimov.dataloader.service.DataLoaderService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.digitalstate.stix.sdo.objects.Vulnerability;

@SpringBootApplication
@RestController
public class DataLoaderMain {

	Logger logger = LoggerFactory.getLogger(DataLoaderMain.class);

	@Autowired
	DataLoaderService dataLoaderService;
	ObjectMapper mapper = new ObjectMapper();

	@RequestMapping("/hello")
	public String hello(@RequestParam(defaultValue = "default") final String name) {
		logger.info("this is a test message");
		return "Hello " + name;
	}

	@RequestMapping("/load")
	public String load() throws IOException {
		JsonNode cveJSON = mapper.readTree(new ClassPathResource("cve.json").getInputStream());

		ArrayNode cveItems = cveJSON.withArray("CVE_Items");
		Stream<JsonNode> nodes = IntStream.range(0, cveItems.size()).mapToObj(cveItems::get);
		ArrayList<Vulnerability> vulnerabilities = nodes.parallel().map(cve -> dataLoaderService.parse(cve.get("cve")))
				.collect(Collectors.toCollection(ArrayList::new));
		// vulnerabilities.forEach(vulnerability ->
		// System.out.println(vulnerability.toJsonString()));
		dataLoaderService.bulkLoadRequest(vulnerabilities);
		return "Loaded " + vulnerabilities.size();
	}

	public static void main(final String[] args) {
		SpringApplication.run(DataLoaderMain.class, args);
	}

}
