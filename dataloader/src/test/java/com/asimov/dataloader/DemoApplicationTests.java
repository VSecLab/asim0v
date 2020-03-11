package com.asimov.dataloader;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.asimov.dataloader.service.DataLoaderService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.Vulnerability;

@SpringBootTest
class DemoApplicationTests {

	@Autowired
	DataLoaderService dataloaderservice;
	ObjectMapper mapper = new ObjectMapper();

	@Test
	void contextLoads() {
	}

	// multiple CWE values
	@Test
	void readVulnerabilityFromCVE() throws IOException {
		JsonNode cveJSON = mapper.readTree(new ClassPathResource("nvdcve-1.1-2019.json").getInputStream());

		ArrayNode cveItems = cveJSON.withArray("CVE_Items");
		Stream<JsonNode> nodes = IntStream.range(0, cveItems.size()).mapToObj(cveItems::get);
		ArrayList<Vulnerability> vulnerabilities = nodes.parallel().map(cve -> dataloaderservice.parse(cve.get("cve")))
				.collect(Collectors.toCollection(ArrayList::new));
		vulnerabilities.forEach(vulnerability -> {
			Vulnerability parsedVulnerability = null;
			try {
				parsedVulnerability = (Vulnerability)StixParsers.parseObject((vulnerability.toJsonString()));
			assertEquals(vulnerability.toJsonString(), parsedVulnerability.toJsonString(), "parsed vulnerability is different from actual one");
			} catch (StixParserValidationException | IOException e) {
				e.printStackTrace();
			}
		});
	}

	@Test
	void parseVulnerabilityFromJavaObject() throws StixParserValidationException, IOException {
		//check it's a valid json
		JsonNode cveJSON = mapper.readTree(new ClassPathResource("cve.json").getInputStream());
		Vulnerability vulnerability = dataloaderservice.parse(cveJSON.get("cve"));
		String jsonString = vulnerability.toJsonString();
		Vulnerability parsedVulnerability = (Vulnerability)StixParsers.parseObject(jsonString);
		assertEquals(jsonString,parsedVulnerability.toJsonString());
	}

	
}
