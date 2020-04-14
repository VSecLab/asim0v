package com.asimov.dataloader;

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

import com.asimov.dataloader.repository.DataLoaderRepository;
import com.asimov.dataloader.service.DataLoaderService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;

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
public class DataLoaderMain {

	Logger logger = LoggerFactory.getLogger(DataLoaderMain.class);

	@Autowired
	DataLoaderService dataLoaderService;
	@Autowired
	DataLoaderRepository dataLoaderRepository;
	@Autowired
	private Environment env;

	ObjectMapper mapper = new ObjectMapper();

	@RequestMapping("/hello")
	public String hello(@RequestParam(defaultValue = "default") final String name) {
		logger.info("this is a test message");
		return "Hello " + name;
	}

	@RequestMapping("/cve")
	@PostMapping
	public List<File> loadCVEFiles() throws IOException {
		List<File> files;
		try (Stream<Path> walk = Files.walk(Paths.get(env.getProperty("cve.path")))) {
			files = walk.filter(Files::isRegularFile).map(x -> x.toFile()).filter(f -> f.getName().endsWith("json")).collect(Collectors.toList());
		}
		files.parallelStream().forEach(file -> {
			logger.info("loading file {}", file);
			JsonNode cveJSON = null;
			try {
				cveJSON = mapper.readTree(file);
			} catch (IOException e) {
				logger.error("the file {} does not contain valid json", file, e);
				throw new RuntimeException(e);
			}
			ArrayNode cveItems = cveJSON.withArray("CVE_Items");
			Stream<JsonNode> nodes = IntStream.range(0, cveItems.size()).mapToObj(cveItems::get);
			List<DomainObject> vulnerabilities = nodes.parallel()
					.map(cve -> dataLoaderService.parseVulnerability(cve.get("cve")))
					.collect(Collectors.toCollection(ArrayList::new));
			dataLoaderRepository.bulkLoadRequest(vulnerabilities, "cve");
		});
		return files;
	}

	@RequestMapping("/enterpriseattack")
	@PostMapping
	public String loadEnterpriseAttackFile() throws IOException {
		String file = env.getProperty("enterprise-attack.path");
		JsonNode bundleJSON = mapper.readTree(new ClassPathResource(file).getInputStream());
		ArrayNode enterpriseAttackItems = bundleJSON.withArray("objects");
		Supplier<Stream<JsonNode>> streamSupplier = () -> IntStream.range(0, enterpriseAttackItems.size())
				.mapToObj(enterpriseAttackItems::get);
		List<AttackPattern> attackPatterns = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("attack-pattern"))
				.map(attackPattern -> dataLoaderService.parseAttackPattern(attackPattern))
				.collect(Collectors.toCollection(ArrayList::new));
		List<Relationship> relationships = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("relationship") && x.get("relationship_type").asText().equals("mitigates"))
				.map(relationship -> dataLoaderService.parseRelationship(relationship))
				.collect(Collectors.toCollection(ArrayList::new));
		List<CourseOfAction> courseofactions = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("course-of-action"))
				.map(courseOfAction -> dataLoaderService.parseCourseOfAction(courseOfAction))
				.collect(Collectors.toCollection(ArrayList::new));
			dataLoaderRepository.bulkLoadRequest(attackPatterns, "attackpattern");
			dataLoaderRepository.bulkLoadRequest(relationships, "relationship");
			dataLoaderRepository.bulkLoadRequest(courseofactions, "courseofaction");
		return file;
	}

	@RequestMapping("/capec")
	@PostMapping
	public String loadCAPECFile() throws IOException {
		String file = env.getProperty("capec.path");
		JsonNode bundleJSON = mapper.readTree(new ClassPathResource(file).getInputStream());
		ArrayNode capecItems = bundleJSON.withArray("objects");
		Supplier<Stream<JsonNode>> streamSupplier = () -> IntStream.range(0, capecItems.size())
				.mapToObj(capecItems::get);
		List<AttackPattern> attackPatterns = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("attack-pattern"))
				.map(attackPattern -> dataLoaderService.parseAttackPattern(attackPattern))
				.collect(Collectors.toCollection(ArrayList::new));
		List<Relationship> relationships = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("relationship"))
				.map(relationship -> dataLoaderService.parseRelationship(relationship))
				.collect(Collectors.toCollection(ArrayList::new));
		List<CourseOfAction> courseofactions = streamSupplier.get().parallel()
				.filter(x -> x.get("type").asText().equals("course-of-action"))
				.map(courseOfAction -> dataLoaderService.parseCourseOfAction(courseOfAction))
				.collect(Collectors.toCollection(ArrayList::new));
			dataLoaderRepository.bulkLoadRequest(attackPatterns, "attackpattern");
			dataLoaderRepository.bulkLoadRequest(relationships, "relationship");
			dataLoaderRepository.bulkLoadRequest(courseofactions, "courseofaction");
		return file;
	}

	@RequestMapping("/cwe")
	@PostMapping
	public List<File> loadCWEFiles() throws IOException {
		CsvMapper csvMapper = new CsvMapper();
		CsvSchema schema = CsvSchema.emptySchema().withHeader(); // use first row as header; otherwise defaults are fine
		List<File> files;
		try (Stream<Path> walk = Files.walk(Paths.get(env.getProperty("cwe.path")))) {
			files = walk.filter(Files::isRegularFile).map(x -> x.toFile()).collect(Collectors.toList());
		}
		files.parallelStream().forEach(file -> {
			MappingIterator<Map<String, Object>> it;
			try {
				it = csvMapper.readerFor(Map.class).with(schema).readValues(file);
			} catch (IOException e) {
				logger.error("the file {} does not contain valid csv", file, e);
				throw new RuntimeException(e);
			}
			List<StixCustomObject> weaknesses = new ArrayList<>();
			while (it.hasNext()) {
				Map<String, Object> cweFromCSV = it.next();
				StixCustomObject cwe = dataLoaderService.parse(cweFromCSV);
				weaknesses.add(cwe);
			}
			logger.info("Loaded {} weaknesses", weaknesses.size());
			dataLoaderRepository.bulkLoadRequest(weaknesses, "cwe");
		});
		return files;
	}

	public static void main(final String[] args) {
		SpringApplication.run(DataLoaderMain.class, args);
	}

}
