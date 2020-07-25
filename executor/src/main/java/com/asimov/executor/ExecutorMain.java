package com.asimov.executor;

import java.util.List;

import com.asimov.executor.exception.ExecutorCustomException;
import com.asimov.executor.service.ExecutorService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.digitalstate.stix.bundle.Bundle;

@SpringBootApplication
@RestController
public class ExecutorMain {

	Logger logger = LoggerFactory.getLogger(ExecutorMain.class);

	@Autowired
	private ExecutorService service;
	@Autowired
	private Environment env;

	ObjectMapper mapper = new ObjectMapper();

	@RequestMapping("/hello")
	public String hello(@RequestParam(defaultValue = "default") final String name) {
		logger.info("this is a test message");
		return "Hello " + name;
	}

	@RequestMapping("/execute")
	@PostMapping
	public String execute(@RequestParam String attack, @RequestParam String targetPlatform,
			@RequestParam(required = false, defaultValue = "${metasploit.reverseShellPort}") String reverseShellPort)
			throws ExecutorCustomException {
		String jobId = service.exploitMultiHandler(targetPlatform, "0.0.0.0", reverseShellPort);
		String result = null;
		if (service.sessionList(jobId) != null) {
			String executionResult = service.runPostModule(jobId, targetPlatform, attack);
			if (executionResult.equals("success")) {
				result = service.readPostModuleResult(jobId);
			}
			else {
				result = "Post Module Execution Failed";
			}
		}
		return result;
	}

	@RequestMapping("/attacks")
	// targetPlatform Windows,Linux,macOS
	public List<String> findAttacks(@RequestParam String cve, @RequestParam(required = false) String targetPlatform)
			throws ExecutorCustomException {
		Bundle bundle = service.retrieveBundle(cve);
		List<String> postModules = service.retrieveAttacks(bundle, targetPlatform);
		return postModules;
	}

	@RequestMapping("/payload")
	@PostMapping
	public String createPayload(@RequestParam String targetPlatform,
			@RequestParam(required = false, defaultValue = "${metasploit.address}") String metasploitAddress,
			@RequestParam(required = false, defaultValue = "${metasploit.reverseShellPort}") String reverseShellPort) {
		String payload = service.generatePayload(targetPlatform, metasploitAddress, reverseShellPort);
		return payload;

	}

	public static void main(final String[] args) {
		SpringApplication.run(ExecutorMain.class, args);
	}

}
