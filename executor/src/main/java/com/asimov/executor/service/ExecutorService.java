package com.asimov.executor.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.asimov.executor.exception.ExecutorCustomException;
import com.asimov.executor.gateway.ExecutorGateway;
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
                        throw new ExecutorCustomException(e.getMessage(), e.getCause());
                }
                return (Bundle) bundle;
        }

        public List<String> retrieveAttacks(Bundle bundle) throws ExecutorCustomException {
                ImmutableList<BundleableObject> list = bundle.getObjects().asList();
                List<String> postModules = new ArrayList<>();
                for (BundleableObject bundleableObject : list) {
                        if (bundleableObject instanceof AttackPattern) {
                                AttackPattern attack = null;
                                try {
                                        attack = (AttackPattern) StixParsers
                                                        .parseObject(bundleableObject.toJsonString());
                                } catch (StixParserValidationException | IOException e) {
                                        throw new ExecutorCustomException("error parsing attack pattern from bundle",
                                                        e.getCause());
                                }
                                attack.getExternalReferences().forEach(x -> {
                                        if (x.getSourceName().equals("mitre-attack")) {
                                                postModules.add(x.getExternalId().get());
                                        }
                                });
                        }
                }
                logger.info("found {} post modules to be executed {} ", postModules.size(), postModules);
                return postModules;

        }

}