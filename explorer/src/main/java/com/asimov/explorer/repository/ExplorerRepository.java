package com.asimov.explorer.repository;

import java.io.IOException;
import java.util.Arrays;

import com.asimov.explorer.exception.ExplorerCustomException;

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

/**
 * DataLoaderService
 */
@Service
@EnableConfigurationProperties(ElasticSeachRestClientConfig.class)
public class ExplorerRepository {

        @Autowired
        RestHighLevelClient esclient;
        Logger logger = LoggerFactory.getLogger(ExplorerRepository.class);

        public SearchResponse search(String field, String[] values, String elasticSearchIndex) throws ExplorerCustomException {
                SearchRequest searchRequest = new SearchRequest(elasticSearchIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(QueryBuilders.termsQuery(field,values));
                logger.info("searching field {}, value {}, index {}", field, Arrays.toString(values), elasticSearchIndex);
                searchRequest.source(searchSourceBuilder);
                SearchResponse searchResponse = null;
                try {
                        searchResponse = esclient.search(searchRequest, RequestOptions.DEFAULT);
                } catch (IOException e) {
                        logger.error("error while inserting data into elasticsearchIndex {}", elasticSearchIndex, e);
                        throw new ExplorerCustomException("searching "+ field + "values " + Arrays.toString(values), e);
                }
                if (logger.isTraceEnabled()) {
                        SearchHit[] results = searchResponse.getHits().getHits();
                        for (SearchHit hit : results) {
                                String sourceAsString = hit.getSourceAsString();
                                logger.trace("for troubleshooting data fetched from elasticsearch {}", sourceAsString);
                        }
                }
                return searchResponse;
        }
}