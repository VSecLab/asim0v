package com.asimov.explorer.repository;

import java.io.IOException;
import java.util.List;

import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.MatchQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import io.digitalstate.stix.common.StixCommonProperties;

/**
 * DataLoaderService
 */
@Service
@EnableConfigurationProperties(ElasticSeachRestClientConfig.class)
public class ExplorerRepository {

        @Autowired
        RestHighLevelClient esclient;
        Logger logger = LoggerFactory.getLogger(ExplorerRepository.class);

        public <T> BulkResponse bulkLoadRequest(List<T> stixObjects, String elasticSearchIndex) {
                BulkRequest request = new BulkRequest();
                for (T stixObject : stixObjects) {
                        IndexRequest indexRequest = new IndexRequest(elasticSearchIndex).source(
                                        (((StixCommonProperties) stixObject).toJsonString()), XContentType.JSON);
                        request.add(indexRequest);
                }
                BulkResponse bulkResponse = null;
                try {
                        bulkResponse = esclient.bulk(request, RequestOptions.DEFAULT);
                } catch (IOException e) {
                        logger.error("error while inserting data into elasticsearchIndex {}", elasticSearchIndex, e);
                }
                return bulkResponse;

        }

        public SearchResponse search(String field, String value, String elasticSearchIndex) {
                SearchRequest searchRequest = new SearchRequest(elasticSearchIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                // searchSourceBuilder.query(QueryBuilders.termQuery(field, value)); 
                searchSourceBuilder.query(QueryBuilders.matchAllQuery()); 
                searchRequest.source(searchSourceBuilder);
                SearchResponse searchResponse = null;
                try {
                        searchResponse = esclient.search(searchRequest, RequestOptions.DEFAULT);
                } catch (IOException e) {
                        logger.error("error while inserting data into elasticsearchIndex {}", elasticSearchIndex, e);
                }
                return searchResponse;
        }
}