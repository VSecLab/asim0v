package com.asimov.explorer.repository;

import java.io.IOException;

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.index.query.QueryBuilders;
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

        public SearchResponse search(String field, String value, String elasticSearchIndex) {
                SearchRequest searchRequest = new SearchRequest(elasticSearchIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(QueryBuilders.queryStringQuery(field+":"+value));
                logger.info("searching {}, {}",field,value);
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