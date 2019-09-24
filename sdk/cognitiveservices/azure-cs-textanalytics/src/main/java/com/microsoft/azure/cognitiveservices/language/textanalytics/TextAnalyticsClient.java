package com.microsoft.azure.cognitiveservices.language.textanalytics;

import com.azure.core.http.rest.SimpleResponse;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.EntitiesBatchResult;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.KeyPhraseBatchResult;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.LanguageBatchResult;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.LanguageInput;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.SentimentBatchResult;

import java.util.List;

import reactor.core.publisher.Mono;

// TODO: Add Javadoc
// TODO: Add more convenience methods for common operations
public class TextAnalyticsClient {
    final TextAnalyticsAsyncClient textAnalyticsAsyncClient;

    TextAnalyticsClient(TextAnalyticsAsyncClient textAnalyticsAsyncClient) {
        this.textAnalyticsAsyncClient = textAnalyticsAsyncClient;
    }

    // TODO: Add blocking mechanism to all methods
    public Mono<LanguageBatchResult> detectLanguage(Boolean showStats, List<LanguageInput> documents) {
        return null;
    }

    public Mono<SimpleResponse<LanguageBatchResult>> detectLanguageWithResponse(Boolean showStats, List<LanguageInput> documents) {
        return null;
    }

    public Mono<EntitiesBatchResult> identifyEntities(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }

    public Mono<SimpleResponse<EntitiesBatchResult>> identifyEntitiesWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }

    public Mono<KeyPhraseBatchResult> extractKeyPhrases(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }

    public Mono<SimpleResponse<KeyPhraseBatchResult>> extractKeyPhrasesWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }

    public Mono<SentimentBatchResult> getSentiment(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }

    public Mono<SimpleResponse<SentimentBatchResult>> getSentimentWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return null;
    }
}
