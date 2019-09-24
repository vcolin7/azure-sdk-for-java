package com.microsoft.azure.cognitiveservices.language.textanalytics;

import com.azure.core.http.rest.SimpleResponse;
import com.azure.core.implementation.util.FluxUtil;
import com.microsoft.azure.cognitiveservices.language.textanalytics.implementation.TextAnalyticsClientImpl;
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
public class TextAnalyticsAsyncClient {
    final TextAnalyticsClientImpl textAnalyticsClientImpl;

    TextAnalyticsAsyncClient(TextAnalyticsClientImpl textAnalyticsClientImpl) {
        this.textAnalyticsClientImpl = textAnalyticsClientImpl;
    }

    public Mono<LanguageBatchResult> detectLanguage(Boolean showStats, List<LanguageInput> documents) {
        return detectLanguageWithResponse(showStats, documents).flatMap(FluxUtil::toMono);
    }

    public Mono<SimpleResponse<LanguageBatchResult>> detectLanguageWithResponse(Boolean showStats, List<LanguageInput> documents) {
        return textAnalyticsClientImpl.detectLanguageWithRestResponseAsync(showStats, documents);
    }

    public Mono<EntitiesBatchResult> identifyEntities(Boolean showStats, List<MultiLanguageInput> documents) {
        return identifyEntitiesWithResponse(showStats, documents).flatMap(FluxUtil::toMono);
    }

    public Mono<SimpleResponse<EntitiesBatchResult>> identifyEntitiesWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return textAnalyticsClientImpl.entitiesWithRestResponseAsync(showStats, documents);
    }

    public Mono<KeyPhraseBatchResult> extractKeyPhrases(Boolean showStats, List<MultiLanguageInput> documents) {
        return extractKeyPhrasesWithResponse(showStats, documents).flatMap(FluxUtil::toMono);
    }

    public Mono<SimpleResponse<KeyPhraseBatchResult>> extractKeyPhrasesWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return textAnalyticsClientImpl.keyPhrasesWithRestResponseAsync(showStats, documents);
    }

    public Mono<SentimentBatchResult> getSentiment(Boolean showStats, List<MultiLanguageInput> documents) {
        return getSentimentWithResponse(showStats, documents).flatMap(FluxUtil::toMono);
    }

    public Mono<SimpleResponse<SentimentBatchResult>> getSentimentWithResponse(Boolean showStats, List<MultiLanguageInput> documents) {
        return textAnalyticsClientImpl.sentimentWithRestResponseAsync(showStats, documents);
    }
}
