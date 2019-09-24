package com.microsoft.azure.cognitiveservices.language.textanalytics;

import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.policy.AddHeadersPolicy;
import com.azure.core.http.policy.CookiePolicy;
import com.azure.core.http.policy.HttpPipelinePolicy;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.core.http.policy.UserAgentPolicy;
import com.azure.core.implementation.annotation.ServiceClientBuilder;

import java.util.ArrayList;
import java.util.List;

// TODO: Add Javadoc
@ServiceClientBuilder(serviceClients = {TextAnalyticsAsyncClient.class, TextAnalyticsClient.class})
public class TextAnalyticsClientBuilder {
    private String endpoint;
    private String subscriptionKey;
    private HttpPipeline pipeline;

    // Required
    public TextAnalyticsClientBuilder endpoint(String endpoint) {
        this.endpoint = endpoint;

        return this;
    }

    // Required
    public TextAnalyticsClientBuilder subscriptonKey(String subscriptionKey) {
        this.subscriptionKey = subscriptionKey;

        return this;
    }

    public TextAnalyticsClientBuilder pipeline(HttpPipeline pipeline) {
        this.pipeline = pipeline;

        return this;
    }

    private HttpPipeline createDefaultPipeline() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.put("Ocp-Apim-Subscription-Key", this.subscriptionKey);
        httpHeaders.put("Content-Type", "application/json");

        List<HttpPipelinePolicy> policies = new ArrayList<>();
        policies.add(new UserAgentPolicy());
        policies.add(new RetryPolicy());
        policies.add(new CookiePolicy());
        policies.add(new AddHeadersPolicy(httpHeaders));

        return new HttpPipelineBuilder()
            .policies(policies.toArray(new HttpPipelinePolicy[0]))
            .build();
    }

    public TextAnalyticsAsyncClient buildAsyncClient() {
        if (pipeline == null)
            this.pipeline = createDefaultPipeline();

        return new TextAnalyticsAsyncClient(
            new com.microsoft.azure.cognitiveservices.language.textanalytics.implementation.TextAnalyticsClientBuilder()
                .endpoint(this.endpoint)
                .pipeline(this.pipeline)
                .build());
    }

    public TextAnalyticsClient buildClient() {
        return new TextAnalyticsClient(buildAsyncClient());
    }
}
