package com.azure.identity.implementation;

import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.ExponentialBackoff;
import com.azure.core.http.policy.ExponentialBackoffOptions;
import com.microsoft.aad.msal4j.MsalException;

import java.net.HttpURLConnection;
import java.time.Duration;

public class IdentityRetryStrategy extends ExponentialBackoff {
    public IdentityRetryStrategy() {
    }

    public IdentityRetryStrategy(ExponentialBackoffOptions options) {
        super(options);
    }

    public IdentityRetryStrategy(int maxRetries, Duration baseDelay, Duration maxDelay) {
        super(maxRetries, baseDelay, maxDelay);
    }

    @Override
    public boolean shouldRetry(HttpResponse httpResponse) {
        return super.shouldRetry(httpResponse);
    }

    @Override
    public boolean shouldRetryException(Throwable throwable) {
        if (throwable instanceof MsalException) {
            MsalException msalException = (MsalException) throwable;

            int code = Integer.parseInt(msalException.errorCode());

            return (code == HttpURLConnection.HTTP_CLIENT_TIMEOUT
                || code == HTTP_STATUS_TOO_MANY_REQUESTS // HttpUrlConnection does not define HTTP status 429
                || (code >= HttpURLConnection.HTTP_INTERNAL_ERROR
                && code != HttpURLConnection.HTTP_NOT_IMPLEMENTED
                && code != HttpURLConnection.HTTP_VERSION));
        } else {
            return super.shouldRetryException(throwable);
        }
    }
}
