// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.generic.core.http.exception;

import com.generic.core.models.ExpandableStringEnum;

import java.util.Collection;

/**
 * Represents exception types for HTTP requests and responses.
 */
public final class HttpExceptionType extends ExpandableStringEnum<HttpExceptionType> {
    /**
     * The exception thrown when failing to authenticate the HTTP request with status code of {@code 4XX}, typically
     * {@code 401 Unauthorized}.
     *
     * <p>A runtime exception indicating request authorization failure caused by one of the following scenarios:
     * <ul>
     * <li>A client did not send the required authorization credentials to access the requested resource, i.e.
     * Authorization HTTP header is missing in the request</li>
     * <li>If the request contains the HTTP Authorization header, then the exception indicates that authorization has
     * been refused for the credentials contained in the request header.</li>
     * </ul>
     */
    public static final HttpExceptionType CLIENT_AUTHENTICATION = fromString("CLIENT_AUTHENTICATION");

    /**
     * The exception thrown when the HTTP request tried to create an already existing resource and received a status
     * code {@code 4XX}, typically {@code 412 Conflict}.
     */
    public static final HttpExceptionType RESOURCE_EXISTS = fromString("RESOURCE_EXISTS");

    /**
     * The exception thrown for invalid resource modification with status code of {@code 4XX}, typically
     * {@code 409 Conflict}.
     */
    public static final HttpExceptionType RESOURCE_MODIFIED = fromString("RESOURCE_MODIFIED");

    /**
     * The exception thrown when receiving an error response with status code {@code 412 response} (for update) or
     * {@code 404 Not Found} (for get/post).
     */
    public static final HttpExceptionType RESOURCE_NOT_FOUND = fromString("RESOURCE_NOT_FOUND");

    /**
     * This exception thrown when an HTTP request has reached the maximum number of redirect attempts with a status code
     * of {@code 3XX}.
     */
    public static final HttpExceptionType TOO_MANY_REDIRECTS = fromString("TOO_MANY_REDIRECTS");

    /**
     * Creates or finds a HttpExceptionType from its string representation.
     *
     * <p>{@code null} will be returned if {@code name} is {@code null}.
     *
     * @param name A name to look for.
     *
     * @return The corresponding {@link HttpExceptionType} of the provided name, or {@code null} if {@code name} was
     * {@code null}.
     */
    public static HttpExceptionType fromString(String name) {
        return fromString(name, HttpExceptionType.class);
    }

    /**
     * Gets known HttpExceptionType values.
     *
     * @return The known HttpExceptionType values.
     */
    public static Collection<HttpExceptionType> values() {
        return values(HttpExceptionType.class);
    }
}
