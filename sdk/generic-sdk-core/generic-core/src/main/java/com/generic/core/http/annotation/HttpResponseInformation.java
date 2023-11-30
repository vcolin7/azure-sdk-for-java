// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.generic.core.http.annotation;

import com.generic.core.implementation.util.Base64Url;
import com.generic.core.implementation.util.DateTimeRfc1123;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.List;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 *
 * Annotation describing information to expect in an HTTP Response.
 * <!-- TODO (vcolin7): Add samples. -->
 */
@Retention(RUNTIME)
@Target(METHOD)
public @interface HttpResponseInformation {
    /**
     * Get the expected response codes.
     *
     * @return The expected response codes.
     */
    int[] expectedResponses() default {};

    /**
     * Get the unexpected response codes.
     *
     * @return The unexpected response codes.
     */
    int[] unexpectedResponses() default {};

    /**
     * Get the character used to delimit headers in the request.
     *
     * @return The character used to delimit headers in the request.
     */
    String headerDelimiter() default ";";

    /**
     * Get the type that will be used to deserialize the return value of a REST API response. Supported values
     * are:
     *
     * <ol>
     *     <li>{@link Base64Url}</li>
     *     <li>{@link DateTimeRfc1123}</li>
     *     <li>{@link List List&lt;T&gt;} where {@code T} can be one of the four values above.</li>
     * </ol>
     *
     * @return The type that the service interface method's return value will be converted from.
     */
    String returnValueWireType() default "";
}
