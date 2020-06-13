// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Code generated by Microsoft (R) AutoRest Code Generator.

package com.azure.resourcemanager.msi.fluent;

import com.azure.core.annotation.ExpectedResponses;
import com.azure.core.annotation.Get;
import com.azure.core.annotation.Headers;
import com.azure.core.annotation.Host;
import com.azure.core.annotation.HostParam;
import com.azure.core.annotation.PathParam;
import com.azure.core.annotation.QueryParam;
import com.azure.core.annotation.ReturnType;
import com.azure.core.annotation.ServiceInterface;
import com.azure.core.annotation.ServiceMethod;
import com.azure.core.annotation.UnexpectedResponseExceptionType;
import com.azure.core.http.rest.Response;
import com.azure.core.http.rest.RestProxy;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.util.Context;
import com.azure.core.util.FluxUtil;
import com.azure.core.util.logging.ClientLogger;
import com.azure.resourcemanager.msi.ManagedServiceIdentityClient;
import com.azure.resourcemanager.msi.fluent.inner.SystemAssignedIdentityInner;
import reactor.core.publisher.Mono;

/** An instance of this class provides access to all the operations defined in SystemAssignedIdentities. */
public final class SystemAssignedIdentitiesClient {
    private final ClientLogger logger = new ClientLogger(SystemAssignedIdentitiesClient.class);

    /** The proxy service used to perform REST calls. */
    private final SystemAssignedIdentitiesService service;

    /** The service client containing this operation class. */
    private final ManagedServiceIdentityClient client;

    /**
     * Initializes an instance of SystemAssignedIdentitiesClient.
     *
     * @param client the instance of the service client containing this operation class.
     */
    public SystemAssignedIdentitiesClient(ManagedServiceIdentityClient client) {
        this.service =
            RestProxy
                .create(SystemAssignedIdentitiesService.class, client.getHttpPipeline(), client.getSerializerAdapter());
        this.client = client;
    }

    /**
     * The interface defining all the services for ManagedServiceIdentityClientSystemAssignedIdentities to be used by
     * the proxy service to perform REST calls.
     */
    @Host("{$host}")
    @ServiceInterface(name = "ManagedServiceIdenti")
    private interface SystemAssignedIdentitiesService {
        @Headers({"Accept: application/json", "Content-Type: application/json"})
        @Get("/{scope}/providers/Microsoft.ManagedIdentity/identities/default")
        @ExpectedResponses({200})
        @UnexpectedResponseExceptionType(ManagementException.class)
        Mono<Response<SystemAssignedIdentityInner>> getByScope(
            @HostParam("$host") String endpoint,
            @PathParam(value = "scope", encoded = true) String scope,
            @QueryParam("api-version") String apiVersion,
            Context context);
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public Mono<Response<SystemAssignedIdentityInner>> getByScopeWithResponseAsync(String scope) {
        if (this.client.getEndpoint() == null) {
            return Mono
                .error(
                    new IllegalArgumentException(
                        "Parameter this.client.getEndpoint() is required and cannot be null."));
        }
        if (scope == null) {
            return Mono.error(new IllegalArgumentException("Parameter scope is required and cannot be null."));
        }
        return FluxUtil
            .withContext(
                context -> service.getByScope(this.client.getEndpoint(), scope, this.client.getApiVersion(), context))
            .subscriberContext(context -> context.putAll(FluxUtil.toReactorContext(this.client.getContext())));
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @param context The context to associate with this operation.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public Mono<Response<SystemAssignedIdentityInner>> getByScopeWithResponseAsync(String scope, Context context) {
        if (this.client.getEndpoint() == null) {
            return Mono
                .error(
                    new IllegalArgumentException(
                        "Parameter this.client.getEndpoint() is required and cannot be null."));
        }
        if (scope == null) {
            return Mono.error(new IllegalArgumentException("Parameter scope is required and cannot be null."));
        }
        return service.getByScope(this.client.getEndpoint(), scope, this.client.getApiVersion(), context);
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public Mono<SystemAssignedIdentityInner> getByScopeAsync(String scope) {
        return getByScopeWithResponseAsync(scope)
            .flatMap(
                (Response<SystemAssignedIdentityInner> res) -> {
                    if (res.getValue() != null) {
                        return Mono.just(res.getValue());
                    } else {
                        return Mono.empty();
                    }
                });
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @param context The context to associate with this operation.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public Mono<SystemAssignedIdentityInner> getByScopeAsync(String scope, Context context) {
        return getByScopeWithResponseAsync(scope, context)
            .flatMap(
                (Response<SystemAssignedIdentityInner> res) -> {
                    if (res.getValue() != null) {
                        return Mono.just(res.getValue());
                    } else {
                        return Mono.empty();
                    }
                });
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public SystemAssignedIdentityInner getByScope(String scope) {
        return getByScopeAsync(scope).block();
    }

    /**
     * Gets the systemAssignedIdentity available under the specified RP scope.
     *
     * @param scope The resource provider scope of the resource. Parent resource being extended by Managed Identities.
     * @param context The context to associate with this operation.
     * @throws IllegalArgumentException thrown if parameters fail the validation.
     * @throws ManagementException thrown if the request is rejected by server.
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent.
     * @return the systemAssignedIdentity available under the specified RP scope.
     */
    @ServiceMethod(returns = ReturnType.SINGLE)
    public SystemAssignedIdentityInner getByScope(String scope, Context context) {
        return getByScopeAsync(scope, context).block();
    }
}