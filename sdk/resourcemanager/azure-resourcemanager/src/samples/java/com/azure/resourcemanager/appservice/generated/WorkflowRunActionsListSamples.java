// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Code generated by Microsoft (R) AutoRest Code Generator.

package com.azure.resourcemanager.appservice.generated;

/**
 * Samples for WorkflowRunActions List.
 */
public final class WorkflowRunActionsListSamples {
    /*
     * x-ms-original-file:
     * specification/web/resource-manager/Microsoft.Web/stable/2024-11-01/examples/WorkflowRunActions_List.json
     */
    /**
     * Sample code: List a workflow run actions.
     * 
     * @param azure The entry point for accessing resource management APIs in Azure.
     */
    public static void listAWorkflowRunActions(com.azure.resourcemanager.AzureResourceManager azure) {
        azure.webApps()
            .manager()
            .serviceClient()
            .getWorkflowRunActions()
            .list("test-resource-group", "test-name", "test-workflow", "08586676746934337772206998657CU22", null, null,
                com.azure.core.util.Context.NONE);
    }
}
