/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.containerservice.v2019_06_01.implementation;

import com.microsoft.azure.management.containerservice.v2019_06_01.CredentialResults;
import com.microsoft.azure.arm.model.implementation.WrapperImpl;
import java.util.List;
import com.microsoft.azure.management.containerservice.v2019_06_01.CredentialResult;

class CredentialResultsImpl extends WrapperImpl<CredentialResultsInner> implements CredentialResults {
    private final ContainerServiceManager manager;
    CredentialResultsImpl(CredentialResultsInner inner, ContainerServiceManager manager) {
        super(inner);
        this.manager = manager;
    }

    @Override
    public ContainerServiceManager manager() {
        return this.manager;
    }

    @Override
    public List<CredentialResult> kubeconfigs() {
        return this.inner().kubeconfigs();
    }

}
