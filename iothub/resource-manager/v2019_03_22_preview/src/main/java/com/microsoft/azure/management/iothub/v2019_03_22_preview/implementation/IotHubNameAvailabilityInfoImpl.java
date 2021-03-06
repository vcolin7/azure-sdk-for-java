/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.iothub.v2019_03_22_preview.implementation;

import com.microsoft.azure.management.iothub.v2019_03_22_preview.IotHubNameAvailabilityInfo;
import com.microsoft.azure.arm.model.implementation.WrapperImpl;
import com.microsoft.azure.management.iothub.v2019_03_22_preview.IotHubNameUnavailabilityReason;

class IotHubNameAvailabilityInfoImpl extends WrapperImpl<IotHubNameAvailabilityInfoInner> implements IotHubNameAvailabilityInfo {
    private final IoTHubManager manager;
    IotHubNameAvailabilityInfoImpl(IotHubNameAvailabilityInfoInner inner, IoTHubManager manager) {
        super(inner);
        this.manager = manager;
    }

    @Override
    public IoTHubManager manager() {
        return this.manager;
    }

    @Override
    public String message() {
        return this.inner().message();
    }

    @Override
    public Boolean nameAvailable() {
        return this.inner().nameAvailable();
    }

    @Override
    public IotHubNameUnavailabilityReason reason() {
        return this.inner().reason();
    }

}
