/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.datamigration.v2018_07_15_preview;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The name of the quota.
 */
public class QuotaName {
    /**
     * The localized name of the quota.
     */
    @JsonProperty(value = "localizedValue")
    private String localizedValue;

    /**
     * The unlocalized name (or ID) of the quota.
     */
    @JsonProperty(value = "value")
    private String value;

    /**
     * Get the localized name of the quota.
     *
     * @return the localizedValue value
     */
    public String localizedValue() {
        return this.localizedValue;
    }

    /**
     * Set the localized name of the quota.
     *
     * @param localizedValue the localizedValue value to set
     * @return the QuotaName object itself.
     */
    public QuotaName withLocalizedValue(String localizedValue) {
        this.localizedValue = localizedValue;
        return this;
    }

    /**
     * Get the unlocalized name (or ID) of the quota.
     *
     * @return the value value
     */
    public String value() {
        return this.value;
    }

    /**
     * Set the unlocalized name (or ID) of the quota.
     *
     * @param value the value value to set
     * @return the QuotaName object itself.
     */
    public QuotaName withValue(String value) {
        this.value = value;
        return this;
    }

}
