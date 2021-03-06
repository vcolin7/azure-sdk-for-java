/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.automation.v2015_10_31;

import java.util.Collection;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.microsoft.rest.ExpandableStringEnum;

/**
 * Defines values for AutomationKeyPermissions.
 */
public final class AutomationKeyPermissions extends ExpandableStringEnum<AutomationKeyPermissions> {
    /** Static value Read for AutomationKeyPermissions. */
    public static final AutomationKeyPermissions READ = fromString("Read");

    /** Static value Full for AutomationKeyPermissions. */
    public static final AutomationKeyPermissions FULL = fromString("Full");

    /**
     * Creates or finds a AutomationKeyPermissions from its string representation.
     * @param name a name to look for
     * @return the corresponding AutomationKeyPermissions
     */
    @JsonCreator
    public static AutomationKeyPermissions fromString(String name) {
        return fromString(name, AutomationKeyPermissions.class);
    }

    /**
     * @return known AutomationKeyPermissions values
     */
    public static Collection<AutomationKeyPermissions> values() {
        return values(AutomationKeyPermissions.class);
    }
}
