/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.datamigration.v2018_07_15_preview;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;

/**
 * Properties for the task that validates a migration between MongoDB data
 * sources.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "taskType", defaultImpl = ValidateMongoDbTaskProperties.class)
@JsonTypeName("Validate.MongoDb")
public class ValidateMongoDbTaskProperties extends ProjectTaskProperties {
    /**
     * The input property.
     */
    @JsonProperty(value = "input")
    private MongoDbMigrationSettings input;

    /**
     * An array containing a single MongoDbMigrationProgress object.
     */
    @JsonProperty(value = "output", access = JsonProperty.Access.WRITE_ONLY)
    private List<MongoDbMigrationProgress> output;

    /**
     * Get the input value.
     *
     * @return the input value
     */
    public MongoDbMigrationSettings input() {
        return this.input;
    }

    /**
     * Set the input value.
     *
     * @param input the input value to set
     * @return the ValidateMongoDbTaskProperties object itself.
     */
    public ValidateMongoDbTaskProperties withInput(MongoDbMigrationSettings input) {
        this.input = input;
        return this;
    }

    /**
     * Get an array containing a single MongoDbMigrationProgress object.
     *
     * @return the output value
     */
    public List<MongoDbMigrationProgress> output() {
        return this.output;
    }

}
