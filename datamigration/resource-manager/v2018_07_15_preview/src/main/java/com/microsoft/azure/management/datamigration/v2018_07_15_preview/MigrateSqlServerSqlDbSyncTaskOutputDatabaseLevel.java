/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.management.datamigration.v2018_07_15_preview;

import org.joda.time.DateTime;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;

/**
 * The MigrateSqlServerSqlDbSyncTaskOutputDatabaseLevel model.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "resultType", defaultImpl = MigrateSqlServerSqlDbSyncTaskOutputDatabaseLevel.class)
@JsonTypeName("DatabaseLevelOutput")
public class MigrateSqlServerSqlDbSyncTaskOutputDatabaseLevel extends MigrateSqlServerSqlDbSyncTaskOutput {
    /**
     * Name of the database.
     */
    @JsonProperty(value = "databaseName", access = JsonProperty.Access.WRITE_ONLY)
    private String databaseName;

    /**
     * Migration start time.
     */
    @JsonProperty(value = "startedOn", access = JsonProperty.Access.WRITE_ONLY)
    private DateTime startedOn;

    /**
     * Migration end time.
     */
    @JsonProperty(value = "endedOn", access = JsonProperty.Access.WRITE_ONLY)
    private DateTime endedOn;

    /**
     * Migration state that this database is in. Possible values include:
     * 'UNDEFINED', 'CONFIGURING', 'INITIALIAZING', 'STARTING', 'RUNNING',
     * 'READY_TO_COMPLETE', 'COMPLETING', 'COMPLETE', 'CANCELLING',
     * 'CANCELLED', 'FAILED'.
     */
    @JsonProperty(value = "migrationState", access = JsonProperty.Access.WRITE_ONLY)
    private SyncDatabaseMigrationReportingState migrationState;

    /**
     * Number of incoming changes.
     */
    @JsonProperty(value = "incomingChanges", access = JsonProperty.Access.WRITE_ONLY)
    private Long incomingChanges;

    /**
     * Number of applied changes.
     */
    @JsonProperty(value = "appliedChanges", access = JsonProperty.Access.WRITE_ONLY)
    private Long appliedChanges;

    /**
     * Number of cdc inserts.
     */
    @JsonProperty(value = "cdcInsertCounter", access = JsonProperty.Access.WRITE_ONLY)
    private Long cdcInsertCounter;

    /**
     * Number of cdc deletes.
     */
    @JsonProperty(value = "cdcDeleteCounter", access = JsonProperty.Access.WRITE_ONLY)
    private Long cdcDeleteCounter;

    /**
     * Number of cdc updates.
     */
    @JsonProperty(value = "cdcUpdateCounter", access = JsonProperty.Access.WRITE_ONLY)
    private Long cdcUpdateCounter;

    /**
     * Number of tables completed in full load.
     */
    @JsonProperty(value = "fullLoadCompletedTables", access = JsonProperty.Access.WRITE_ONLY)
    private Long fullLoadCompletedTables;

    /**
     * Number of tables loading in full load.
     */
    @JsonProperty(value = "fullLoadLoadingTables", access = JsonProperty.Access.WRITE_ONLY)
    private Long fullLoadLoadingTables;

    /**
     * Number of tables queued in full load.
     */
    @JsonProperty(value = "fullLoadQueuedTables", access = JsonProperty.Access.WRITE_ONLY)
    private Long fullLoadQueuedTables;

    /**
     * Number of tables errored in full load.
     */
    @JsonProperty(value = "fullLoadErroredTables", access = JsonProperty.Access.WRITE_ONLY)
    private Long fullLoadErroredTables;

    /**
     * Indicates if initial load (full load) has been completed.
     */
    @JsonProperty(value = "initializationCompleted", access = JsonProperty.Access.WRITE_ONLY)
    private Boolean initializationCompleted;

    /**
     * CDC apply latency.
     */
    @JsonProperty(value = "latency", access = JsonProperty.Access.WRITE_ONLY)
    private Long latency;

    /**
     * Get name of the database.
     *
     * @return the databaseName value
     */
    public String databaseName() {
        return this.databaseName;
    }

    /**
     * Get migration start time.
     *
     * @return the startedOn value
     */
    public DateTime startedOn() {
        return this.startedOn;
    }

    /**
     * Get migration end time.
     *
     * @return the endedOn value
     */
    public DateTime endedOn() {
        return this.endedOn;
    }

    /**
     * Get migration state that this database is in. Possible values include: 'UNDEFINED', 'CONFIGURING', 'INITIALIAZING', 'STARTING', 'RUNNING', 'READY_TO_COMPLETE', 'COMPLETING', 'COMPLETE', 'CANCELLING', 'CANCELLED', 'FAILED'.
     *
     * @return the migrationState value
     */
    public SyncDatabaseMigrationReportingState migrationState() {
        return this.migrationState;
    }

    /**
     * Get number of incoming changes.
     *
     * @return the incomingChanges value
     */
    public Long incomingChanges() {
        return this.incomingChanges;
    }

    /**
     * Get number of applied changes.
     *
     * @return the appliedChanges value
     */
    public Long appliedChanges() {
        return this.appliedChanges;
    }

    /**
     * Get number of cdc inserts.
     *
     * @return the cdcInsertCounter value
     */
    public Long cdcInsertCounter() {
        return this.cdcInsertCounter;
    }

    /**
     * Get number of cdc deletes.
     *
     * @return the cdcDeleteCounter value
     */
    public Long cdcDeleteCounter() {
        return this.cdcDeleteCounter;
    }

    /**
     * Get number of cdc updates.
     *
     * @return the cdcUpdateCounter value
     */
    public Long cdcUpdateCounter() {
        return this.cdcUpdateCounter;
    }

    /**
     * Get number of tables completed in full load.
     *
     * @return the fullLoadCompletedTables value
     */
    public Long fullLoadCompletedTables() {
        return this.fullLoadCompletedTables;
    }

    /**
     * Get number of tables loading in full load.
     *
     * @return the fullLoadLoadingTables value
     */
    public Long fullLoadLoadingTables() {
        return this.fullLoadLoadingTables;
    }

    /**
     * Get number of tables queued in full load.
     *
     * @return the fullLoadQueuedTables value
     */
    public Long fullLoadQueuedTables() {
        return this.fullLoadQueuedTables;
    }

    /**
     * Get number of tables errored in full load.
     *
     * @return the fullLoadErroredTables value
     */
    public Long fullLoadErroredTables() {
        return this.fullLoadErroredTables;
    }

    /**
     * Get indicates if initial load (full load) has been completed.
     *
     * @return the initializationCompleted value
     */
    public Boolean initializationCompleted() {
        return this.initializationCompleted;
    }

    /**
     * Get cDC apply latency.
     *
     * @return the latency value
     */
    public Long latency() {
        return this.latency;
    }

}
