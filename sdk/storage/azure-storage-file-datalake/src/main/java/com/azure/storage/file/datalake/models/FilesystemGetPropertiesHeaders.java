// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Code generated by Microsoft (R) AutoRest Code Generator.

package com.azure.storage.file.datalake.models;

import com.azure.core.annotation.Fluent;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines headers for GetProperties operation.
 */
@Fluent
public final class FilesystemGetPropertiesHeaders {
    /*
     * A UTC date/time value generated by the service that indicates the time
     * at which the response was initiated.
     */
    @JsonProperty(value = "Date")
    private String dateProperty;

    /*
     * An HTTP entity tag associated with the filesystem.  Changes to
     * filesystem properties affect the entity tag, but operations on files and
     * directories do not.
     */
    @JsonProperty(value = "ETag")
    private String eTag;

    /*
     * The data and time the filesystem was last modified.  Changes to
     * filesystem properties update the last modified time, but operations on
     * files and directories do not.
     */
    @JsonProperty(value = "Last-Modified")
    private String lastModified;

    /*
     * A server-generated UUID recorded in the analytics logs for
     * troubleshooting and correlation.
     */
    @JsonProperty(value = "x-ms-request-id")
    private String xMsRequestId;

    /*
     * The version of the REST protocol used to process the request.
     */
    @JsonProperty(value = "x-ms-version")
    private String xMsVersion;

    /*
     * The user-defined properties associated with the filesystem.  A
     * comma-separated list of name and value pairs in the format "n1=v1,
     * n2=v2, ...", where each value is a base64 encoded string. Note that the
     * string may only contain ASCII characters in the ISO-8859-1 character
     * set.
     */
    @JsonProperty(value = "x-ms-properties")
    private String xMsProperties;

    /*
     * A bool string indicates whether the namespace feature is enabled. If
     * "true", the namespace is enabled for the filesystem.
     */
    @JsonProperty(value = "x-ms-namespace-enabled")
    private String xMsNamespaceEnabled;

    /**
     * Get the dateProperty property: A UTC date/time value generated by the
     * service that indicates the time at which the response was initiated.
     *
     * @return the dateProperty value.
     */
    public String getDateProperty() {
        return this.dateProperty;
    }

    /**
     * Set the dateProperty property: A UTC date/time value generated by the
     * service that indicates the time at which the response was initiated.
     *
     * @param dateProperty the dateProperty value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setDateProperty(String dateProperty) {
        this.dateProperty = dateProperty;
        return this;
    }

    /**
     * Get the eTag property: An HTTP entity tag associated with the
     * filesystem.  Changes to filesystem properties affect the entity tag, but
     * operations on files and directories do not.
     *
     * @return the eTag value.
     */
    public String getETag() {
        return this.eTag;
    }

    /**
     * Set the eTag property: An HTTP entity tag associated with the
     * filesystem.  Changes to filesystem properties affect the entity tag, but
     * operations on files and directories do not.
     *
     * @param eTag the eTag value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setETag(String eTag) {
        this.eTag = eTag;
        return this;
    }

    /**
     * Get the lastModified property: The data and time the filesystem was last
     * modified.  Changes to filesystem properties update the last modified
     * time, but operations on files and directories do not.
     *
     * @return the lastModified value.
     */
    public String getLastModified() {
        return this.lastModified;
    }

    /**
     * Set the lastModified property: The data and time the filesystem was last
     * modified.  Changes to filesystem properties update the last modified
     * time, but operations on files and directories do not.
     *
     * @param lastModified the lastModified value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setLastModified(String lastModified) {
        this.lastModified = lastModified;
        return this;
    }

    /**
     * Get the xMsRequestId property: A server-generated UUID recorded in the
     * analytics logs for troubleshooting and correlation.
     *
     * @return the xMsRequestId value.
     */
    public String getXMsRequestId() {
        return this.xMsRequestId;
    }

    /**
     * Set the xMsRequestId property: A server-generated UUID recorded in the
     * analytics logs for troubleshooting and correlation.
     *
     * @param xMsRequestId the xMsRequestId value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setXMsRequestId(String xMsRequestId) {
        this.xMsRequestId = xMsRequestId;
        return this;
    }

    /**
     * Get the xMsVersion property: The version of the REST protocol used to
     * process the request.
     *
     * @return the xMsVersion value.
     */
    public String getXMsVersion() {
        return this.xMsVersion;
    }

    /**
     * Set the xMsVersion property: The version of the REST protocol used to
     * process the request.
     *
     * @param xMsVersion the xMsVersion value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setXMsVersion(String xMsVersion) {
        this.xMsVersion = xMsVersion;
        return this;
    }

    /**
     * Get the xMsProperties property: The user-defined properties associated
     * with the filesystem.  A comma-separated list of name and value pairs in
     * the format "n1=v1, n2=v2, ...", where each value is a base64 encoded
     * string. Note that the string may only contain ASCII characters in the
     * ISO-8859-1 character set.
     *
     * @return the xMsProperties value.
     */
    public String getXMsProperties() {
        return this.xMsProperties;
    }

    /**
     * Set the xMsProperties property: The user-defined properties associated
     * with the filesystem.  A comma-separated list of name and value pairs in
     * the format "n1=v1, n2=v2, ...", where each value is a base64 encoded
     * string. Note that the string may only contain ASCII characters in the
     * ISO-8859-1 character set.
     *
     * @param xMsProperties the xMsProperties value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setXMsProperties(String xMsProperties) {
        this.xMsProperties = xMsProperties;
        return this;
    }

    /**
     * Get the xMsNamespaceEnabled property: A bool string indicates whether
     * the namespace feature is enabled. If "true", the namespace is enabled
     * for the filesystem.
     *
     * @return the xMsNamespaceEnabled value.
     */
    public String getXMsNamespaceEnabled() {
        return this.xMsNamespaceEnabled;
    }

    /**
     * Set the xMsNamespaceEnabled property: A bool string indicates whether
     * the namespace feature is enabled. If "true", the namespace is enabled
     * for the filesystem.
     *
     * @param xMsNamespaceEnabled the xMsNamespaceEnabled value to set.
     * @return the FilesystemGetPropertiesHeaders object itself.
     */
    public FilesystemGetPropertiesHeaders setXMsNamespaceEnabled(String xMsNamespaceEnabled) {
        this.xMsNamespaceEnabled = xMsNamespaceEnabled;
        return this;
    }
}
