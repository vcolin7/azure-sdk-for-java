/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.cognitiveservices.vision.computervision.models;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A region consists of multiple lines (e.g. a column of text in a multi-column
 * document).
 */
public class OcrRegion {
    /**
     * Bounding box of a recognized region. The four integers represent the
     * x-coordinate of the left edge, the y-coordinate of the top edge, width,
     * and height of the bounding box, in the coordinate system of the input
     * image, after it has been rotated around its center according to the
     * detected text angle (see textAngle property), with the origin at the
     * top-left corner, and the y-axis pointing down.
     */
    @JsonProperty(value = "boundingBox")
    private String boundingBox;

    /**
     * The lines property.
     */
    @JsonProperty(value = "lines")
    private List<OcrLine> lines;

    /**
     * Get the boundingBox value.
     *
     * @return the boundingBox value
     */
    public String boundingBox() {
        return this.boundingBox;
    }

    /**
     * Set the boundingBox value.
     *
     * @param boundingBox the boundingBox value to set
     * @return the OcrRegion object itself.
     */
    public OcrRegion withBoundingBox(String boundingBox) {
        this.boundingBox = boundingBox;
        return this;
    }

    /**
     * Get the lines value.
     *
     * @return the lines value
     */
    public List<OcrLine> lines() {
        return this.lines;
    }

    /**
     * Set the lines value.
     *
     * @param lines the lines value to set
     * @return the OcrRegion object itself.
     */
    public OcrRegion withLines(List<OcrLine> lines) {
        this.lines = lines;
        return this;
    }

}
