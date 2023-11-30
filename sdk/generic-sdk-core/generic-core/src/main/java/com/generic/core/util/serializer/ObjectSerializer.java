// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.generic.core.util.serializer;

import com.generic.core.http.annotation.HttpResponseInformation;
import com.generic.core.models.Headers;
import com.generic.core.models.TypeReference;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;

/**
 * Generic interface covering serializing and deserialization objects.
 */
public interface ObjectSerializer {
    /**
     * Reads a byte array into its object representation.
     *
     * @param data Byte array.
     * @param typeReference {@link TypeReference} representing the object.
     * @param <T> Type of the object.
     *
     * @return The object represented by the deserialized byte array.
     */
    default <T> T deserializeFromBytes(byte[] data, TypeReference<T> typeReference) {
        // If the byte array is null pass an empty one by default. This is better than returning null as a previous
        // implementation of this may have custom handling for empty data.
        return (data == null)
            ? deserialize(new ByteArrayInputStream(new byte[0]), typeReference)
            : deserialize(new ByteArrayInputStream(data), typeReference);
    }

    /**
     * Reads a stream into its object representation.
     *
     * @param stream {@link InputStream} of data.
     * @param typeReference {@link TypeReference} representing the object.
     * @param <T> Type of the object.
     *
     * @return The object represented by the deserialized stream.
     */
    <T> T deserialize(InputStream stream, TypeReference<T> typeReference);

    /**
     * Deserialize the provided {@link Headers} returned from a REST API to an entity instance declared as the model to
     * hold 'Matching' headers.
     *
     * <p>'Matching' headers are the REST API returned headers with:</p>
     *
     * <ol>
     *   <li>Header names that have the same name as the name of a properties in the entity.</li>
     *   <li>Header names that start with a specific {@link HttpResponseInformation#headerDelimiter() delimiter}</li>
     * </ol>
     *
     * @param headers The REST API returned headers.
     * @param <T> The type of the deserialized object.
     * @param type The type to deserialize.
     *
     * @return An instance of header entity type created based on the provided {@link Headers}, if header entity model
     * does not exist then return {@code null}.
     *
     * @throws IOException If an I/O error occurs.
     */
    <T> T deserialize(Headers headers, Type type) throws IOException;

    /**
     * Converts the object into a byte array.
     *
     * @param value The object.
     *
     * @return The binary representation of the serialized object.
     */
    default byte[] serializeToBytes(Object value) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        serialize(stream, value);

        return stream.toByteArray();
    }

    /**
     * Writes the serialized object into a stream.
     *
     * @param stream {@link OutputStream} where the serialized object will be written.
     * @param value The object.
     */
    void serialize(OutputStream stream, Object value);
}
