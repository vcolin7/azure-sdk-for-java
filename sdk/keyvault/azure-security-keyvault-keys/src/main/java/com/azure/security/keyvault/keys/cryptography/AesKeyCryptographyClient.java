// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.azure.security.keyvault.keys.cryptography;

import com.azure.core.util.Context;
import com.azure.security.keyvault.keys.cryptography.models.DecryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import reactor.core.publisher.Mono;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

class AesKeyCryptographyClient extends LocalKeyCryptographyClient {
    private byte[] key;

    static final int AES_BLOCK_SIZE = 16;

    /**
     * Creates a {@link AesKeyCryptographyClient} to perform local cryptography operations.
     *
     * @param serviceClient The client to route the requests through.
     */
    AesKeyCryptographyClient(CryptographyClientImpl serviceClient) {
        super(serviceClient);
    }

    AesKeyCryptographyClient(JsonWebKey key, CryptographyClientImpl serviceClient) {
        super(serviceClient);

        this.key = key.toAes().getEncoded();
    }

    private byte[] getKey(JsonWebKey key) {
        if (this.key == null) {
            this.key = key.toAes().getEncoded();
        }

        return this.key;
    }

    @Override
    Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey jsonWebKey,
                                     Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(plaintext, "The plaintext cannot be null.");

        return Mono.defer(() ->
            Mono.just(encryptInternal(algorithm, plaintext, null, null, jsonWebKey, context)));
    }

    @Override
    EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(plaintext, "The plaintext cannot be null.");

        return encryptInternal(algorithm, plaintext, null, null, jsonWebKey, context);
    }

    Mono<EncryptResult> encryptAsync(EncryptParameters encryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(encryptParameters, "The encrypt parameters cannot be null.");

        return Mono.defer(() ->
            Mono.just(
                encryptInternal(encryptParameters.getAlgorithm(), encryptParameters.getPlainText(),
                    encryptParameters.getIv(), encryptParameters.getAdditionalAuthenticatedData(), jsonWebKey,
                    context)));
    }

    EncryptResult encrypt(EncryptParameters encryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(encryptParameters, "The encrypt parameters cannot be null.");

        return encryptInternal(encryptParameters.getAlgorithm(), encryptParameters.getPlainText(),
            encryptParameters.getIv(), encryptParameters.getAdditionalAuthenticatedData(), jsonWebKey, context);
    }

    private EncryptResult encryptInternal(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv,
                                          byte[] additionalAuthenticatedData, JsonWebKey jsonWebKey, Context context) {
        if (isGcm(algorithm)) {
            throw new UnsupportedOperationException("AES-GCM is not supported for local cryptography operations.");
        }

        if (!isAes(algorithm)) {
            throw new IllegalStateException("The encryption algorithm provided is not supported: " + algorithm);
        }

        key = getKey(jsonWebKey);

        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("The key provided is empty.");
        }

        // Interpret the algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (!(baseAlgorithm instanceof SymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (iv == null) {
            if (isAes(algorithm)) {
                iv = generateRandomByteArray(AES_BLOCK_SIZE);
            } else {
                throw new IllegalStateException("The encryption algorithm provided is not supported: " + algorithm);
            }
        }

        SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = (SymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] ciphertext;

        try {
            cryptoTransform = symmetricEncryptionAlgorithm.createEncryptor(key, iv, additionalAuthenticatedData, null);
            ciphertext = cryptoTransform.doFinal(plaintext);
        } catch (BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {

            throw new RuntimeException(e);
        }

        return new EncryptResult(ciphertext, algorithm, jsonWebKey.getId(), iv, null, additionalAuthenticatedData);
    }

    @Override
    Mono<DecryptResult> decryptAsync(EncryptionAlgorithm algorithm, byte[] ciphertext, JsonWebKey jsonWebKey,
                                     Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(ciphertext, "The ciphertext cannot be null.");

        return Mono.defer(() ->
            Mono.just(decryptInternal(algorithm, ciphertext, null, null, null, jsonWebKey, context)));
    }

    @Override
    DecryptResult decrypt(EncryptionAlgorithm algorithm, byte[] ciphertext, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(ciphertext, "The ciphertext cannot be null.");

        return decryptInternal(algorithm, ciphertext, null, null, null, jsonWebKey, context);
    }

    @Override
    Mono<DecryptResult> decryptAsync(DecryptParameters decryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(decryptParameters, "The decrypt parameters cannot be null.");

        return Mono.defer(() ->
            Mono.just(
                decryptInternal(decryptParameters.getAlgorithm(), decryptParameters.getCipherText(),
                decryptParameters.getIv(), decryptParameters.getAdditionalAuthenticatedData(),
                decryptParameters.getAuthenticationTag(), jsonWebKey, context)));
    }

    @Override
    DecryptResult decrypt(DecryptParameters decryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(decryptParameters, "The decrypt parameters cannot be null.");

        return decryptInternal(decryptParameters.getAlgorithm(), decryptParameters.getCipherText(),
            decryptParameters.getIv(), decryptParameters.getAdditionalAuthenticatedData(),
            decryptParameters.getAuthenticationTag(), jsonWebKey, context);
    }

    private DecryptResult decryptInternal(EncryptionAlgorithm algorithm, byte[] ciphertext, byte[] iv,
                                          byte[] additionalAuthenticatedData, byte[] authenticationTag,
                                          JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(iv, "'iv' cannot be null in local decryption operations.");

        if (isGcm(algorithm)) {
            throw new UnsupportedOperationException("AES-GCM is not supported for local cryptography operations.");
        }

        if (!isAes(algorithm)) {
            throw new IllegalStateException("The encryption algorithm provided is not supported: " + algorithm);
        }

        key = getKey(jsonWebKey);

        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("The key provided is empty.");
        }

        // Interpret the algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (!(baseAlgorithm instanceof SymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = (SymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] plaintext;

        try {
            cryptoTransform = symmetricEncryptionAlgorithm.createDecryptor(key, iv, additionalAuthenticatedData,
                authenticationTag);
            plaintext = cryptoTransform.doFinal(ciphertext);
        } catch (BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {

            throw new RuntimeException(e);
        }

        return new DecryptResult(plaintext, algorithm, jsonWebKey.getId());
    }

    @Override
    Mono<SignResult> signAsync(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The sign operation not supported for symmetric keys.");
    }

    @Override
    SignResult sign(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The sign operation not supported for symmetric keys.");
    }

    @Override
    Mono<VerifyResult> verifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                                   Context context) {
        throw new UnsupportedOperationException("The verify operation not supported for symmetric keys.");
    }

    VerifyResult verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                        Context context) {
        throw
            new UnsupportedOperationException("The verify operation not supported for symmetric keys.");
    }

    @Override
    Mono<WrapResult> wrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] keyToWrap, JsonWebKey jsonWebKey,
                                  Context context) {
        return Mono.defer(() -> Mono.just(wrapKey(algorithm, keyToWrap, jsonWebKey, context)));
    }

    @Override
    WrapResult wrapKey(KeyWrapAlgorithm algorithm, byte[] keyToWrap, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(keyToWrap, "The key content to be wrapped cannot be null.");

        key = getKey(jsonWebKey);

        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("key");
        }

        // Interpret the algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (!(baseAlgorithm instanceof LocalKeyWrapAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        LocalKeyWrapAlgorithm localKeyWrapAlgorithm = (LocalKeyWrapAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] encryptedKey;

        try {
            cryptoTransform = localKeyWrapAlgorithm.createEncryptor(key, null, null);
            encryptedKey = cryptoTransform.doFinal(keyToWrap);
        } catch (BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {

            throw new RuntimeException(e);
        }

        return new WrapResult(encryptedKey, algorithm, jsonWebKey.getId());
    }

    @Override
    Mono<UnwrapResult> unwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey jsonWebKey,
                                      Context context) {
        return Mono.defer(() -> Mono.just(unwrapKey(algorithm, encryptedKey, jsonWebKey, context)));
    }

    @Override
    UnwrapResult unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(encryptedKey, "The encrypted key content to be unwrapped cannot be null.");

        this.key = getKey(jsonWebKey);

        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (!(baseAlgorithm instanceof LocalKeyWrapAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        LocalKeyWrapAlgorithm localKeyWrapAlgorithm = (LocalKeyWrapAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] decryptedKey;

        try {
            cryptoTransform = localKeyWrapAlgorithm.createDecryptor(this.key, null, null);
            decryptedKey = cryptoTransform.doFinal(encryptedKey);
        } catch (BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {

            throw new RuntimeException(e);
        }

        return new UnwrapResult(decryptedKey, algorithm, jsonWebKey.getId());
    }

    @Override
    Mono<SignResult> signDataAsync(SignatureAlgorithm algorithm, byte[] data, JsonWebKey key, Context context) {
        return signAsync(algorithm, data, key, context);
    }

    @Override
    SignResult signData(SignatureAlgorithm algorithm, byte[] data, JsonWebKey key, Context context) {
        return sign(algorithm, data, key, context);
    }

    @Override
    Mono<VerifyResult> verifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature, JsonWebKey key,
                                       Context context) {
        return verifyAsync(algorithm, data, signature, key, context);
    }

    VerifyResult verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature, JsonWebKey key,
                            Context context) {
        return verify(algorithm, data, signature, key, context);
    }

    private byte[] generateRandomByteArray(int sizeInBytes) {
        byte[] iv;
        SecureRandom randomSecureRandom;

        try {
            randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            iv = new byte[sizeInBytes];
            randomSecureRandom.nextBytes(iv);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return iv;
    }

    private boolean isAes(EncryptionAlgorithm encryptionAlgorithm) {
        return (encryptionAlgorithm == EncryptionAlgorithm.A128CBC
            || encryptionAlgorithm == EncryptionAlgorithm.A192CBC
            || encryptionAlgorithm == EncryptionAlgorithm.A256CBC
            || encryptionAlgorithm == EncryptionAlgorithm.A128CBCPAD
            || encryptionAlgorithm == EncryptionAlgorithm.A192CBCPAD
            || encryptionAlgorithm == EncryptionAlgorithm.A256CBCPAD);
    }

    private boolean isGcm(EncryptionAlgorithm encryptionAlgorithm) {
        return (encryptionAlgorithm == EncryptionAlgorithm.A128GCM
            || encryptionAlgorithm == EncryptionAlgorithm.A192GCM
            || encryptionAlgorithm == EncryptionAlgorithm.A256GCM);
    }
}
