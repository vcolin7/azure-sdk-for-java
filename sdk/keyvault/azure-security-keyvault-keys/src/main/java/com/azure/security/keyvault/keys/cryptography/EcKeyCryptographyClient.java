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

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;

class EcKeyCryptographyClient extends LocalKeyCryptographyClient {
    private final CryptographyClientImpl serviceClient;
    private final Provider provider;

    private KeyPair keyPair;

    /**
     * Creates a EcKeyCryptographyClient that uses {@code service} to service requests
     *
     * @param serviceClient the client to use for service side cryptography operations.
     */
    EcKeyCryptographyClient(CryptographyClientImpl serviceClient) {
        super(serviceClient);

        this.serviceClient = serviceClient;
        this.provider = null;
    }

    EcKeyCryptographyClient(JsonWebKey key, CryptographyClientImpl serviceClient) {
        super(serviceClient);

        this.provider = Security.getProvider("SunEC");
        this.keyPair = key.toEc(key.hasPrivateKey(), provider);
        this.serviceClient = serviceClient;
    }

    private KeyPair getKeyPair(JsonWebKey key) {
        if (keyPair == null) {
            keyPair = key.toEc(key.hasPrivateKey());
        }

        return keyPair;
    }

    @Override
    Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The encrypt operation is not supported for EC keys.");
    }

    @Override
    EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The encrypt operation is not supported for EC keys.");
    }

    @Override
    Mono<EncryptResult> encryptAsync(EncryptParameters encryptParameters, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The encrypt operation is not supported for EC keys.");
    }

    @Override
    EncryptResult encrypt(EncryptParameters encryptParameters, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The encrypt operation is not supported for EC keys.");
    }

    @Override
    Mono<DecryptResult> decryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The decrypt operation is not supported for EC keys.");
    }

    @Override
    DecryptResult decrypt(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The decrypt operation is not supported for EC keys.");
    }

    @Override
    Mono<DecryptResult> decryptAsync(DecryptParameters options, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The decrypt operation is not supported for EC keys.");
    }

    @Override
    DecryptResult decrypt(DecryptParameters options, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The decrypt operation is not supported for EC keys.");
    }

    @Override
    Mono<SignResult> signAsync(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        Objects.requireNonNull(algorithm, "The signature algorithm cannot be null.");
        Objects.requireNonNull(digest, "The digest content cannot be null.");

        keyPair = getKeyPair(key);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.signAsync(algorithm, digest, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricSignatureAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.signAsync(algorithm, digest, context);
            }

            throw new IllegalArgumentException("Private portion of the key not available to perform sign operation");
        }

        Ecdsa ecdsaAlgorithm;
        if (baseAlgorithm instanceof Ecdsa) {
            ecdsaAlgorithm = (Ecdsa) baseAlgorithm;
        } else {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        ISignatureTransform signatureTransform = ecdsaAlgorithm.createSignatureTransform(keyPair, provider);

        try {
            return Mono.just(new SignResult(signatureTransform.sign(digest), algorithm, key.getId()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    SignResult sign(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        Objects.requireNonNull(algorithm, "The signature algorithm cannot be null.");
        Objects.requireNonNull(digest, "The digest content cannot be null.");

        keyPair = getKeyPair(key);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.sign(algorithm, digest, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricSignatureAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.sign(algorithm, digest, context);
            }

            throw new IllegalArgumentException("Private portion of the key not available to perform sign operation");
        }

        Ecdsa ecdsaAlgorithm;

        if (baseAlgorithm instanceof Ecdsa) {
            ecdsaAlgorithm = (Ecdsa) baseAlgorithm;
        } else {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        ISignatureTransform signatureTransform = ecdsaAlgorithm.createSignatureTransform(keyPair, provider);

        try {
            return new SignResult(signatureTransform.sign(digest), algorithm, key.getId());
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    Mono<VerifyResult> verifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                                   Context context) {
        Objects.requireNonNull(algorithm, "The signature algorithm cannot be null.");
        Objects.requireNonNull(digest, "The digest content cannot be null.");
        Objects.requireNonNull(signature, "The signature to be verified cannot be null.");

        keyPair = getKeyPair(key);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.verifyAsync(algorithm, digest, signature, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricSignatureAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.verifyAsync(algorithm, digest, signature, context);
            }

            throw new IllegalArgumentException("Public portion of the key not available to perform verify operation");
        }

        Ecdsa ecdsaAlgorithm;

        if (baseAlgorithm instanceof Ecdsa) {
            ecdsaAlgorithm = (Ecdsa) baseAlgorithm;
        } else {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        ISignatureTransform signatureTransform = ecdsaAlgorithm.createSignatureTransform(keyPair, provider);

        try {
            return Mono.just(new VerifyResult(signatureTransform.verify(digest, signature), algorithm, key.getId()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    VerifyResult verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                        Context context) {
        Objects.requireNonNull(algorithm, "The signature algorithm cannot be null.");
        Objects.requireNonNull(digest, "The digest content cannot be null.");
        Objects.requireNonNull(signature, "The signature to be verified cannot be null.");

        keyPair = getKeyPair(key);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.verify(algorithm, digest, signature, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricSignatureAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.verify(algorithm, digest, signature, context);
            }

            throw
                new IllegalArgumentException("Public portion of the key not available to perform verify operation");
        }

        Ecdsa ecdsaAlgorithm;
        if (baseAlgorithm instanceof Ecdsa) {
            ecdsaAlgorithm = (Ecdsa) baseAlgorithm;
        } else {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        ISignatureTransform signer = ecdsaAlgorithm.createSignatureTransform(keyPair, provider);

        try {
            return new VerifyResult(signer.verify(digest, signature), algorithm, key.getId());
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    Mono<WrapResult> wrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key, JsonWebKey webKey, Context context) {
        throw new UnsupportedOperationException("The wrap key operation is not supported for EC keys.");
    }

    @Override
    WrapResult wrapKey(KeyWrapAlgorithm algorithm, byte[] key, JsonWebKey webKey, Context context) {
        throw new UnsupportedOperationException("The wrap key operation is not supported for EC keys.");
    }

    @Override
    Mono<UnwrapResult> unwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey key,
                                      Context context) {
        throw new UnsupportedOperationException("The unwrap key operation is not supported for EC keys.");
    }

    @Override
    UnwrapResult unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey key, Context context) {
        throw new UnsupportedOperationException("The unwrap key operation is not supported for EC keys.");
    }

    @Override
    Mono<SignResult> signDataAsync(SignatureAlgorithm algorithm, byte[] data, JsonWebKey key, Context context) {
        return signAsync(algorithm, calculateDigest(algorithm, data), key, context);
    }

    @Override
    SignResult signData(SignatureAlgorithm algorithm, byte[] data, JsonWebKey key, Context context) {
        return sign(algorithm, calculateDigest(algorithm, data), key, context);
    }

    @Override
    Mono<VerifyResult> verifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature, JsonWebKey key,
                                       Context context) {
        return verifyAsync(algorithm, calculateDigest(algorithm, data), signature, key, context);
    }

    @Override
    VerifyResult verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature, JsonWebKey key,
                            Context context) {
        return verify(algorithm, calculateDigest(algorithm, data), signature, key, context);
    }

    private byte[] calculateDigest(SignatureAlgorithm algorithm, byte[] data) {
        HashAlgorithm hashAlgorithm = SignatureHashResolver.DEFAULT.get(algorithm);
        MessageDigest md;

        try {
            md = MessageDigest.getInstance(hashAlgorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        md.update(data);

        return md.digest();
    }

    private boolean serviceClientAvailable() {
        return serviceClient != null;
    }
}
