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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

class RsaKeyCryptographyClient extends LocalKeyCryptographyClient {
    private KeyPair keyPair;

    /*
     * Creates a RsaKeyCryptographyClient that uses {@code serviceClient) to service requests
     *
     * @param keyPair the key pair to use for cryptography operations.
     */
    RsaKeyCryptographyClient(CryptographyClientImpl serviceClient) {
        super(serviceClient);
    }

    RsaKeyCryptographyClient(JsonWebKey key, CryptographyClientImpl serviceClient) {
        super(serviceClient);

        keyPair = key.toRsa(key.hasPrivateKey());
    }

    private KeyPair getKeyPair(JsonWebKey key) {
        if (keyPair == null) {
            keyPair = key.toRsa(key.hasPrivateKey());
        }

        return keyPair;
    }

    @Override
    Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey jsonWebKey,
                                     Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(plaintext, "The plaintext cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.encryptAsync(algorithm, plaintext, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.encryptAsync(algorithm, plaintext, context);
            }

            throw new IllegalArgumentException("The public portion of the key not available to perform the encrypt"
                + " operation");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] ciphertext;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createEncryptor(keyPair);
            ciphertext = cryptoTransform.doFinal(plaintext);

            return Mono.defer(() -> Mono.just(new EncryptResult(ciphertext, algorithm, jsonWebKey.getId())));
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(plaintext, "The plaintext cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.encrypt(algorithm, plaintext, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.encrypt(algorithm, plaintext, context);
            }

            throw new IllegalArgumentException("The public portion of the key not available to perform the encrypt"
                + " operation");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createEncryptor(keyPair);

            return new EncryptResult(cryptoTransform.doFinal(plaintext), algorithm, jsonWebKey.getId());
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    Mono<EncryptResult> encryptAsync(EncryptParameters encryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(encryptParameters, "The encrypt parameters cannot be null.");

        return Mono.defer(() -> Mono.just(encrypt(encryptParameters, jsonWebKey, context)));
    }

    @Override
    EncryptResult encrypt(EncryptParameters encryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(encryptParameters, "The encrypt parameters cannot be null.");

        return encrypt(encryptParameters.getAlgorithm(), encryptParameters.getPlainText(), jsonWebKey, context);
    }

    @Override
    Mono<DecryptResult> decryptAsync(EncryptionAlgorithm algorithm, byte[] ciphertext, JsonWebKey jsonWebKey,
                                     Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(ciphertext, "The ciphertext cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.decryptAsync(algorithm, ciphertext, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.decryptAsync(algorithm, ciphertext, context);
            }

            throw new IllegalArgumentException("The private portion of the key not available to perform the decrypt"
                + " operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] plaintext;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createDecryptor(keyPair);
            plaintext = cryptoTransform.doFinal(ciphertext);

            return Mono.defer(() -> Mono.just(new DecryptResult(plaintext, algorithm, jsonWebKey.getId())));
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    DecryptResult decrypt(EncryptionAlgorithm algorithm, byte[] ciphertext, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The encryption algorithm cannot be null.");
        Objects.requireNonNull(ciphertext, "The ciphertext cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.decrypt(algorithm, ciphertext, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.decrypt(algorithm, ciphertext, context);
            }

            throw new IllegalArgumentException("The private portion of the key not available to perform the decrypt"
                + " operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createDecryptor(keyPair);

            return new DecryptResult(cryptoTransform.doFinal(ciphertext), algorithm, jsonWebKey.getId());
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    Mono<DecryptResult> decryptAsync(DecryptParameters decryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(decryptParameters, "The decrypt parameters cannot be null.");

        return Mono.defer(() -> Mono.just(decrypt(decryptParameters, jsonWebKey, context)));
    }

    @Override
    DecryptResult decrypt(DecryptParameters decryptParameters, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(decryptParameters, "The decrypt parameters cannot be null.");

        return decrypt(decryptParameters.getAlgorithm(), decryptParameters.getCipherText(), jsonWebKey, context);
    }

    @Override
    Mono<SignResult> signAsync(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        if (serviceClientAvailable()) {
            return serviceClient.signAsync(algorithm, digest, context);
        } else {
            throw new UnsupportedOperationException("The sign operation is not currently supported for Local RSA"
                + " keys.");
        }
    }

    @Override
    SignResult sign(SignatureAlgorithm algorithm, byte[] digest, JsonWebKey key, Context context) {
        if (serviceClientAvailable()) {
            return serviceClient.sign(algorithm, digest, context);
        } else {
            throw new UnsupportedOperationException("The sign operation is not currently supported for Local RSA"
                + " keys.");
        }
    }

    @Override
    Mono<VerifyResult> verifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                                   Context context) {
        if (serviceClientAvailable()) {
            return serviceClient.verifyAsync(algorithm, digest, signature, context);
        } else {
            throw new UnsupportedOperationException("The verify operation is not currently supported for Local RSA"
                + " keys.");
        }
    }

    VerifyResult verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, JsonWebKey key,
                        Context context) {
        if (serviceClientAvailable()) {
            return serviceClient.verify(algorithm, digest, signature, context);
        } else {
            throw new UnsupportedOperationException("The verify operation is not currently supported for Local RSA"
                + " keys.");
        }
    }

    @Override
    Mono<WrapResult> wrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(key, "The key content to be wrapped cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.wrapKeyAsync(algorithm, key, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.wrapKeyAsync(algorithm, key, context);
            }

            throw new IllegalArgumentException("The public portion of the key is not available to perform the wrap key"
                + " operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] encryptedKey;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createEncryptor(keyPair);
            encryptedKey = cryptoTransform.doFinal(key);

            return Mono.defer(() -> Mono.just(new WrapResult(encryptedKey, algorithm, jsonWebKey.getId())));
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    WrapResult wrapKey(KeyWrapAlgorithm algorithm, byte[] key, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(key, "The key content to be wrapped cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.wrapKey(algorithm, key, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPublic() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.wrapKey(algorithm, key, context);
            }

            throw new IllegalArgumentException("The public portion of the key is not available to perform the wrap key"
                + " operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createEncryptor(keyPair);
            return new WrapResult(cryptoTransform.doFinal(key), algorithm, jsonWebKey.getId());
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    Mono<UnwrapResult> unwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey jsonWebKey,
                                      Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(encryptedKey, "The encrypted key content to be unwrapped cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.unwrapKeyAsync(algorithm, encryptedKey, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.unwrapKeyAsync(algorithm, encryptedKey, context);
            }

            throw new IllegalArgumentException("The private portion of the key is not available to perform the unwrap"
                + " key operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;
        byte[] decryptedKey;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createDecryptor(keyPair);
            decryptedKey = cryptoTransform.doFinal(encryptedKey);

            return Mono.just(new UnwrapResult(decryptedKey, algorithm, jsonWebKey.getId()));
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    UnwrapResult unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey, JsonWebKey jsonWebKey, Context context) {
        Objects.requireNonNull(algorithm, "The key wrap algorithm cannot be null.");
        Objects.requireNonNull(encryptedKey, "The encrypted key content to be unwrapped cannot be null.");

        keyPair = getKeyPair(jsonWebKey);

        // Interpret the requested algorithm.
        Algorithm baseAlgorithm = AlgorithmResolver.DEFAULT.get(algorithm.toString());

        if (baseAlgorithm == null) {
            if (serviceClientAvailable()) {
                return serviceClient.unwrapKey(algorithm, encryptedKey, context);
            }

            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        } else if (!(baseAlgorithm instanceof AsymmetricEncryptionAlgorithm)) {
            throw new RuntimeException(new NoSuchAlgorithmException(algorithm.toString()));
        }

        if (keyPair.getPrivate() == null) {
            if (serviceClientAvailable()) {
                return serviceClient.unwrapKey(algorithm, encryptedKey, context);
            }

            throw new IllegalArgumentException("The private portion of the key is not available to perform the unwrap"
                + " key operation.");
        }

        AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm) baseAlgorithm;
        ICryptoTransform cryptoTransform;

        try {
            cryptoTransform = asymmetricEncryptionAlgorithm.createDecryptor(keyPair);

            return new UnwrapResult(cryptoTransform.doFinal(encryptedKey), algorithm, jsonWebKey.getId());
        } catch (InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {

            throw new RuntimeException(e);
        }
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
