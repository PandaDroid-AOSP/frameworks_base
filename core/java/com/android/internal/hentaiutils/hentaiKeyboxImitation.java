/*
 * Copyright (C) 2024 Paranoid Android
 * Copyright (C) 2024 The hentaiOS Project and its Proprietors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.internal.hentaiutils;

import android.os.SystemProperties;
import android.security.KeyChain;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyEntryResponse;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @hide
 */
public class hentaiKeyboxImitation {

    private static final String TAG = "hentaiKeyboxImitation";

    private static final ASN1ObjectIdentifier KEY_ATTESTATION_OID = new ASN1ObjectIdentifier(
            "1.3.6.1.4.1.11129.2.1.17");

    private static PrivateKey parsePrivateKey(String encodedKey, String algorithm)
            throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(algorithm).generatePrivate(keySpec);
    }

    private static byte[] parseCertificate(String encodedCert) {
        return Base64.getDecoder().decode(encodedCert);
    }

    private static byte[] getCertificateChain(String algorithm) throws Exception {
        IKeyboxProvider provider = KeyProviderManager.getProvider();
        String[] certChain = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)
                ? provider.getEcCertificateChain()
                : provider.getRsaCertificateChain();

        ByteArrayOutputStream certificateStream = new ByteArrayOutputStream();
        for (String cert : certChain) {
            certificateStream.write(parseCertificate(cert));
        }
        return certificateStream.toByteArray();
    }

    private static PrivateKey getPrivateKey(String algorithm) throws Exception {
        IKeyboxProvider provider = KeyProviderManager.getProvider();
        String privateKeyEncoded = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)
                ? provider.getEcPrivateKey()
                : provider.getRsaPrivateKey();

        return parsePrivateKey(privateKeyEncoded, algorithm);
    }

    private static X509CertificateHolder getCertificateHolder(String algorithm) throws Exception {
        IKeyboxProvider provider = KeyProviderManager.getProvider();
        String certChain = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)
                ? provider.getEcCertificateChain()[0]
                : provider.getRsaCertificateChain()[0];

        return new X509CertificateHolder(parseCertificate(certChain));
    }

    private static byte[] modifyLeafCertificate(X509Certificate leafCertificate,
            String keyAlgorithm) throws Exception {
        X509CertificateHolder certificateHolder = new X509CertificateHolder(
                leafCertificate.getEncoded());
        Extension keyAttestationExtension = certificateHolder.getExtension(KEY_ATTESTATION_OID);
        ASN1Sequence keyAttestationSequence = ASN1Sequence.getInstance(
                keyAttestationExtension.getExtnValue().getOctets());
        ASN1Encodable[] keyAttestationEncodables = keyAttestationSequence.toArray();
        ASN1Sequence teeEnforcedSequence = (ASN1Sequence) keyAttestationEncodables[7];
        ASN1EncodableVector teeEnforcedVector = new ASN1EncodableVector();

        ASN1Sequence rootOfTrustSequence = null;
        for (ASN1Encodable teeEnforcedEncodable : teeEnforcedSequence) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) teeEnforcedEncodable;
            if (taggedObject.getTagNo() == 704) {
                rootOfTrustSequence = (ASN1Sequence) taggedObject.getObject();
                continue;
            }
            teeEnforcedVector.add(teeEnforcedEncodable);
        }

        if (rootOfTrustSequence == null) throw new Exception("Root of trust not found");

        PrivateKey privateKey = getPrivateKey(keyAlgorithm);
        X509CertificateHolder providerCertHolder = getCertificateHolder(keyAlgorithm);

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                providerCertHolder.getSubject(),
                certificateHolder.getSerialNumber(),
                certificateHolder.getNotBefore(),
                certificateHolder.getNotAfter(),
                certificateHolder.getSubject(),
                certificateHolder.getSubjectPublicKeyInfo()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(
                leafCertificate.getSigAlgName()).build(privateKey);

        byte[] verifiedBootKey = new byte[32];
        ThreadLocalRandom.current().nextBytes(verifiedBootKey);

        DEROctetString verifiedBootHash = (DEROctetString) rootOfTrustSequence.getObjectAt(3);
        if (verifiedBootHash == null) {
            byte[] randomHash = new byte[32];
            ThreadLocalRandom.current().nextBytes(randomHash);
            verifiedBootHash = new DEROctetString(randomHash);
        }

        ASN1Encodable[] rootOfTrustEncodables = {
                new DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,
                new ASN1Enumerated(0),
                verifiedBootHash
        };

        ASN1Sequence newRootOfTrustSequence = new DERSequence(rootOfTrustEncodables);
        ASN1TaggedObject rootOfTrustTaggedObject = new DERTaggedObject(704, newRootOfTrustSequence);
        teeEnforcedVector.add(rootOfTrustTaggedObject);

        ASN1Sequence newTeeEnforcedSequence = new DERSequence(teeEnforcedVector);
        keyAttestationEncodables[7] = newTeeEnforcedSequence;
        ASN1Sequence newKeyAttestationSequence = new DERSequence(keyAttestationEncodables);
        ASN1OctetString newKeyAttestationOctetString = new DEROctetString(
                newKeyAttestationSequence);
        Extension newKeyAttestationExtension = new Extension(KEY_ATTESTATION_OID, false,
                newKeyAttestationOctetString);

        certificateBuilder.addExtension(newKeyAttestationExtension);

        for (ASN1ObjectIdentifier extensionOID :
                certificateHolder.getExtensions().getExtensionOIDs()) {
            if (KEY_ATTESTATION_OID.getId().equals(extensionOID.getId())) continue;
            certificateBuilder.addExtension(certificateHolder.getExtension(extensionOID));
        }

        return certificateBuilder.build(contentSigner).getEncoded();
    }

    public static KeyEntryResponse onGetKeyEntry(KeyEntryResponse response) {
        // If no keybox is found, don't continue spoofing
        if (!KeyProviderManager.isKeyboxAvailable()) {
            Log.d(TAG, "Key attestation spoofing is disabled because no keybox is defined to spoof");
            return response;
        }

        if (response == null || response.metadata == null) return response;

        try {
            if (response.metadata.certificate == null) {
                Log.d(TAG, "Certificate is null, skipping modification");
                return response;
            }

            X509Certificate certificate = KeyChain.toCertificate(response.metadata.certificate);
            if (certificate.getExtensionValue(KEY_ATTESTATION_OID.getId()) == null) {
                Log.d(TAG, "Key attestation OID not found, skipping modification");
                return response;
            }

            String keyAlgorithm = certificate.getPublicKey().getAlgorithm();
            response.metadata.certificate = modifyLeafCertificate(certificate, keyAlgorithm);
            response.metadata.certificateChain = getCertificateChain(keyAlgorithm);
        } catch (Exception e) {
            Log.e(TAG, "Error in onGetKeyEntry", e);
        }

        return response;
    }
}
