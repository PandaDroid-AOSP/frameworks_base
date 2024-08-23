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

/**
 * Interface for keybox providers.
 *
 * This interface defines the methods that a keybox provider must implement
 * to provide access to EC and RSA keys and certificate chains.
 *
 * @hide
 */
public interface IKeyboxProvider {

    /**
     * Checks if a valid keybox is available.
     *
     * @return true if a valid keybox is available, false otherwise
     * @hide
     */
    boolean hasKeybox();

    /**
     * Retrieves the EC private key.
     *
     * @return the EC private key as a String
     * @hide
     */
    String getEcPrivateKey();

    /**
     * Retrieves the RSA private key.
     *
     * @return the RSA private key as a String
     * @hide
     */
    String getRsaPrivateKey();

    /**
     * Retrieves the EC certificate chain.
     *
     * @return an array of Strings representing the EC certificate chain
     * @hide
     */
    String[] getEcCertificateChain();

    /**
     * Retrieves the RSA certificate chain.
     *
     * @return an array of Strings representing the RSA certificate chain
     * @hide
     */
    String[] getRsaCertificateChain();
}
