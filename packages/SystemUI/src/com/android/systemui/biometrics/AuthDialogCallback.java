/*
 * Copyright (C) 2018 The Android Open Source Project
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

package com.android.systemui.biometrics;

import android.annotation.Nullable;
import android.hardware.biometrics.BiometricPrompt;

/**
 * Callback interface for dialog views. These should be implemented by the controller (e.g.
 * FingerprintDialogImpl) and passed into their views (e.g. FingerprintDialogView).
 */
public interface AuthDialogCallback {
    /**
     * Invoked when the dialog is dismissed
     * @param reason - the {@link BiometricPrompt.DismissedReason} for dismissing
     * @param credentialAttestation the HAT received from LockSettingsService upon verification
     */
    void onDismissed(@BiometricPrompt.DismissedReason int reason,
                     @Nullable byte[] credentialAttestation, long requestId);

    /**
     * Invoked when the "try again" button is clicked
     */
    void onTryAgainPressed(long requestId);

    /**
     * Invoked when the "use password" button is clicked
     */
    void onDeviceCredentialPressed(long requestId);

    /**
     * See {@link android.hardware.biometrics.BiometricPrompt.Builder
     * #setReceiveSystemEvents(boolean)}
     * @param event
     */
    void onSystemEvent(int event, long requestId);

    /**
     * Notifies when the dialog has finished animating.
     */
    void onDialogAnimatedIn(long requestId, boolean startFingerprintNow);

    /**
     * Notifies that the fingerprint sensor should be started now.
     */
    void onStartFingerprintNow(long requestId);
}
