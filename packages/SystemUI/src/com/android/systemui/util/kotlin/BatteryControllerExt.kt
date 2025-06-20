/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.systemui.util.kotlin

import com.android.systemui.utils.coroutines.flow.conflatedCallbackFlow
import com.android.systemui.statusbar.policy.BatteryController
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.onStart

fun BatteryController.isDevicePluggedIn(): Flow<Boolean> {
    return conflatedCallbackFlow {
            val batteryCallback =
                object : BatteryController.BatteryStateChangeCallback {
                    override fun onBatteryLevelChanged(
                        level: Int,
                        pluggedIn: Boolean,
                        charging: Boolean
                    ) {
                        trySend(pluggedIn)
                    }
                }
            addCallback(batteryCallback)
            awaitClose { removeCallback(batteryCallback) }
        }
        .onStart { emit(isPluggedIn) }
}

fun BatteryController.isBatteryPowerSaveEnabled(): Flow<Boolean> {
    return conflatedCallbackFlow {
            val batteryCallback =
                object : BatteryController.BatteryStateChangeCallback {
                    override fun onPowerSaveChanged(isPowerSave: Boolean) {
                        trySend(isPowerSave)
                    }
                }
            addCallback(batteryCallback)
            awaitClose { removeCallback(batteryCallback) }
        }
        .onStart { emit(isPowerSave) }
}

fun BatteryController.getBatteryLevel(): Flow<Int> {
    return conflatedCallbackFlow {
            val batteryCallback =
                object : BatteryController.BatteryStateChangeCallback {
                    override fun onBatteryLevelChanged(
                        level: Int,
                        pluggedIn: Boolean,
                        charging: Boolean
                    ) {
                        trySend(level)
                    }
                }
            addCallback(batteryCallback)
            awaitClose { removeCallback(batteryCallback) }
        }
        .onStart { emit(0) }
}

fun BatteryController.isExtremePowerSaverEnabled(): Flow<Boolean> {
    return conflatedCallbackFlow {
            val batteryCallback =
                object : BatteryController.BatteryStateChangeCallback {
                    override fun onExtremeBatterySaverChanged(isExtreme: Boolean) {
                        trySend(isExtreme)
                    }
                }
            addCallback(batteryCallback)
            awaitClose { removeCallback(batteryCallback) }
        }
        .onStart { emit(isExtremeSaverOn) }
}
