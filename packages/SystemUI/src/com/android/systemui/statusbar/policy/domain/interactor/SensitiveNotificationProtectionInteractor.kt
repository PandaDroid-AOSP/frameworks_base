/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.systemui.statusbar.policy.domain.interactor

import com.android.server.notification.Flags
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.statusbar.policy.SensitiveNotificationProtectionController
import com.android.systemui.utils.coroutines.flow.conflatedCallbackFlow
import javax.inject.Inject
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOf

/** A interactor which provides the current sensitive notification protections status */
@SysUISingleton
class SensitiveNotificationProtectionInteractor
@Inject
constructor(private val controller: SensitiveNotificationProtectionController) {

    /** sensitive notification protections status */
    val isSensitiveStateActive: Flow<Boolean> =
        if (Flags.screenshareNotificationHiding()) {
            conflatedCallbackFlow {
                    val listener = Runnable { trySend(controller.isSensitiveStateActive) }
                    controller.registerSensitiveStateListener(listener)
                    trySend(controller.isSensitiveStateActive)
                    awaitClose { controller.unregisterSensitiveStateListener(listener) }
                }
                .distinctUntilChanged()
        } else {
            flowOf(false)
        }
}
