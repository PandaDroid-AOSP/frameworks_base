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

package com.android.systemui.keyguard.domain.interactor

import com.android.keyguard.logging.KeyguardLogger
import com.android.systemui.bouncer.domain.interactor.primaryBouncerInteractor
import com.android.systemui.deviceentry.domain.interactor.deviceUnlockedInteractor
import com.android.systemui.keyguard.data.repository.keyguardRepository
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.testScope
import com.android.systemui.log.logcatLogBuffer
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.shade.domain.interactor.shadeInteractor

val Kosmos.keyguardDismissActionInteractor by
    Kosmos.Fixture {
        KeyguardDismissActionInteractor(
            repository = keyguardRepository,
            transitionInteractor = keyguardTransitionInteractor,
            dismissInteractor = keyguardDismissInteractor,
            applicationScope = testScope.backgroundScope,
            deviceUnlockedInteractor = { deviceUnlockedInteractor },
            shadeInteractor = { shadeInteractor },
            keyguardInteractor = { keyguardInteractor },
            sceneInteractor = { sceneInteractor },
            keyguardLogger = KeyguardLogger(logcatLogBuffer("keyguard-logger-for-test")),
            primaryBouncerInteractor = primaryBouncerInteractor,
        )
    }
