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

import android.app.admin.devicePolicyManager
import android.content.applicationContext
import android.view.accessibility.AccessibilityManager
import com.android.internal.widget.lockPatternUtils
import com.android.keyguard.logging.KeyguardQuickAffordancesLogger
import com.android.systemui.animation.dialogTransitionAnimator
import com.android.systemui.dock.dockManager
import com.android.systemui.flags.featureFlagsClassic
import com.android.systemui.keyguard.data.repository.biometricSettingsRepository
import com.android.systemui.keyguard.data.repository.keyguardQuickAffordanceRepository
import com.android.systemui.keyguard.shared.quickaffordance.KeyguardQuickAffordancesMetricsLogger
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.Kosmos.Fixture
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.plugins.activityStarter
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.settings.userTracker
import com.android.systemui.shade.domain.interactor.shadeInteractor
import com.android.systemui.statusbar.policy.keyguardStateController
import org.mockito.kotlin.mock

var Kosmos.keyguardQuickAffordanceInteractor by Fixture {
    KeyguardQuickAffordanceInteractor(
        keyguardInteractor = keyguardInteractor,
        shadeInteractor = shadeInteractor,
        lockPatternUtils = lockPatternUtils,
        keyguardStateController = keyguardStateController,
        userTracker = userTracker,
        activityStarter = activityStarter,
        featureFlags = featureFlagsClassic,
        repository = { keyguardQuickAffordanceRepository },
        launchAnimator = dialogTransitionAnimator,
        logger = mock<KeyguardQuickAffordancesLogger>(),
        metricsLogger = mock<KeyguardQuickAffordancesMetricsLogger>(),
        devicePolicyManager = devicePolicyManager,
        dockManager = dockManager,
        biometricSettingsRepository = biometricSettingsRepository,
        accessibilityManager = mock<AccessibilityManager>(),
        backgroundDispatcher = testDispatcher,
        appContext = applicationContext,
        sceneInteractor = { sceneInteractor },
    )
}
