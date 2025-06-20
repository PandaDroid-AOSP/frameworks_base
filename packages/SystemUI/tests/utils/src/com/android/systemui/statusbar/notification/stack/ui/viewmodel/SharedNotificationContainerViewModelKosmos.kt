/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.statusbar.notification.stack.ui.viewmodel

import android.content.applicationContext
import com.android.systemui.bouncer.domain.interactor.bouncerInteractor
import com.android.systemui.common.ui.domain.interactor.configurationInteractor
import com.android.systemui.communal.domain.interactor.communalSceneInteractor
import com.android.systemui.dump.dumpManager
import com.android.systemui.keyguard.domain.interactor.keyguardInteractor
import com.android.systemui.keyguard.domain.interactor.keyguardTransitionInteractor
import com.android.systemui.keyguard.ui.viewmodel.alternateBouncerToGoneTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.alternateBouncerToPrimaryBouncerTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodBurnInViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodToGlanceableHubTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodToGoneTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodToOccludedTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.aodToPrimaryBouncerTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.dozingToGlanceableHubTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.dozingToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.dozingToOccludedTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.dozingToPrimaryBouncerTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.dreamingToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.glanceableHubToAodTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.glanceableHubToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.goneToAodTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.goneToDozingTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.goneToDreamingTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.goneToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.lockscreenToDreamingTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.lockscreenToGlanceableHubTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.lockscreenToGoneTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.lockscreenToOccludedTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.lockscreenToPrimaryBouncerTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.occludedToAodTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.occludedToGoneTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.occludedToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.offToLockscreenTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.primaryBouncerToGoneTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.primaryBouncerToLockscreenTransitionViewModel
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.Kosmos.Fixture
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.shade.domain.interactor.shadeInteractor
import com.android.systemui.shade.domain.interactor.shadeModeInteractor
import com.android.systemui.shade.largeScreenHeaderHelper
import com.android.systemui.statusbar.notification.stack.domain.interactor.headsUpNotificationInteractor
import com.android.systemui.statusbar.notification.stack.domain.interactor.notificationStackAppearanceInteractor
import com.android.systemui.statusbar.notification.stack.domain.interactor.sharedNotificationContainerInteractor
import com.android.systemui.unfold.domain.interactor.unfoldTransitionInteractor
import com.android.systemui.window.ui.viewmodel.fakeBouncerTransitions

val Kosmos.sharedNotificationContainerViewModel by Fixture {
    SharedNotificationContainerViewModel(
        interactor = sharedNotificationContainerInteractor,
        dumpManager = dumpManager,
        applicationScope = applicationCoroutineScope,
        context = applicationContext,
        configurationInteractor = configurationInteractor,
        keyguardInteractor = keyguardInteractor,
        keyguardTransitionInteractor = keyguardTransitionInteractor,
        shadeInteractor = shadeInteractor,
        bouncerInteractor = bouncerInteractor,
        shadeModeInteractor = shadeModeInteractor,
        notificationStackAppearanceInteractor = notificationStackAppearanceInteractor,
        alternateBouncerToGoneTransitionViewModel = alternateBouncerToGoneTransitionViewModel,
        alternateBouncerToPrimaryBouncerTransitionViewModel =
            alternateBouncerToPrimaryBouncerTransitionViewModel,
        aodToGoneTransitionViewModel = aodToGoneTransitionViewModel,
        aodToLockscreenTransitionViewModel = aodToLockscreenTransitionViewModel,
        aodToOccludedTransitionViewModel = aodToOccludedTransitionViewModel,
        aodToPrimaryBouncerTransitionViewModel = aodToPrimaryBouncerTransitionViewModel,
        dozingToGlanceableHubTransitionViewModel = dozingToGlanceableHubTransitionViewModel,
        dozingToLockscreenTransitionViewModel = dozingToLockscreenTransitionViewModel,
        dozingToOccludedTransitionViewModel = dozingToOccludedTransitionViewModel,
        dozingToPrimaryBouncerTransitionViewModel = dozingToPrimaryBouncerTransitionViewModel,
        dreamingToLockscreenTransitionViewModel = dreamingToLockscreenTransitionViewModel,
        goneToAodTransitionViewModel = goneToAodTransitionViewModel,
        goneToDozingTransitionViewModel = goneToDozingTransitionViewModel,
        goneToDreamingTransitionViewModel = goneToDreamingTransitionViewModel,
        goneToLockscreenTransitionViewModel = goneToLockscreenTransitionViewModel,
        glanceableHubToLockscreenTransitionViewModel = glanceableHubToLockscreenTransitionViewModel,
        lockscreenToDreamingTransitionViewModel = lockscreenToDreamingTransitionViewModel,
        lockscreenToGlanceableHubTransitionViewModel = lockscreenToGlanceableHubTransitionViewModel,
        lockscreenToGoneTransitionViewModel = lockscreenToGoneTransitionViewModel,
        lockscreenToOccludedTransitionViewModel = lockscreenToOccludedTransitionViewModel,
        lockscreenToPrimaryBouncerTransitionViewModel =
            lockscreenToPrimaryBouncerTransitionViewModel,
        occludedToAodTransitionViewModel = occludedToAodTransitionViewModel,
        occludedToGoneTransitionViewModel = occludedToGoneTransitionViewModel,
        occludedToLockscreenTransitionViewModel = occludedToLockscreenTransitionViewModel,
        offToLockscreenTransitionViewModel = offToLockscreenTransitionViewModel,
        primaryBouncerToGoneTransitionViewModel = primaryBouncerToGoneTransitionViewModel,
        primaryBouncerToLockscreenTransitionViewModel =
            primaryBouncerToLockscreenTransitionViewModel,
        primaryBouncerTransitions = fakeBouncerTransitions,
        aodBurnInViewModel = aodBurnInViewModel,
        communalSceneInteractor = communalSceneInteractor,
        headsUpNotificationInteractor = { headsUpNotificationInteractor },
        largeScreenHeaderHelperLazy = { largeScreenHeaderHelper },
        unfoldTransitionInteractor = unfoldTransitionInteractor,
        glanceableHubToAodTransitionViewModel = glanceableHubToAodTransitionViewModel,
        aodToGlanceableHubTransitionViewModel = aodToGlanceableHubTransitionViewModel,
    )
}
