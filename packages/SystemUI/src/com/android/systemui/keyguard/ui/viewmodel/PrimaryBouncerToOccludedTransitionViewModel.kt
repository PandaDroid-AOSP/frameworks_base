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

package com.android.systemui.keyguard.ui.viewmodel

import com.android.systemui.Flags
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.keyguard.domain.interactor.FromPrimaryBouncerTransitionInteractor
import com.android.systemui.keyguard.shared.model.Edge
import com.android.systemui.keyguard.shared.model.KeyguardState.OCCLUDED
import com.android.systemui.keyguard.shared.model.KeyguardState.PRIMARY_BOUNCER
import com.android.systemui.keyguard.ui.KeyguardTransitionAnimationFlow
import com.android.systemui.keyguard.ui.transitions.BlurConfig
import com.android.systemui.keyguard.ui.transitions.PrimaryBouncerTransition
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow

@SysUISingleton
class PrimaryBouncerToOccludedTransitionViewModel
@Inject
constructor(
    shadeDependentFlows: ShadeDependentFlows,
    blurConfig: BlurConfig,
    animationFlow: KeyguardTransitionAnimationFlow,
) : PrimaryBouncerTransition {
    private val transitionAnimation =
        animationFlow
            .setup(
                duration = FromPrimaryBouncerTransitionInteractor.TO_OCCLUDED_DURATION,
                edge = Edge.INVALID,
            )
            .setupWithoutSceneContainer(edge = Edge.create(PRIMARY_BOUNCER, OCCLUDED))

    override val windowBlurRadius: Flow<Float> =
        shadeDependentFlows.transitionFlow(
            flowWhenShadeIsExpanded =
                if (Flags.notificationShadeBlur()) {
                    transitionAnimation.immediatelyTransitionTo(blurConfig.maxBlurRadiusPx)
                } else {
                    transitionAnimation.immediatelyTransitionTo(blurConfig.minBlurRadiusPx)
                },
            flowWhenShadeIsNotExpanded =
                transitionAnimation.immediatelyTransitionTo(blurConfig.minBlurRadiusPx),
        )

    override val notificationBlurRadius: Flow<Float> =
        transitionAnimation.immediatelyTransitionTo(0.0f)
}
