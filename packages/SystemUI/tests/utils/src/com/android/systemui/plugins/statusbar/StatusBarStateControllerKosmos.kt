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

package com.android.systemui.plugins.statusbar

import com.android.internal.logging.uiEventLogger
import com.android.systemui.bouncer.domain.interactor.alternateBouncerInteractor
import com.android.systemui.deviceentry.domain.interactor.deviceUnlockedInteractor
import com.android.systemui.keyguard.domain.interactor.keyguardClockInteractor
import com.android.systemui.keyguard.domain.interactor.keyguardInteractor
import com.android.systemui.keyguard.domain.interactor.keyguardTransitionInteractor
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.scene.domain.interactor.sceneBackInteractor
import com.android.systemui.scene.domain.interactor.sceneContainerOcclusionInteractor
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.shade.domain.interactor.shadeInteractor
import com.android.systemui.statusbar.FakeStatusBarStateController
import com.android.systemui.statusbar.StatusBarStateControllerImpl
import com.android.systemui.statusbar.SysuiStatusBarStateController
import com.android.systemui.util.mockito.mock

var Kosmos.statusBarStateController: SysuiStatusBarStateController by
    Kosmos.Fixture {
        StatusBarStateControllerImpl(
            uiEventLogger,
            mock(),
            { keyguardInteractor },
            { keyguardTransitionInteractor },
            { shadeInteractor },
            { deviceUnlockedInteractor },
            { sceneInteractor },
            { sceneContainerOcclusionInteractor },
            { keyguardClockInteractor },
            { sceneBackInteractor },
            { alternateBouncerInteractor },
        )
    }

var Kosmos.fakeStatusBarStateController: SysuiStatusBarStateController by
    Kosmos.Fixture { FakeStatusBarStateController() }
