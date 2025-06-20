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

import com.android.systemui.bouncer.domain.interactor.bouncerInteractor
import com.android.systemui.dump.dumpManager
import com.android.systemui.keyguard.domain.interactor.keyguardInteractor
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.Kosmos.Fixture
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.shade.domain.interactor.shadeInteractor
import com.android.systemui.shade.domain.interactor.shadeModeInteractor
import com.android.systemui.statusbar.domain.interactor.remoteInputInteractor
import com.android.systemui.statusbar.notification.stack.domain.interactor.notificationStackAppearanceInteractor

val Kosmos.notificationScrollViewModel by Fixture {
    NotificationScrollViewModel(
        dumpManager = dumpManager,
        stackAppearanceInteractor = notificationStackAppearanceInteractor,
        shadeInteractor = shadeInteractor,
        shadeModeInteractor = shadeModeInteractor,
        bouncerInteractor = bouncerInteractor,
        remoteInputInteractor = remoteInputInteractor,
        sceneInteractor = sceneInteractor,
        keyguardInteractor = { keyguardInteractor },
    )
}
