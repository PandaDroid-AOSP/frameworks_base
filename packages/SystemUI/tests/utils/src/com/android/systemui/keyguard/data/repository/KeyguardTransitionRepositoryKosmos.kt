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

package com.android.systemui.keyguard.data.repository

import com.android.systemui.keyguard.shared.transition.keyguardTransitionAnimationCallbackDelegator
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.kosmos.testScope
import org.mockito.Mockito.spy

var Kosmos.keyguardTransitionRepository: KeyguardTransitionRepository by
    Kosmos.Fixture { fakeKeyguardTransitionRepository }
var Kosmos.fakeKeyguardTransitionRepository by
    Kosmos.Fixture { FakeKeyguardTransitionRepository(testScope = testScope) }
var Kosmos.fakeKeyguardTransitionRepositorySpy: FakeKeyguardTransitionRepository by
    Kosmos.Fixture { spy(fakeKeyguardTransitionRepository) }
var Kosmos.realKeyguardTransitionRepository: KeyguardTransitionRepository by
    Kosmos.Fixture {
        KeyguardTransitionRepositoryImpl(
            testDispatcher,
            keyguardTransitionAnimationCallbackDelegator,
        )
    }
