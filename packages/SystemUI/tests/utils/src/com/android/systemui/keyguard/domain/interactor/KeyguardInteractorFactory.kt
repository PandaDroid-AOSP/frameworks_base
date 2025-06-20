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
 *
 */

package com.android.systemui.keyguard.domain.interactor

import com.android.systemui.bouncer.data.repository.FakeKeyguardBouncerRepository
import com.android.systemui.common.ui.data.repository.FakeConfigurationRepository
import com.android.systemui.common.ui.domain.interactor.ConfigurationInteractorImpl
import com.android.systemui.flags.FakeFeatureFlags
import com.android.systemui.keyguard.data.repository.FakeKeyguardRepository
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.scene.domain.interactor.SceneInteractor
import com.android.systemui.shade.data.repository.FakeShadeRepository
import com.android.systemui.util.mockito.mock
import com.android.systemui.util.mockito.whenever
import com.android.systemui.wallpapers.data.repository.FakeWallpaperFocalAreaRepository
import com.android.systemui.wallpapers.data.repository.WallpaperFocalAreaRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import org.mockito.kotlin.any

/**
 * Simply put, I got tired of adding a constructor argument and then having to tweak dozens of
 * files. This should alleviate some of the burden by providing defaults for testing.
 */
object KeyguardInteractorFactory {

    @JvmOverloads
    @JvmStatic
    fun create(
        featureFlags: FakeFeatureFlags = FakeFeatureFlags(),
        repository: FakeKeyguardRepository = FakeKeyguardRepository(),
        bouncerRepository: FakeKeyguardBouncerRepository = FakeKeyguardBouncerRepository(),
        configurationRepository: FakeConfigurationRepository = FakeConfigurationRepository(),
        shadeRepository: FakeShadeRepository = FakeShadeRepository(),
        wallpaperFocalAreaRepository: WallpaperFocalAreaRepository =
            FakeWallpaperFocalAreaRepository(),
        sceneInteractor: SceneInteractor = mock(),
        fromGoneTransitionInteractor: FromGoneTransitionInteractor = mock(),
        fromLockscreenTransitionInteractor: FromLockscreenTransitionInteractor = mock(),
        fromOccludedTransitionInteractor: FromOccludedTransitionInteractor = mock(),
        fromAlternateBouncerTransitionInteractor: FromAlternateBouncerTransitionInteractor = mock(),
        testScope: CoroutineScope = TestScope(),
    ): WithDependencies {
        // Mock these until they are replaced by kosmos
        val currentKeyguardStateFlow = MutableSharedFlow<KeyguardState>()
        val transitionStateFlow = MutableStateFlow(TransitionStep())
        val keyguardTransitionInteractor =
            mock<KeyguardTransitionInteractor>().also {
                whenever(it.currentKeyguardState).thenReturn(currentKeyguardStateFlow)
                whenever(it.transitionState).thenReturn(transitionStateFlow)
                whenever(it.isFinishedIn(any(), any())).thenReturn(MutableStateFlow(false))
            }
        return WithDependencies(
            repository = repository,
            featureFlags = featureFlags,
            bouncerRepository = bouncerRepository,
            configurationRepository = configurationRepository,
            shadeRepository = shadeRepository,
            KeyguardInteractor(
                repository = repository,
                bouncerRepository = bouncerRepository,
                configurationInteractor = ConfigurationInteractorImpl(configurationRepository),
                shadeRepository = shadeRepository,
                keyguardTransitionInteractor = keyguardTransitionInteractor,
                sceneInteractorProvider = { sceneInteractor },
                fromGoneTransitionInteractor = { fromGoneTransitionInteractor },
                fromLockscreenTransitionInteractor = { fromLockscreenTransitionInteractor },
                fromOccludedTransitionInteractor = { fromOccludedTransitionInteractor },
                fromAlternateBouncerTransitionInteractor = {
                    fromAlternateBouncerTransitionInteractor
                },
                applicationScope = testScope,
                wallpaperFocalAreaRepository = wallpaperFocalAreaRepository,
            ),
        )
    }

    data class WithDependencies(
        val repository: FakeKeyguardRepository,
        val featureFlags: FakeFeatureFlags,
        val bouncerRepository: FakeKeyguardBouncerRepository,
        val configurationRepository: FakeConfigurationRepository,
        val shadeRepository: FakeShadeRepository,
        val keyguardInteractor: KeyguardInteractor,
    )
}
