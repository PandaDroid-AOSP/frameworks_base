/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.systemui.keyguard.ui.binder

import android.transition.TransitionManager
import android.transition.TransitionSet
import android.view.View.INVISIBLE
import android.view.ViewGroup
import androidx.annotation.VisibleForTesting
import androidx.constraintlayout.helper.widget.Layer
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.constraintlayout.widget.ConstraintSet
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.systemui.keyguard.domain.interactor.KeyguardBlueprintInteractor
import com.android.systemui.keyguard.domain.interactor.KeyguardClockInteractor
import com.android.systemui.keyguard.shared.model.ClockSize
import com.android.systemui.keyguard.ui.view.layout.blueprints.transitions.IntraBlueprintTransition.Type
import com.android.systemui.keyguard.ui.view.layout.sections.ClockSection
import com.android.systemui.keyguard.ui.viewmodel.AodBurnInViewModel
import com.android.systemui.keyguard.ui.viewmodel.KeyguardClockViewModel
import com.android.systemui.keyguard.ui.viewmodel.KeyguardRootViewModel
import com.android.systemui.lifecycle.repeatWhenAttached
import com.android.systemui.plugins.clocks.AodClockBurnInModel
import com.android.systemui.plugins.clocks.ClockController
import com.android.systemui.util.kotlin.DisposableHandles
import com.android.systemui.util.ui.value
import kotlinx.coroutines.DisposableHandle
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

object KeyguardClockViewBinder {
    private val TAG = KeyguardClockViewBinder::class.simpleName!!

    @JvmStatic
    fun bind(
        clockSection: ClockSection,
        keyguardRootView: ConstraintLayout,
        viewModel: KeyguardClockViewModel,
        keyguardClockInteractor: KeyguardClockInteractor,
        blueprintInteractor: KeyguardBlueprintInteractor,
        rootViewModel: KeyguardRootViewModel,
        aodBurnInViewModel: AodBurnInViewModel,
    ): DisposableHandle {
        val disposables = DisposableHandles()
        disposables +=
            keyguardRootView.repeatWhenAttached {
                repeatOnLifecycle(Lifecycle.State.CREATED) {
                    keyguardClockInteractor.clockEventController.registerListeners(keyguardRootView)
                }
            }

        disposables +=
            keyguardRootView.repeatWhenAttached {
                repeatOnLifecycle(Lifecycle.State.CREATED) {
                    // When changing to new clock, we need to remove old views from burnInLayer
                    var lastClock: ClockController? = null
                    launch {
                        viewModel.currentClock.collect { currentClock ->
                            if (lastClock != currentClock) {
                                cleanupClockViews(
                                    lastClock,
                                    keyguardRootView,
                                    viewModel.burnInLayer,
                                )
                                lastClock = currentClock
                            }

                            addClockViews(currentClock, keyguardRootView)
                            updateBurnInLayer(
                                keyguardRootView,
                                viewModel,
                                viewModel.clockSize.value,
                            )
                            applyConstraints(clockSection, keyguardRootView, true)
                        }
                    }
                        .invokeOnCompletion {
                            cleanupClockViews(lastClock, keyguardRootView, viewModel.burnInLayer)
                            lastClock = null
                        }

                    launch {
                        viewModel.clockSize.collect { clockSize ->
                            updateBurnInLayer(keyguardRootView, viewModel, clockSize)
                            blueprintInteractor.refreshBlueprint(Type.ClockSize)
                        }
                    }

                    launch {
                        viewModel.clockShouldBeCentered.collect {
                            viewModel.currentClock.value?.let {
                                if (it.largeClock.config.hasCustomPositionUpdatedAnimation) {
                                    blueprintInteractor.refreshBlueprint(Type.DefaultClockStepping)
                                } else {
                                    blueprintInteractor.refreshBlueprint(Type.DefaultTransition)
                                }
                            }
                        }
                    }

                    launch {
                        combine(
                            viewModel.hasAodIcons,
                            rootViewModel.isNotifIconContainerVisible.map { it.value },
                        ) { hasIcon, isVisible ->
                            hasIcon && isVisible
                        }
                            .distinctUntilChanged()
                            .collect { _ ->
                                viewModel.currentClock.value?.let {
                                    if (it.config.useCustomClockScene) {
                                        blueprintInteractor.refreshBlueprint(Type.DefaultTransition)
                                    }
                                }
                            }
                    }

                    launch {
                        aodBurnInViewModel.movement.collect { burnInModel ->
                            viewModel.currentClock.value
                                ?.largeClock
                                ?.layout
                                ?.applyAodBurnIn(
                                    AodClockBurnInModel(
                                        translationX = burnInModel.translationX.toFloat(),
                                        translationY = burnInModel.translationY.toFloat(),
                                        scale = burnInModel.scale,
                                    )
                                )
                        }
                    }

                    launch {
                        viewModel.largeClockTextSize.collect { fontSizePx ->
                            viewModel.currentClock.value
                                ?.largeClock
                                ?.events
                                ?.onFontSettingChanged(fontSizePx = fontSizePx.toFloat())
                        }
                    }
                }
            }

        disposables +=
            keyguardRootView.repeatWhenAttached {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    viewModel.currentClock.collect { currentClock ->
                        currentClock?.apply {
                            smallClock.run { events.onThemeChanged(theme) }
                            largeClock.run { events.onThemeChanged(theme) }
                        }
                    }
                }
            }

        return disposables
    }

    @VisibleForTesting
    fun updateBurnInLayer(
        keyguardRootView: ConstraintLayout,
        viewModel: KeyguardClockViewModel,
        clockSize: ClockSize,
    ) {
        val burnInLayer = viewModel.burnInLayer
        val clockController = viewModel.currentClock.value
        // Large clocks won't be added to or removed from burn in layer
        // Weather large clock has customized burn in preventing mechanism
        // Non-weather large clock will only scale and translate vertically
        clockController?.let { clock ->
            when (clockSize) {
                ClockSize.LARGE -> {
                    clock.smallClock.layout.views.forEach { burnInLayer?.removeView(it) }
                }
                ClockSize.SMALL -> {
                    clock.smallClock.layout.views.forEach { burnInLayer?.addView(it) }
                }
            }
        }
        viewModel.burnInLayer?.updatePostLayout(keyguardRootView)
    }

    fun cleanupClockViews(
        lastClock: ClockController?,
        rootView: ConstraintLayout,
        burnInLayer: Layer?,
    ) {
        lastClock?.run {
            smallClock.layout.views.forEach {
                burnInLayer?.removeView(it)
                rootView.removeView(it)
            }
            largeClock.layout.views.forEach { rootView.removeView(it) }
        }
    }

    @VisibleForTesting
    fun addClockViews(clockController: ClockController?, rootView: ConstraintLayout) {
        // We'll collect the same clock when exiting wallpaper picker without changing clock
        // so we need to remove clock views from parent before addView again
        clockController?.let { clock ->
            clock.smallClock.layout.views.forEach {
                if (it.parent != null) {
                    (it.parent as ViewGroup).removeView(it)
                }
                rootView.addView(it).apply { it.visibility = INVISIBLE }
            }
            clock.largeClock.layout.views.forEach {
                if (it.parent != null) {
                    (it.parent as ViewGroup).removeView(it)
                }
                rootView.addView(it).apply { it.visibility = INVISIBLE }
            }
        }
    }

    fun applyConstraints(
        clockSection: ClockSection,
        rootView: ConstraintLayout,
        animated: Boolean,
        set: TransitionSet? = null,
    ) {
        val constraintSet = ConstraintSet().apply { clone(rootView) }
        clockSection.applyConstraints(constraintSet)
        if (animated) {
            set?.let { TransitionManager.beginDelayedTransition(rootView, it) }
                ?: run { TransitionManager.beginDelayedTransition(rootView) }
        }
        constraintSet.applyTo(rootView)
    }
}
