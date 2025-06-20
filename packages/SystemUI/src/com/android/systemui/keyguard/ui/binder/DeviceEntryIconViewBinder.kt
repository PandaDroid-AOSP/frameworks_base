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

package com.android.systemui.keyguard.ui.binder

import android.annotation.SuppressLint
import android.content.res.ColorStateList
import android.util.Log
import android.util.StateSet
import android.view.HapticFeedbackConstants
import android.view.View
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.core.view.isInvisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.systemui.Flags
import com.android.systemui.common.ui.view.TouchHandlingView
import com.android.systemui.keyguard.ui.view.DeviceEntryIconView
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryBackgroundViewModel
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryForegroundViewModel
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryIconViewModel
import com.android.systemui.lifecycle.repeatWhenAttached
import com.android.systemui.plugins.FalsingManager
import com.android.systemui.res.R
import com.android.systemui.statusbar.VibratorHelper
import com.android.systemui.util.kotlin.DisposableHandles
import com.google.android.msdl.data.model.MSDLToken
import com.google.android.msdl.domain.MSDLPlayer
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DisposableHandle

object DeviceEntryIconViewBinder {
    private const val TAG = "DeviceEntryIconViewBinder"

    /**
     * Updates UI for:
     * - device entry containing view (parent view for the below views)
     *     - touch handling view (transparent, no UI)
     *     - foreground icon view (lock/unlock/fingerprint)
     *     - background view (optional)
     */
    @SuppressLint("ClickableViewAccessibility")
    @JvmStatic
    fun bind(
        applicationScope: CoroutineScope,
        mainImmediateDispatcher: CoroutineDispatcher,
        view: DeviceEntryIconView,
        viewModel: DeviceEntryIconViewModel,
        fgViewModel: DeviceEntryForegroundViewModel,
        bgViewModel: DeviceEntryBackgroundViewModel,
        falsingManager: FalsingManager,
        vibratorHelper: VibratorHelper,
        msdlPlayer: MSDLPlayer,
        overrideColor: Color? = null,
    ): DisposableHandle {
        val disposables = DisposableHandles()
        val touchHandlingView = view.touchHandlingView
        val fgIconView = view.iconView
        val bgView = view.bgView
        touchHandlingView.listener =
            object : TouchHandlingView.Listener {
                override fun onLongPressDetected(
                    view: View,
                    x: Int,
                    y: Int,
                    isA11yAction: Boolean,
                ) {
                    if (
                        !isA11yAction && falsingManager.isFalseLongTap(FalsingManager.LOW_PENALTY)
                    ) {
                        Log.d(
                            TAG,
                            "Long press rejected because it is not a11yAction " +
                                "and it is a falseLongTap",
                        )
                        return
                    }
                    if (!Flags.msdlFeedback()) {
                        vibratorHelper.performHapticFeedback(view, HapticFeedbackConstants.CONFIRM)
                    }
                    applicationScope.launch {
                        view.clearFocus()
                        view.clearAccessibilityFocus()
                        viewModel.onUserInteraction()
                    }
                }
            }

        disposables +=
            view.repeatWhenAttached(mainImmediateDispatcher) {
                repeatOnLifecycle(Lifecycle.State.CREATED) {
                    launch("$TAG#viewModel.useBackgroundProtection") {
                        viewModel.useBackgroundProtection.collect { useBackgroundProtection ->
                            if (useBackgroundProtection) {
                                bgView.visibility = View.VISIBLE
                            } else {
                                bgView.visibility = View.GONE
                            }
                        }
                    }
                    launch("$TAG#viewModel.burnInOffsets") {
                        viewModel.burnInOffsets.collect { burnInOffsets ->
                            view.translationX = burnInOffsets.x.toFloat()
                            view.translationY = burnInOffsets.y.toFloat()
                            view.aodFpDrawable.progress = burnInOffsets.progress
                        }
                    }

                    launch("$TAG#viewModel.deviceEntryViewAlpha") {
                        viewModel.deviceEntryViewAlpha.collect { alpha -> view.alpha = alpha }
                    }
                }
            }

        disposables +=
            view.repeatWhenAttached {
                // Repeat on CREATED so that the view will always observe the entire
                // GONE => AOD transition (even though the view may not be visible until the middle
                // of the transition.
                repeatOnLifecycle(Lifecycle.State.CREATED) {
                    launch("$TAG#viewModel.isVisible") {
                        viewModel.isVisible.collect { isVisible ->
                            touchHandlingView.isInvisible = !isVisible
                            view.isClickable = isVisible
                        }
                    }
                    launch("$TAG#viewModel.isLongPressEnabled") {
                        viewModel.isLongPressEnabled.collect { isEnabled ->
                            touchHandlingView.setLongPressHandlingEnabled(isEnabled)
                        }
                    }
                    launch("$TAG#viewModel.isUdfpsSupported") {
                        viewModel.isUdfpsSupported.collect { udfpsSupported ->
                            touchHandlingView.longPressDuration =
                                if (udfpsSupported) {
                                    {
                                        view.resources
                                            .getInteger(
                                                R.integer.config_udfpsDeviceEntryIconLongPress
                                            )
                                            .toLong()
                                    }
                                } else {
                                    {
                                        view.resources
                                            .getInteger(R.integer.config_lockIconLongPress)
                                            .toLong()
                                    }
                                }
                        }
                    }
                    launch("$TAG#viewModel.accessibilityDelegateHint") {
                        viewModel.accessibilityDelegateHint.collect { hint ->
                            view.accessibilityHintType = hint
                            if (hint != DeviceEntryIconView.AccessibilityHintType.NONE) {
                                view.setOnClickListener {
                                    if (Flags.msdlFeedback()) {
                                        val token =
                                            if (
                                                hint ==
                                                    DeviceEntryIconView.AccessibilityHintType.ENTER
                                            ) {
                                                MSDLToken.UNLOCK
                                            } else {
                                                MSDLToken.LONG_PRESS
                                            }
                                        msdlPlayer.playToken(token)
                                    } else {
                                        vibratorHelper.performHapticFeedback(
                                            view,
                                            HapticFeedbackConstants.CONFIRM,
                                        )
                                    }
                                    applicationScope.launch {
                                        view.clearFocus()
                                        view.clearAccessibilityFocus()
                                        viewModel.onUserInteraction()
                                    }
                                }
                            } else {
                                view.setOnClickListener(null)
                            }
                        }
                    }

                    if (Flags.msdlFeedback()) {
                        launch("$TAG#viewModel.isPrimaryBouncerShowing") {
                            viewModel.deviceDidNotEnterFromDeviceEntryIcon.collect {
                                // If we did not enter from the icon, we did not play device entry
                                // haptics. Therefore, we play the token for long-press instead.
                                msdlPlayer.playToken(MSDLToken.LONG_PRESS)
                            }
                        }
                    }
                }
            }

        disposables +=
            fgIconView.repeatWhenAttached {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    // Start with an empty state
                    Log.d(TAG, "Initializing device entry fgIconView")
                    fgIconView.setImageState(StateSet.NOTHING, /* merge */ false)
                    launch("$TAG#fpIconView.viewModel") {
                        fgViewModel.viewModel.collect { viewModel ->
                            Log.d(TAG, "Updating device entry icon image state $viewModel")
                            if (viewModel.type.contentDescriptionResId != -1) {
                                fgIconView.contentDescription =
                                    fgIconView.resources.getString(
                                        viewModel.type.contentDescriptionResId
                                    )
                            }
                            fgIconView.imageTintList =
                                ColorStateList.valueOf(overrideColor?.toArgb() ?: viewModel.tint)
                            fgIconView.setPadding(
                                viewModel.padding,
                                viewModel.padding,
                                viewModel.padding,
                                viewModel.padding,
                            )
                            // Set image state at the end after updating other view state. This
                            // method forces the ImageView to recompute the bounds of the drawable.
                            fgIconView.setImageState(
                                view.getIconState(viewModel.type, viewModel.useAodVariant),
                                /* merge */ false,
                            )
                            // Invalidate, just in case the padding changes just after icon changes
                            fgIconView.invalidate()
                        }
                    }
                }
            }

        disposables +=
            bgView.repeatWhenAttached(mainImmediateDispatcher) {
                repeatOnLifecycle(Lifecycle.State.CREATED) {
                    launch("$TAG#bgViewModel.alpha") {
                        bgViewModel.alpha.collect { alpha -> bgView.alpha = alpha }
                    }
                    launch("$TAG#bgViewModel.color") {
                        bgViewModel.color.collect { color ->
                            bgView.imageTintList = ColorStateList.valueOf(color)
                        }
                    }
                }
            }

        return disposables
    }
}
