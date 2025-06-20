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

package com.android.systemui.statusbar.pipeline.shared.ui.view

import android.content.Context
import android.graphics.Color
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import androidx.compose.ui.platform.ComposeView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.systemui.lifecycle.repeatWhenAttached
import com.android.systemui.res.R
import com.android.systemui.statusbar.StatusBarIconView
import com.android.systemui.statusbar.StatusBarIconView.STATE_HIDDEN
import com.android.systemui.statusbar.pipeline.shared.ui.binder.ModernStatusBarViewBinding
import com.android.systemui.statusbar.pipeline.shared.ui.binder.ModernStatusBarViewVisibilityHelper
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Compose view that is bound to bindable_status_bar_compose_icon.xml */
class SingleBindableStatusBarComposeIconView(context: Context, attrs: AttributeSet?) :
    ModernStatusBarView(context, attrs) {

    internal lateinit var composeView: ComposeView
    internal lateinit var dotView: StatusBarIconView

    override fun toString(): String {
        return "SingleBindableStatusBarComposeIcon(" +
            "slot='$slot', " +
            "isCollecting=${binding.isCollecting()}, " +
            "visibleState=${StatusBarIconView.getVisibleStateString(visibleState)}); " +
            "viewString=${super.toString()}"
    }

    override fun initView(slot: String, bindingCreator: () -> ModernStatusBarViewBinding) {
        super.initView(slot, bindingCreator)

        composeView = requireViewById(R.id.compose_view)
        dotView = requireViewById(R.id.status_bar_dot)
    }

    companion object {
        fun createView(context: Context): SingleBindableStatusBarComposeIconView {
            return LayoutInflater.from(context)
                .inflate(R.layout.bindable_status_bar_compose_icon, null)
                as SingleBindableStatusBarComposeIconView
        }

        /**
         * Using a given binding [block], create the necessary scaffolding to handle the general
         * case of a single status bar icon. This includes eliding into a dot view when there is not
         * enough space, and handling tint.
         *
         * [block] should be a simple [launch] call that handles updating the single icon view with
         * its new view. Currently there is no simple way to e.g., extend to handle multiple tints
         * for dual-layered icons, and any more complex logic should probably find a way to return
         * its own version of [ModernStatusBarViewBinding].
         */
        fun withDefaultBinding(
            view: SingleBindableStatusBarComposeIconView,
            shouldBeVisible: () -> Boolean,
            block: suspend LifecycleOwner.(View, StateFlow<Int>) -> Unit,
        ): ModernStatusBarViewBinding {
            @StatusBarIconView.VisibleState
            val visibilityState: MutableStateFlow<Int> = MutableStateFlow(STATE_HIDDEN)

            val iconTint: MutableStateFlow<Int> = MutableStateFlow(Color.WHITE)
            val decorTint: MutableStateFlow<Int> = MutableStateFlow(Color.WHITE)

            var isCollecting: Boolean = false

            view.repeatWhenAttached {
                // Child binding
                block(view, iconTint)

                lifecycleScope.launch {
                    repeatOnLifecycle(Lifecycle.State.STARTED) {
                        // isVisible controls the visibility state of the outer group, and thus it
                        // needs to run in the CREATED lifecycle so it can continue to watch while
                        // invisible. See (b/291031862) for details
                        launch {
                            visibilityState.collect { visibilityState ->
                                // for b/296864006, we can not hide all the child views if
                                // visibilityState is STATE_HIDDEN. Because hiding all child views
                                // would cause the getWidth() of this view return 0, and that would
                                // cause the translation calculation fails in StatusIconContainer.
                                // Therefore, like class MobileIconBinder, instead of set the child
                                // views visibility to View.GONE, we set their visibility to
                                // View.INVISIBLE to make them invisible but keep the width.
                                ModernStatusBarViewVisibilityHelper.setVisibilityState(
                                    visibilityState,
                                    view.composeView,
                                    view.dotView,
                                )
                            }
                        }

                        launch { iconTint.collect { tint -> view.dotView.setDecorColor(tint) } }

                        launch {
                            decorTint.collect { decorTint -> view.dotView.setDecorColor(decorTint) }
                        }

                        try {
                            awaitCancellation()
                        } finally {
                            isCollecting = false
                        }
                    }
                }
            }

            return object : ModernStatusBarViewBinding {
                override fun getShouldIconBeVisible(): Boolean {
                    return shouldBeVisible()
                }

                override fun onVisibilityStateChanged(state: Int) {
                    visibilityState.value = state
                }

                override fun onIconTintChanged(newTint: Int, contrastTint: Int) {
                    iconTint.value = newTint
                }

                override fun onDecorTintChanged(newTint: Int) {
                    decorTint.value = newTint
                }

                override fun isCollecting(): Boolean {
                    return isCollecting
                }
            }
        }
    }
}
