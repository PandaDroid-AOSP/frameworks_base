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

package com.android.systemui.keyguard.ui.composable.blueprint

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.dp
import com.android.compose.animation.scene.ContentScope
import com.android.compose.modifiers.padding
import com.android.systemui.compose.modifiers.sysuiResTag
import com.android.systemui.keyguard.ui.composable.LockscreenLongPress
import com.android.systemui.keyguard.ui.composable.section.AmbientIndicationSection
import com.android.systemui.keyguard.ui.composable.section.BottomAreaSection
import com.android.systemui.keyguard.ui.composable.section.LockSection
import com.android.systemui.keyguard.ui.composable.section.NotificationSection
import com.android.systemui.keyguard.ui.composable.section.SettingsMenuSection
import com.android.systemui.keyguard.ui.composable.section.StatusBarSection
import com.android.systemui.keyguard.ui.composable.section.TopAreaSection
import com.android.systemui.keyguard.ui.viewmodel.LockscreenContentViewModel
import com.android.systemui.keyguard.ui.viewmodel.LockscreenContentViewModel.NotificationsPlacement.BelowClock
import com.android.systemui.keyguard.ui.viewmodel.LockscreenContentViewModel.NotificationsPlacement.BesideClock
import com.android.systemui.res.R
import java.util.Optional
import javax.inject.Inject
import kotlin.math.roundToInt

/**
 * Renders the lockscreen scene when showing with the default layout (e.g. vertical phone form
 * factor).
 */
class DefaultBlueprint
@Inject
constructor(
    private val statusBarSection: StatusBarSection,
    private val lockSection: LockSection,
    private val ambientIndicationSectionOptional: Optional<AmbientIndicationSection>,
    private val bottomAreaSection: BottomAreaSection,
    private val settingsMenuSection: SettingsMenuSection,
    private val topAreaSection: TopAreaSection,
    private val notificationSection: NotificationSection,
) : ComposableLockscreenSceneBlueprint {

    override val id: String = "default"

    @Composable
    override fun ContentScope.Content(viewModel: LockscreenContentViewModel, modifier: Modifier) {
        val isUdfpsVisible = viewModel.isUdfpsVisible
        val isBypassEnabled = viewModel.isBypassEnabled
        val notificationsPlacement = viewModel.notificationsPlacement

        if (isBypassEnabled) {
            with(notificationSection) { HeadsUpNotifications() }
        }

        LockscreenLongPress(viewModel = viewModel.touchHandling, modifier = modifier) {
            onSettingsMenuPlaced ->
            Layout(
                content = {
                    // Constrained to above the lock icon.
                    Column(modifier = Modifier.fillMaxSize()) {
                        with(statusBarSection) {
                            StatusBar(
                                modifier =
                                    Modifier.fillMaxWidth()
                                        .padding(
                                            horizontal = {
                                                viewModel.unfoldTranslations.start.roundToInt()
                                            }
                                        )
                            )
                        }

                        Box(modifier = Modifier.fillMaxWidth()) {
                            with(topAreaSection) {
                                DefaultClockLayout(
                                    smartSpacePaddingTop = viewModel::getSmartSpacePaddingTop,
                                    modifier =
                                        Modifier.fillMaxWidth().graphicsLayer {
                                            translationX = viewModel.unfoldTranslations.start
                                        },
                                )
                            }
                            if (notificationsPlacement is BesideClock && !isBypassEnabled) {
                                with(notificationSection) {
                                    Box(modifier = Modifier.fillMaxHeight()) {
                                        AodPromotedNotificationArea(
                                            modifier =
                                                Modifier.fillMaxWidth(0.5f)
                                                    .align(notificationsPlacement.alignment)
                                        )
                                        Notifications(
                                            areNotificationsVisible =
                                                viewModel.areNotificationsVisible,
                                            burnInParams = null,
                                            modifier =
                                                Modifier.fillMaxWidth(0.5f)
                                                    .fillMaxHeight()
                                                    .align(notificationsPlacement.alignment)
                                                    .padding(top = 12.dp),
                                        )
                                    }
                                }
                            }
                        }

                        // Not a mistake; reusing below_clock_padding_start_icons as AOD RON top
                        // padding for now.
                        val aodPromotedNotifTopPadding: Dp =
                            dimensionResource(R.dimen.below_clock_padding_start_icons)
                        val aodIconPadding: Dp =
                            dimensionResource(R.dimen.below_clock_padding_start_icons)

                        with(notificationSection) {
                            if (notificationsPlacement is BelowClock && !isBypassEnabled) {
                                Box(modifier = Modifier.weight(weight = 1f)) {
                                    Column(Modifier.align(alignment = Alignment.TopStart)) {
                                        AodPromotedNotificationArea(
                                            modifier =
                                                Modifier.padding(top = aodPromotedNotifTopPadding)
                                        )
                                        AodNotificationIcons(
                                            modifier = Modifier.padding(start = aodIconPadding)
                                        )
                                    }
                                    Notifications(
                                        areNotificationsVisible = viewModel.areNotificationsVisible,
                                        burnInParams = null,
                                    )
                                }
                            } else {
                                Column {
                                    if (viewModel.notificationsPlacement is BelowClock) {
                                        AodPromotedNotificationArea(
                                            modifier =
                                                Modifier.padding(top = aodPromotedNotifTopPadding)
                                        )
                                    }
                                    AodNotificationIcons(
                                        modifier =
                                            Modifier.padding(
                                                top =
                                                    dimensionResource(
                                                        R.dimen.keyguard_status_view_bottom_margin
                                                    ),
                                                start = aodIconPadding,
                                            )
                                    )
                                }
                            }
                        }
                        if (!isUdfpsVisible && ambientIndicationSectionOptional.isPresent) {
                            with(ambientIndicationSectionOptional.get()) {
                                AmbientIndication(modifier = Modifier.fillMaxWidth())
                            }
                        }
                    }

                    with(lockSection) { LockIcon() }

                    // Aligned to bottom and constrained to below the lock icon.
                    // TODO("b/383588832") change this away from "keyguard_bottom_area"
                    Column(modifier = Modifier.fillMaxWidth().sysuiResTag("keyguard_bottom_area")) {
                        if (isUdfpsVisible && ambientIndicationSectionOptional.isPresent) {
                            with(ambientIndicationSectionOptional.get()) {
                                AmbientIndication(modifier = Modifier.fillMaxWidth())
                            }
                        }

                        with(bottomAreaSection) {
                            IndicationArea(modifier = Modifier.fillMaxWidth())
                        }
                    }

                    // Aligned to bottom and NOT constrained by the lock icon.
                    with(bottomAreaSection) {
                        Shortcut(
                            isStart = true,
                            applyPadding = true,
                            modifier =
                                Modifier.graphicsLayer {
                                    translationX = viewModel.unfoldTranslations.start
                                },
                        )
                        Shortcut(
                            isStart = false,
                            applyPadding = true,
                            modifier =
                                Modifier.graphicsLayer {
                                    translationX = viewModel.unfoldTranslations.end
                                },
                        )
                    }
                    with(settingsMenuSection) { SettingsMenu(onSettingsMenuPlaced) }
                },
                modifier = Modifier.fillMaxSize(),
            ) { measurables, constraints ->
                check(measurables.size == 6) { "Expected 6 measurables, got: ${measurables.size}" }
                val aboveLockIconMeasurable = measurables[0]
                val lockIconMeasurable = measurables[1]
                val belowLockIconMeasurable = measurables[2]
                val startShortcutMeasurable = measurables[3]
                val endShortcutMeasurable = measurables[4]
                val settingsMenuMeasurable = measurables[5]

                val noMinConstraints = constraints.copy(minWidth = 0, minHeight = 0)
                val lockIconPlaceable = lockIconMeasurable.measure(noMinConstraints)
                val lockIconBounds =
                    IntRect(
                        left = lockIconPlaceable[BlueprintAlignmentLines.LockIcon.Left],
                        top = lockIconPlaceable[BlueprintAlignmentLines.LockIcon.Top],
                        right = lockIconPlaceable[BlueprintAlignmentLines.LockIcon.Right],
                        bottom = lockIconPlaceable[BlueprintAlignmentLines.LockIcon.Bottom],
                    )

                val aboveLockIconPlaceable =
                    aboveLockIconMeasurable.measure(
                        noMinConstraints.copy(maxHeight = lockIconBounds.top)
                    )
                val belowLockIconPlaceable =
                    belowLockIconMeasurable.measure(
                        noMinConstraints.copy(
                            maxHeight =
                                (constraints.maxHeight - lockIconBounds.bottom).coerceAtLeast(0)
                        )
                    )
                val startShortcutPleaceable = startShortcutMeasurable.measure(noMinConstraints)
                val endShortcutPleaceable = endShortcutMeasurable.measure(noMinConstraints)
                val settingsMenuPlaceable = settingsMenuMeasurable.measure(noMinConstraints)

                layout(constraints.maxWidth, constraints.maxHeight) {
                    aboveLockIconPlaceable.place(x = 0, y = 0)
                    lockIconPlaceable.place(x = lockIconBounds.left, y = lockIconBounds.top)
                    belowLockIconPlaceable.place(
                        x = 0,
                        y = constraints.maxHeight - belowLockIconPlaceable.height,
                    )
                    startShortcutPleaceable.place(
                        x = 0,
                        y = constraints.maxHeight - startShortcutPleaceable.height,
                    )
                    endShortcutPleaceable.place(
                        x = constraints.maxWidth - endShortcutPleaceable.width,
                        y = constraints.maxHeight - endShortcutPleaceable.height,
                    )
                    settingsMenuPlaceable.place(
                        x = (constraints.maxWidth - settingsMenuPlaceable.width) / 2,
                        y = constraints.maxHeight - settingsMenuPlaceable.height,
                    )
                }
            }
        }
    }
}
