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

package com.android.systemui.statusbar.chips.ui.viewmodel

import android.view.View
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.internal.jank.Cuj
import com.android.internal.logging.InstanceId
import com.android.systemui.SysuiTestCase
import com.android.systemui.animation.DialogCuj
import com.android.systemui.animation.DialogTransitionAnimator
import com.android.systemui.animation.Expandable
import com.android.systemui.log.logcatLogBuffer
import com.android.systemui.res.R
import com.android.systemui.statusbar.chips.ui.view.ChipBackgroundContainer
import com.android.systemui.statusbar.chips.ui.viewmodel.OngoingActivityChipViewModel.Companion.createDialogLaunchOnClickCallback
import com.android.systemui.statusbar.chips.ui.viewmodel.OngoingActivityChipViewModel.Companion.createDialogLaunchOnClickListener
import com.android.systemui.statusbar.chips.uievents.statusBarChipsUiEventLogger
import com.android.systemui.statusbar.phone.SystemUIDialog
import com.android.systemui.statusbar.phone.ongoingcall.DisableChipsModernization
import com.android.systemui.statusbar.phone.ongoingcall.EnableChipsModernization
import com.android.systemui.testKosmos
import kotlin.test.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

@SmallTest
@RunWith(AndroidJUnit4::class)
class OngoingActivityChipViewModelTest : SysuiTestCase() {
    private val kosmos = testKosmos()
    private val mockSystemUIDialog = mock<SystemUIDialog>()
    private val dialogDelegate = SystemUIDialog.Delegate { mockSystemUIDialog }
    private val dialogTransitionAnimator = mock<DialogTransitionAnimator>()

    private val chipBackgroundView = mock<ChipBackgroundContainer>()
    private val chipView =
        mock<View>().apply {
            whenever(
                    this.requireViewById<ChipBackgroundContainer>(
                        R.id.ongoing_activity_chip_background
                    )
                )
                .thenReturn(chipBackgroundView)
        }
    private val mockExpandable: Expandable =
        mock<Expandable>().apply { whenever(dialogTransitionController(any())).thenReturn(mock()) }

    @Test
    @DisableChipsModernization
    fun createDialogLaunchOnClickListener_showsDialogOnClick() {
        val cuj = DialogCuj(Cuj.CUJ_STATUS_BAR_LAUNCH_DIALOG_FROM_CHIP, tag = "Test")
        val clickListener =
            createDialogLaunchOnClickListener(
                dialogDelegate,
                dialogTransitionAnimator,
                cuj,
                instanceId = InstanceId.fakeInstanceId(0),
                uiEventLogger = kosmos.statusBarChipsUiEventLogger,
                logger = logcatLogBuffer("OngoingActivityChipViewModelTest"),
                tag = "tag",
            )

        clickListener.onClick(chipView)
        verify(dialogTransitionAnimator)
            .showFromView(eq(mockSystemUIDialog), eq(chipBackgroundView), eq(cuj), anyBoolean())
    }

    @Test
    @EnableChipsModernization
    fun createDialogLaunchOnClickCallback_showsDialogOnClick() {
        val cuj = DialogCuj(Cuj.CUJ_STATUS_BAR_LAUNCH_DIALOG_FROM_CHIP, tag = "Test")
        val clickCallback =
            createDialogLaunchOnClickCallback(
                dialogDelegate,
                dialogTransitionAnimator,
                cuj,
                instanceId = InstanceId.fakeInstanceId(0),
                uiEventLogger = kosmos.statusBarChipsUiEventLogger,
                logger = logcatLogBuffer("OngoingActivityChipViewModelTest"),
                tag = "tag",
            )

        clickCallback.invoke(mockExpandable)
        verify(dialogTransitionAnimator).show(eq(mockSystemUIDialog), any(), anyBoolean())
    }
}
