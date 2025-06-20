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

package com.android.systemui.statusbar.chips.screenrecord.ui.viewmodel

import android.content.DialogInterface
import android.view.View
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.internal.jank.Cuj
import com.android.systemui.SysuiTestCase
import com.android.systemui.animation.DialogCuj
import com.android.systemui.animation.Expandable
import com.android.systemui.animation.mockDialogTransitionAnimator
import com.android.systemui.common.shared.model.Icon
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.kosmos.testScope
import com.android.systemui.kosmos.useUnconfinedTestDispatcher
import com.android.systemui.mediaprojection.data.model.MediaProjectionState
import com.android.systemui.mediaprojection.data.repository.fakeMediaProjectionRepository
import com.android.systemui.mediaprojection.taskswitcher.FakeActivityTaskManager
import com.android.systemui.res.R
import com.android.systemui.screenrecord.data.model.ScreenRecordModel
import com.android.systemui.screenrecord.data.repository.screenRecordRepository
import com.android.systemui.statusbar.chips.mediaprojection.domain.interactor.MediaProjectionChipInteractorTest.Companion.setUpPackageManagerForMediaProjection
import com.android.systemui.statusbar.chips.screenrecord.ui.view.EndScreenRecordingDialogDelegate
import com.android.systemui.statusbar.chips.sharetoapp.ui.viewmodel.shareToAppChipViewModel
import com.android.systemui.statusbar.chips.ui.model.ColorsModel
import com.android.systemui.statusbar.chips.ui.model.OngoingActivityChipModel
import com.android.systemui.statusbar.chips.ui.view.ChipBackgroundContainer
import com.android.systemui.statusbar.chips.ui.viewmodel.OngoingActivityChipsViewModelTest.Companion.getStopActionFromDialog
import com.android.systemui.statusbar.phone.SystemUIDialog
import com.android.systemui.statusbar.phone.mockSystemUIDialogFactory
import com.android.systemui.statusbar.phone.ongoingcall.DisableChipsModernization
import com.android.systemui.statusbar.phone.ongoingcall.EnableChipsModernization
import com.android.systemui.testKosmos
import com.android.systemui.util.time.fakeSystemClock
import com.google.common.truth.Truth.assertThat
import kotlin.test.Test
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

@SmallTest
@RunWith(AndroidJUnit4::class)
class ScreenRecordChipViewModelTest : SysuiTestCase() {
    private val kosmos = testKosmos().useUnconfinedTestDispatcher()
    private val testScope = kosmos.testScope
    private val screenRecordRepo = kosmos.screenRecordRepository
    private val mediaProjectionRepo = kosmos.fakeMediaProjectionRepository
    private val systemClock = kosmos.fakeSystemClock
    private val mockSystemUIDialog = mock<SystemUIDialog>()
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

    private val underTest = kosmos.screenRecordChipViewModel

    @Before
    fun setUp() {
        setUpPackageManagerForMediaProjection(kosmos)
        whenever(kosmos.mockSystemUIDialogFactory.create(any<EndScreenRecordingDialogDelegate>()))
            .thenReturn(mockSystemUIDialog)
    }

    @Test
    fun chip_doingNothingState_isHidden() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.DoingNothing

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Inactive::class.java)
        }

    @Test
    fun chip_startingState_isShownAsCountdownWithoutIconOrClickListener() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Starting(400)

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active.Countdown::class.java)
            assertThat((latest as OngoingActivityChipModel.Active).isImportantForPrivacy).isTrue()
            assertThat((latest as OngoingActivityChipModel.Active).instanceId).isNotNull()
            assertThat((latest as OngoingActivityChipModel.Active).icon).isNull()
            assertThat((latest as OngoingActivityChipModel.Active).onClickListenerLegacy).isNull()
        }

    // The millis we typically get from [ScreenRecordRepository] are around 2995, 1995, and 995.
    @Test
    fun chip_startingState_millis2995_is3() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Starting(2995)

            assertThat((latest as OngoingActivityChipModel.Active.Countdown).secondsUntilStarted)
                .isEqualTo(3)
        }

    @Test
    fun chip_startingState_millis1995_is2() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Starting(1995)

            assertThat((latest as OngoingActivityChipModel.Active.Countdown).secondsUntilStarted)
                .isEqualTo(2)
        }

    @Test
    fun chip_startingState_millis995_is1() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Starting(995)

            assertThat((latest as OngoingActivityChipModel.Active.Countdown).secondsUntilStarted)
                .isEqualTo(1)
        }

    @Test
    fun chip_recordingState_isShownAsTimerWithIcon() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active.Timer::class.java)
            assertThat((latest as OngoingActivityChipModel.Active).isImportantForPrivacy).isTrue()
            assertThat((latest as OngoingActivityChipModel.Active).instanceId).isNotNull()
            val icon =
                (((latest as OngoingActivityChipModel.Active).icon)
                        as OngoingActivityChipModel.ChipIcon.SingleColorIcon)
                    .impl as Icon.Resource
            assertThat(icon.res).isEqualTo(R.drawable.ic_screenrecord)
            assertThat(icon.contentDescription).isNotNull()
        }

    @Test
    fun chip_recordingStoppedFromDialog_screenRecordAndShareToAppChipImmediatelyHidden() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            val latestShareToApp by collectLastValue(kosmos.shareToAppChipViewModel.chip)

            // On real devices, when screen recording is active then share-to-app is also active
            // because screen record is just a special case of share-to-app where the app receiving
            // the share is SysUI
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.EntireScreen("fake.package")

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active::class.java)
            assertThat(latestShareToApp).isInstanceOf(OngoingActivityChipModel.Active::class.java)

            // WHEN the stop action on the dialog is clicked
            val dialogStopAction =
                getStopActionFromDialog(
                    latest,
                    chipView,
                    mockExpandable,
                    mockSystemUIDialog,
                    kosmos,
                )
            dialogStopAction.onClick(mock<DialogInterface>(), 0)

            // THEN both the screen record chip and the share-to-app chip are immediately hidden...
            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Inactive::class.java)
            assertThat(latestShareToApp).isInstanceOf(OngoingActivityChipModel.Inactive::class.java)
            // ...even though the repos still say it's recording
            assertThat(screenRecordRepo.screenRecordState.value)
                .isEqualTo(ScreenRecordModel.Recording)
            assertThat(mediaProjectionRepo.mediaProjectionState.value)
                .isInstanceOf(MediaProjectionState.Projecting::class.java)

            // AND we specify no animation
            assertThat((latest as OngoingActivityChipModel.Inactive).shouldAnimate).isFalse()
        }

    @Test
    fun chip_startingState_colorsAreRed() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Starting(2000L)

            assertThat((latest as OngoingActivityChipModel.Active).colors)
                .isEqualTo(ColorsModel.Red)
        }

    @Test
    fun chip_recordingState_colorsAreRed() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording

            assertThat((latest as OngoingActivityChipModel.Active).colors)
                .isEqualTo(ColorsModel.Red)
        }

    @Test
    fun chip_timeResetsOnEachNewRecording() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            systemClock.setElapsedRealtime(1234)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active::class.java)
            assertThat((latest as OngoingActivityChipModel.Active.Timer).startTimeMs)
                .isEqualTo(1234)

            screenRecordRepo.screenRecordState.value = ScreenRecordModel.DoingNothing
            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Inactive::class.java)

            systemClock.setElapsedRealtime(5678)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active::class.java)
            assertThat((latest as OngoingActivityChipModel.Active.Timer).startTimeMs)
                .isEqualTo(5678)
        }

    /** Regression test for b/349620526. */
    @Test
    fun chip_recordingState_thenGetsTaskInfo_startTimeDoesNotChange() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)

            // Start recording, but without any task info
            systemClock.setElapsedRealtime(1234)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value = MediaProjectionState.NotProjecting

            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active::class.java)
            assertThat((latest as OngoingActivityChipModel.Active).isImportantForPrivacy).isTrue()
            assertThat((latest as OngoingActivityChipModel.Active.Timer).startTimeMs)
                .isEqualTo(1234)

            // WHEN we receive the recording task info a few milliseconds later
            systemClock.setElapsedRealtime(1240)
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.SingleTask(
                    "host.package",
                    hostDeviceName = null,
                    FakeActivityTaskManager.createTask(taskId = 1),
                )

            // THEN the start time is still the old start time
            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active::class.java)
            assertThat((latest as OngoingActivityChipModel.Active).isImportantForPrivacy).isTrue()
            assertThat((latest as OngoingActivityChipModel.Active.Timer).startTimeMs)
                .isEqualTo(1234)
        }

    @Test
    @DisableChipsModernization
    fun chip_notProjecting_clickListenerShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value = MediaProjectionState.NotProjecting

            val clickListener = ((latest as OngoingActivityChipModel.Active).onClickListenerLegacy)
            assertThat(clickListener).isNotNull()

            clickListener!!.onClick(chipView)
            // EndScreenRecordingDialogDelegate will test that the dialog has the right message
            verify(kosmos.mockDialogTransitionAnimator)
                .showFromView(eq(mockSystemUIDialog), eq(chipBackgroundView), any(), anyBoolean())
        }

    @Test
    @DisableChipsModernization
    fun chip_projectingEntireScreen_clickListenerShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.EntireScreen("host.package")

            val clickListener = ((latest as OngoingActivityChipModel.Active).onClickListenerLegacy)
            assertThat(clickListener).isNotNull()

            clickListener!!.onClick(chipView)
            // EndScreenRecordingDialogDelegate will test that the dialog has the right message
            verify(kosmos.mockDialogTransitionAnimator)
                .showFromView(eq(mockSystemUIDialog), eq(chipBackgroundView), any(), anyBoolean())
        }

    @Test
    @DisableChipsModernization
    fun chip_projectingSingleTask_clickListenerShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.SingleTask(
                    "host.package",
                    hostDeviceName = null,
                    FakeActivityTaskManager.createTask(taskId = 1),
                )

            val clickListener = ((latest as OngoingActivityChipModel.Active).onClickListenerLegacy)
            assertThat(clickListener).isNotNull()

            clickListener!!.onClick(chipView)
            // EndScreenRecordingDialogDelegate will test that the dialog has the right message
            verify(kosmos.mockDialogTransitionAnimator)
                .showFromView(eq(mockSystemUIDialog), eq(chipBackgroundView), any(), anyBoolean())
        }

    @Test
    @DisableChipsModernization
    fun chip_clickListenerHasCujLegacy() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.EntireScreen("host.package")

            val clickListener = ((latest as OngoingActivityChipModel.Active).onClickListenerLegacy)
            clickListener!!.onClick(chipView)

            val cujCaptor = argumentCaptor<DialogCuj>()
            verify(kosmos.mockDialogTransitionAnimator)
                .showFromView(any(), any(), cujCaptor.capture(), anyBoolean())
            assertThat(cujCaptor.firstValue.cujType)
                .isEqualTo(Cuj.CUJ_STATUS_BAR_LAUNCH_DIALOG_FROM_CHIP)
            assertThat(cujCaptor.firstValue.tag).contains("Screen record")
        }

    @Test
    @EnableChipsModernization
    fun chip_recordingState_hasClickBehavior() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            assertThat(latest).isInstanceOf(OngoingActivityChipModel.Active.Timer::class.java)
            assertThat((latest as OngoingActivityChipModel.Active).clickBehavior)
                .isInstanceOf(OngoingActivityChipModel.ClickBehavior.ExpandAction::class.java)
        }

    @Test
    @EnableChipsModernization
    fun chip_notProjecting_expandActionBehaviorShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value = MediaProjectionState.NotProjecting

            val expandAction =
                ((latest as OngoingActivityChipModel.Active).clickBehavior
                    as OngoingActivityChipModel.ClickBehavior.ExpandAction)

            expandAction.onClick(mockExpandable)
            verify(kosmos.mockDialogTransitionAnimator).show(any(), any(), anyBoolean())
        }

    @Test
    @EnableChipsModernization
    fun chip_projectingEntireScreen_expandActionBehaviorShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording

            val expandAction =
                ((latest as OngoingActivityChipModel.Active).clickBehavior
                    as OngoingActivityChipModel.ClickBehavior.ExpandAction)

            expandAction.onClick(mockExpandable)
            verify(kosmos.mockDialogTransitionAnimator).show(any(), any(), anyBoolean())
        }

    @Test
    @EnableChipsModernization
    fun chip_projectingSingleTask_expandActionBehaviorShowsDialog() =
        testScope.runTest {
            val latest by collectLastValue(underTest.chip)
            screenRecordRepo.screenRecordState.value = ScreenRecordModel.Recording
            mediaProjectionRepo.mediaProjectionState.value =
                MediaProjectionState.Projecting.SingleTask(
                    "host.package",
                    hostDeviceName = null,
                    FakeActivityTaskManager.createTask(taskId = 1),
                )

            val expandAction =
                ((latest as OngoingActivityChipModel.Active).clickBehavior
                    as OngoingActivityChipModel.ClickBehavior.ExpandAction)

            expandAction.onClick(mockExpandable)
            verify(kosmos.mockDialogTransitionAnimator).show(any(), any(), anyBoolean())
        }
}
