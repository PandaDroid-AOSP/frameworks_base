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

package com.android.systemui.volume.dialog.sliders.domain.interactor

import android.app.ActivityManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.accessibility.data.repository.accessibilityRepository
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.testScope
import com.android.systemui.plugins.fakeVolumeDialogController
import com.android.systemui.testKosmos
import com.android.systemui.volume.Events
import com.android.systemui.volume.dialog.domain.interactor.volumeDialogVisibilityInteractor
import com.android.systemui.volume.dialog.shared.model.VolumeDialogVisibilityModel
import com.android.systemui.volume.dialog.sliders.shared.model.SliderInputEvent
import com.google.common.truth.Truth.assertThat
import kotlin.test.Test
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.runner.RunWith

private val volumeDialogTimeout = 3.seconds

@SmallTest
@RunWith(AndroidJUnit4::class)
class VolumeDialogSliderInputEventsInteractorTest : SysuiTestCase() {

    private val kosmos =
        testKosmos().apply { accessibilityRepository.setRecommendedTimeout(volumeDialogTimeout) }

    private val underTest: VolumeDialogSliderInputEventsInteractor =
        kosmos.volumeDialogSliderInputEventsInteractor

    @Test
    fun inputEvents_resetDialogVisibilityTimeout() =
        with(kosmos) {
            testScope.runTest {
                runCurrent()
                val dialogVisibility by
                    collectLastValue(volumeDialogVisibilityInteractor.dialogVisibility)
                fakeVolumeDialogController.onShowRequested(
                    Events.SHOW_REASON_VOLUME_CHANGED,
                    false,
                    ActivityManager.LOCK_TASK_MODE_LOCKED,
                )
                runCurrent()
                advanceTimeBy(volumeDialogTimeout / 2)
                assertThat(dialogVisibility)
                    .isInstanceOf(VolumeDialogVisibilityModel.Visible::class.java)

                underTest.onTouchEvent(SliderInputEvent.Touch.Start(0f, 0f))
                advanceTimeBy(volumeDialogTimeout / 2)

                assertThat(dialogVisibility)
                    .isInstanceOf(VolumeDialogVisibilityModel.Visible::class.java)
            }
        }
}
