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

package com.android.systemui.keyguard.ui.view.layout.sections

import android.graphics.Point
import android.view.WindowManager
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.constraintlayout.widget.ConstraintSet
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.biometrics.AuthController
import com.android.systemui.flags.FakeFeatureFlags
import com.android.systemui.flags.FakeFeatureFlagsClassic
import com.android.systemui.flags.Flags
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryBackgroundViewModel
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryForegroundViewModel
import com.android.systemui.keyguard.ui.viewmodel.DeviceEntryIconViewModel
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.log.logcatLogBuffer
import com.android.systemui.plugins.FalsingManager
import com.android.systemui.res.R
import com.android.systemui.shade.NotificationPanelView
import com.android.systemui.statusbar.VibratorHelper
import com.android.systemui.testKosmos
import com.android.systemui.util.mockito.whenever
import com.google.android.msdl.domain.MSDLPlayer
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Answers
import org.mockito.Mock
import org.mockito.Mockito.mock
import org.mockito.MockitoAnnotations

@RunWith(AndroidJUnit4::class)
@SmallTest
class DefaultDeviceEntrySectionTest : SysuiTestCase() {
    @Mock private lateinit var authController: AuthController
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) private lateinit var windowManager: WindowManager
    @Mock private lateinit var notificationPanelView: NotificationPanelView
    private lateinit var featureFlags: FakeFeatureFlags
    @Mock private lateinit var falsingManager: FalsingManager
    @Mock private lateinit var deviceEntryIconViewModel: DeviceEntryIconViewModel
    @Mock private lateinit var msdlPlayer: MSDLPlayer
    private lateinit var underTest: DefaultDeviceEntrySection

    @Before
    fun setup() {
        MockitoAnnotations.initMocks(this)

        featureFlags =
            FakeFeatureFlagsClassic().apply { set(Flags.LOCKSCREEN_ENABLE_LANDSCAPE, false) }
        underTest =
            DefaultDeviceEntrySection(
                TestScope().backgroundScope,
                testKosmos().testDispatcher,
                authController,
                windowManager,
                context,
                notificationPanelView,
                featureFlags,
                { deviceEntryIconViewModel },
                { mock(DeviceEntryForegroundViewModel::class.java) },
                { mock(DeviceEntryBackgroundViewModel::class.java) },
                { falsingManager },
                { mock(VibratorHelper::class.java) },
                { msdlPlayer },
                logcatLogBuffer(),
                logcatLogBuffer("blueprints"),
            )
    }

    @Test
    fun addViewsConditionally() {
        val constraintLayout = ConstraintLayout(context, null)
        underTest.addViews(constraintLayout)
        assertThat(constraintLayout.childCount).isGreaterThan(0)
    }

    @Test
    fun applyConstraints() {
        whenever(deviceEntryIconViewModel.isUdfpsSupported).thenReturn(MutableStateFlow(false))
        val cs = ConstraintSet()
        underTest.applyConstraints(cs)

        val constraint = cs.getConstraint(R.id.device_entry_icon_view)

        assertThat(constraint.layout.topToTop).isEqualTo(ConstraintSet.PARENT_ID)
        assertThat(constraint.layout.startToStart).isEqualTo(ConstraintSet.PARENT_ID)
    }

    @Test
    fun testCenterIcon() {
        val cs = ConstraintSet()
        underTest.centerIcon(Point(5, 6), 1F, cs)

        val constraint = cs.getConstraint(R.id.device_entry_icon_view)

        assertThat(constraint.layout.mWidth).isEqualTo(2)
        assertThat(constraint.layout.mHeight).isEqualTo(2)
        assertThat(constraint.layout.topToTop).isEqualTo(ConstraintSet.PARENT_ID)
        assertThat(constraint.layout.startToStart).isEqualTo(ConstraintSet.PARENT_ID)
        assertThat(constraint.layout.topMargin).isEqualTo(5)
        assertThat(constraint.layout.startMargin).isEqualTo(4)
    }
}
