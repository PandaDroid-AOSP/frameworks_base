/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.systemui.qs.tiles

import android.os.Handler
import android.platform.test.flag.junit.FlagsParameterization
import android.platform.test.flag.junit.FlagsParameterization.allCombinationsOf
import android.testing.TestableLooper
import androidx.test.filters.SmallTest
import com.android.internal.logging.MetricsLogger
import com.android.systemui.SysuiTestCase
import com.android.systemui.animation.DialogTransitionAnimator
import com.android.systemui.classifier.FalsingManagerFake
import com.android.systemui.plugins.ActivityStarter
import com.android.systemui.plugins.qs.QSTile
import com.android.systemui.plugins.statusbar.StatusBarStateController
import com.android.systemui.qs.QSHost
import com.android.systemui.qs.QsEventLogger
import com.android.systemui.qs.flags.QSComposeFragment
import com.android.systemui.qs.flags.QsInCompose.isEnabled
import com.android.systemui.qs.logging.QSLogger
import com.android.systemui.qs.tileimpl.QSTileImpl
import com.android.systemui.qs.tileimpl.QSTileImpl.DrawableIconWithRes
import com.android.systemui.res.R
import com.android.systemui.shade.domain.interactor.FakeShadeDialogContextInteractor
import com.android.systemui.statusbar.phone.SystemUIDialog
import com.android.systemui.statusbar.policy.DataSaverController
import com.android.systemui.util.mockito.whenever
import com.google.common.truth.Truth.assertThat
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.eq
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@RunWith(ParameterizedAndroidJunit4::class)
@TestableLooper.RunWithLooper(setAsMainLooper = true)
@SmallTest
class DataSaverTileTest(flags: FlagsParameterization) : SysuiTestCase() {

    init {
        mSetFlagsRule.setFlagsParameterization(flags)
    }

    @Mock private lateinit var mHost: QSHost
    @Mock private lateinit var mMetricsLogger: MetricsLogger
    @Mock private lateinit var mQsLogger: QSLogger
    private val falsingManager = FalsingManagerFake()
    @Mock private lateinit var statusBarStateController: StatusBarStateController
    @Mock private lateinit var activityStarter: ActivityStarter
    @Mock private lateinit var dataSaverController: DataSaverController
    @Mock private lateinit var mDialogTransitionAnimator: DialogTransitionAnimator
    @Mock private lateinit var uiEventLogger: QsEventLogger
    @Mock private lateinit var systemUIDialogFactory: SystemUIDialog.Factory
    @Mock private lateinit var systemUIDialog: SystemUIDialog

    private lateinit var testableLooper: TestableLooper
    private lateinit var tile: DataSaverTile

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        testableLooper = TestableLooper.get(this)

        whenever(mHost.context).thenReturn(mContext)
        whenever(systemUIDialogFactory.create(eq(mContext))).thenReturn(systemUIDialog)

        tile =
            DataSaverTile(
                mHost,
                uiEventLogger,
                testableLooper.looper,
                Handler(testableLooper.looper),
                falsingManager,
                mMetricsLogger,
                statusBarStateController,
                activityStarter,
                mQsLogger,
                dataSaverController,
                mDialogTransitionAnimator,
                systemUIDialogFactory,
                FakeShadeDialogContextInteractor(mContext),
            )
    }

    @After
    fun tearDown() {
        tile.destroy()
        testableLooper.processAllMessages()
    }

    @Test
    fun testIcon_whenDataSaverEnabled_isOnState() {
        val state = QSTile.BooleanState()

        tile.handleUpdateState(state, true)

        assertThat(state.icon).isEqualTo(createExpectedIcon(R.drawable.qs_data_saver_icon_on))
    }

    @Test
    fun testIcon_whenDataSaverDisabled_isOffState() {
        val state = QSTile.BooleanState()

        tile.handleUpdateState(state, false)

        assertThat(state.icon).isEqualTo(createExpectedIcon(R.drawable.qs_data_saver_icon_off))
    }

    private fun createExpectedIcon(resId: Int): QSTile.Icon {
        return if (isEnabled) {
            DrawableIconWithRes(mContext.getDrawable(resId), resId)
        } else {
            QSTileImpl.ResourceIcon.get(resId)
        }
    }

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return allCombinationsOf(QSComposeFragment.FLAG_NAME)
        }
    }
}
