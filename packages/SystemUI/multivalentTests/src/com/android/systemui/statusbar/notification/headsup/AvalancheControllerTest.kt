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
package com.android.systemui.statusbar.notification.headsup

import android.app.Notification
import android.os.Handler
import android.platform.test.annotations.DisableFlags
import android.platform.test.annotations.EnableFlags
import android.platform.test.flag.junit.FlagsParameterization
import android.testing.TestableLooper.RunWithLooper
import androidx.test.filters.SmallTest
import com.android.internal.logging.testing.UiEventLoggerFake
import com.android.systemui.SysuiTestCase
import com.android.systemui.dump.DumpManager
import com.android.systemui.kosmos.testScope
import com.android.systemui.log.logcatLogBuffer
import com.android.systemui.plugins.statusbar.statusBarStateController
import com.android.systemui.shade.domain.interactor.shadeInteractor
import com.android.systemui.statusbar.chips.notification.shared.StatusBarNotifChips
import com.android.systemui.statusbar.notification.collection.NotificationEntryBuilder
import com.android.systemui.statusbar.notification.collection.provider.visualStabilityProvider
import com.android.systemui.statusbar.notification.collection.render.GroupMembershipManagerImpl
import com.android.systemui.statusbar.notification.headsup.HeadsUpManagerTestUtil.createFullScreenIntentEntry
import com.android.systemui.statusbar.notification.shared.NotificationThrottleHun
import com.android.systemui.statusbar.phone.keyguardBypassController
import com.android.systemui.statusbar.policy.AccessibilityManagerWrapper
import com.android.systemui.statusbar.policy.configurationController
import com.android.systemui.testKosmos
import com.android.systemui.util.concurrency.FakeExecutor
import com.android.systemui.util.concurrency.mockExecutorHandler
import com.android.systemui.util.kotlin.JavaAdapter
import com.android.systemui.util.settings.FakeGlobalSettings
import com.android.systemui.util.time.FakeSystemClock
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.MockitoJUnit
import org.mockito.junit.MockitoRule
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@RunWithLooper
@RunWith(ParameterizedAndroidJunit4::class)
@EnableFlags(NotificationThrottleHun.FLAG_NAME)
class AvalancheControllerTest(val flags: FlagsParameterization) : SysuiTestCase() {
    init {
        mSetFlagsRule.setFlagsParameterization(flags)
    }

    private val kosmos = testKosmos()

    // For creating mocks
    @get:Rule var rule: MockitoRule = MockitoJUnit.rule()
    @Mock private val runnableMock: Runnable? = null

    // For creating AvalancheController
    @Mock private lateinit var dumpManager: DumpManager
    private lateinit var mAvalancheController: AvalancheController

    // For creating TestableHeadsUpManager
    @Mock private val mAccessibilityMgr: AccessibilityManagerWrapper? = null
    private val mUiEventLoggerFake = UiEventLoggerFake()
    private val headsUpManagerLogger = HeadsUpManagerLogger(logcatLogBuffer())
    @Mock private lateinit var mBgHandler: Handler

    private val mLogger = Mockito.spy(headsUpManagerLogger)
    private val mGlobalSettings = FakeGlobalSettings()
    private val mSystemClock = FakeSystemClock()
    private val mExecutor = FakeExecutor(mSystemClock)
    private lateinit var testableHeadsUpManager: HeadsUpManagerImpl

    @Before
    fun setUp() {
        // Use default non-a11y timeout
        Mockito.`when`(
                mAccessibilityMgr!!.getRecommendedTimeoutMillis(
                    ArgumentMatchers.anyInt(),
                    ArgumentMatchers.anyInt(),
                )
            )
            .then { i: InvocationOnMock -> i.getArgument(0) }

        // Initialize AvalancheController and TestableHeadsUpManager during setUp instead of
        // declaration, where mocks are null
        mAvalancheController =
            AvalancheController(dumpManager, mUiEventLoggerFake, headsUpManagerLogger, mBgHandler)

        testableHeadsUpManager =
            HeadsUpManagerImpl(
                mContext,
                mLogger,
                kosmos.statusBarStateController,
                kosmos.keyguardBypassController,
                GroupMembershipManagerImpl(),
                kosmos.visualStabilityProvider,
                kosmos.configurationController,
                mockExecutorHandler(mExecutor),
                mGlobalSettings,
                mSystemClock,
                mExecutor,
                mAccessibilityMgr,
                mUiEventLoggerFake,
                JavaAdapter(kosmos.testScope),
                kosmos.shadeInteractor,
                mAvalancheController,
            )
    }

    private fun createHeadsUpEntry(id: Int): HeadsUpManagerImpl.HeadsUpEntry {
        return testableHeadsUpManager.createHeadsUpEntry(
            NotificationEntryBuilder()
                .setSbn(HeadsUpManagerTestUtil.createSbn(id, Notification.Builder(mContext, "")))
                .build()
        )
    }

    private fun createFsiHeadsUpEntry(id: Int): HeadsUpManagerImpl.HeadsUpEntry {
        return testableHeadsUpManager.createHeadsUpEntry(createFullScreenIntentEntry(id, mContext))
    }

    @Test
    fun testUpdate_isShowing_runsRunnable() {
        // Entry is showing
        val headsUpEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = headsUpEntry

        // Update
        mAvalancheController.update(headsUpEntry, runnableMock!!, "testLabel")

        // Runnable was run
        Mockito.verify(runnableMock, Mockito.times(1)).run()
    }

    @Test
    fun testUpdate_noneShowingAndNotNext_showNow() {
        val headsUpEntry = createHeadsUpEntry(id = 0)

        // None showing
        mAvalancheController.headsUpEntryShowing = null

        // Entry is NOT next
        mAvalancheController.clearNext()

        // Update
        mAvalancheController.update(headsUpEntry, runnableMock!!, "testLabel")

        // Entry is showing now
        assertThat(mAvalancheController.headsUpEntryShowing).isEqualTo(headsUpEntry)
    }

    @Test
    fun testUpdate_isNext_addsRunnable() {
        // Another entry is already showing
        val otherShowingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = otherShowingEntry

        // Entry is next
        val headsUpEntry = createHeadsUpEntry(id = 1)
        mAvalancheController.addToNext(headsUpEntry, runnableMock!!)

        // Entry has one Runnable
        val runnableList: List<Runnable?>? = mAvalancheController.nextMap[headsUpEntry]
        assertThat(runnableList).isNotNull()
        assertThat(runnableList!!.size).isEqualTo(1)

        // Update
        mAvalancheController.update(headsUpEntry, runnableMock, "testLabel")

        // Entry has two Runnables
        assertThat(runnableList.size).isEqualTo(2)
    }

    @Test
    fun testUpdate_isNotNextWithOtherHunShowing_isNext() {
        val headsUpEntry = createHeadsUpEntry(id = 0)

        // Another entry is already showing
        val otherShowingEntry = createHeadsUpEntry(id = 1)
        mAvalancheController.headsUpEntryShowing = otherShowingEntry

        // Entry is NOT next
        mAvalancheController.clearNext()

        // Update
        mAvalancheController.update(headsUpEntry, runnableMock!!, "testLabel")

        // Entry is next
        assertThat(mAvalancheController.nextMap.containsKey(headsUpEntry)).isTrue()
    }

    @Test
    fun testDelete_untracked_runnableRuns() {
        val headsUpEntry = createHeadsUpEntry(id = 0)

        // None showing
        mAvalancheController.headsUpEntryShowing = null

        // Nothing is next
        mAvalancheController.clearNext()

        // Delete
        mAvalancheController.delete(headsUpEntry, runnableMock!!, "testLabel")

        // Runnable was run
        Mockito.verify(runnableMock, Mockito.times(1)).run()
    }

    @Test
    fun testDelete_isNext_removedFromNext_runnableNotRun() {
        // Entry is next
        val headsUpEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.addToNext(headsUpEntry, runnableMock!!)

        // Delete
        mAvalancheController.delete(headsUpEntry, runnableMock, "testLabel")

        // Entry was removed from next
        assertThat(mAvalancheController.nextMap.containsKey(headsUpEntry)).isFalse()

        // Runnable was not run
        Mockito.verify(runnableMock, Mockito.times(0)).run()
    }

    @Test
    fun testDelete_isShowing_runnableRun() {
        // Entry is showing
        val headsUpEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = headsUpEntry

        // Delete
        mAvalancheController.delete(headsUpEntry, runnableMock!!, "testLabel")

        // Runnable was run
        Mockito.verify(runnableMock, Mockito.times(1)).run()
    }

    @Test
    fun testDelete_isShowing_showNext() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next
        val nextEntry = createHeadsUpEntry(id = 1)
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        // Delete
        mAvalancheController.delete(showingEntry, runnableMock, "testLabel")

        // Next entry is shown
        assertThat(mAvalancheController.headsUpEntryShowing).isEqualTo(nextEntry)
    }

    @Test
    fun testDelete_deleteSecondToLastEntry_showingEntryKeyBecomesPreviousHunKey() {
        mAvalancheController.previousHunKey = ""

        // Entry is showing
        val firstEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = firstEntry

        // There's another entry waiting to show next
        val secondEntry = createHeadsUpEntry(id = 1)
        mAvalancheController.addToNext(secondEntry, runnableMock!!)

        // Delete
        mAvalancheController.delete(firstEntry, runnableMock, "testLabel")

        // Showing entry becomes previous
        assertThat(mAvalancheController.previousHunKey).isEqualTo(firstEntry.mEntry!!.key)
    }

    @Test
    fun testDelete_deleteLastEntry_previousHunKeyCleared() {
        mAvalancheController.previousHunKey = "key"

        // Nothing waiting to show
        mAvalancheController.clearNext()

        // One entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // Delete
        mAvalancheController.delete(showingEntry, runnableMock!!, "testLabel")

        // Previous key not filled in
        assertThat(mAvalancheController.previousHunKey).isEqualTo("")
    }

    @Test
    fun testGetDuration_untrackedEntryEmptyAvalanche_useAutoDismissTime() {
        val givenEntry = createHeadsUpEntry(id = 0)

        // Nothing is showing
        mAvalancheController.headsUpEntryShowing = null

        // Nothing is next
        mAvalancheController.clearNext()

        val durationMs = mAvalancheController.getDuration(givenEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(5000)
    }

    @Test
    fun testGetDuration_untrackedEntryNonEmptyAvalanche_useAutoDismissTime() {
        val givenEntry = createHeadsUpEntry(id = 0)

        // Given entry not tracked
        mAvalancheController.headsUpEntryShowing = createHeadsUpEntry(id = 1)

        mAvalancheController.clearNext()
        val nextEntry = createHeadsUpEntry(id = 2)
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        val durationMs = mAvalancheController.getDuration(givenEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(5000)
    }

    @Test
    fun testGetDuration_lastEntry_useAutoDismissTime() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // Nothing is next
        mAvalancheController.clearNext()

        val durationMs = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(5000)
    }

    @Test
    fun testGetDuration_nextEntryLowerPriority_5000() {
        // Entry is showing
        val showingEntry = createFsiHeadsUpEntry(id = 1)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next
        val nextEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        // Next entry has lower priority
        assertThat(nextEntry.compareNonTimeFields(showingEntry)).isEqualTo(1)

        val durationMs = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(5000)
    }

    @Test
    fun testGetDuration_nextEntrySamePriority_1000() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next
        val nextEntry = createHeadsUpEntry(id = 1)
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        // Same priority
        assertThat(nextEntry.compareNonTimeFields(showingEntry)).isEqualTo(0)

        val durationMs = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(1000)
    }

    @Test
    fun testGetDuration_nextEntryHigherPriority_500() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next
        val nextEntry = createFsiHeadsUpEntry(id = 1)
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        // Next entry has higher priority
        assertThat(nextEntry.compareNonTimeFields(showingEntry)).isEqualTo(-1)

        val durationMs = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(500)
    }

    @Test
    @DisableFlags(StatusBarNotifChips.FLAG_NAME)
    fun testGetDuration_nextEntryIsPinnedByUser_flagOff_1000() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next and it's PinnedByUser
        val nextEntry = createHeadsUpEntry(id = 1)
        nextEntry.requestedPinnedStatus = PinnedStatus.PinnedByUser
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        val durationMs = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)

        // BUT PinnedByUser is ignored because flag is off, so the duration for a SAME priority next
        // is used
        assertThat((durationMs as RemainingDuration.UpdatedDuration).duration).isEqualTo(1000)
    }

    @Test
    @EnableFlags(StatusBarNotifChips.FLAG_NAME)
    fun testGetDuration_nextEntryIsPinnedByUser_flagOn_hideImmediately() {
        // Entry is showing
        val showingEntry = createHeadsUpEntry(id = 0)
        mAvalancheController.headsUpEntryShowing = showingEntry

        // There's another entry waiting to show next and it's PinnedByUser
        val nextEntry = createHeadsUpEntry(id = 1)
        nextEntry.requestedPinnedStatus = PinnedStatus.PinnedByUser
        mAvalancheController.addToNext(nextEntry, runnableMock!!)

        val duration = mAvalancheController.getDuration(showingEntry, autoDismissMsValue = 5000)

        assertThat(duration).isEqualTo(RemainingDuration.HideImmediately)
    }

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return FlagsParameterization.allCombinationsOf(StatusBarNotifChips.FLAG_NAME)
        }
    }
}
