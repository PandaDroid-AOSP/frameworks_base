/*
 * Copyright 2024 The Android Open Source Project
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

package com.android.systemui.education.domain.interactor

import android.content.pm.UserInfo
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.contextualeducation.GestureType
import com.android.systemui.contextualeducation.GestureType.ALL_APPS
import com.android.systemui.contextualeducation.GestureType.BACK
import com.android.systemui.contextualeducation.GestureType.HOME
import com.android.systemui.contextualeducation.GestureType.OVERVIEW
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.coroutines.collectValues
import com.android.systemui.education.data.model.GestureEduModel
import com.android.systemui.education.data.repository.contextualEducationRepository
import com.android.systemui.education.data.repository.fakeEduClock
import com.android.systemui.education.shared.model.EducationUiType
import com.android.systemui.inputdevice.tutorial.data.repository.DeviceType
import com.android.systemui.inputdevice.tutorial.tutorialSchedulerRepository
import com.android.systemui.keyboard.data.repository.keyboardRepository
import com.android.systemui.kosmos.testScope
import com.android.systemui.recents.LauncherProxyService.LauncherProxyListener
import com.android.systemui.testKosmos
import com.android.systemui.touchpad.data.repository.touchpadRepository
import com.android.systemui.user.data.repository.fakeUserRepository
import com.google.common.truth.Truth.assertThat
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.verify
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@RunWith(ParameterizedAndroidJunit4::class)
class KeyboardTouchpadEduInteractorParameterizedTest(private val gestureType: GestureType) :
    SysuiTestCase() {
    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val contextualEduInteractor = kosmos.contextualEducationInteractor
    private val repository = kosmos.contextualEducationRepository
    private val touchpadRepository = kosmos.touchpadRepository
    private val keyboardRepository = kosmos.keyboardRepository
    private val tutorialSchedulerRepository = kosmos.tutorialSchedulerRepository
    private val userRepository = kosmos.fakeUserRepository
    private val launcherProxyService = kosmos.mockLauncherProxyService

    private val underTest: KeyboardTouchpadEduInteractor = kosmos.keyboardTouchpadEduInteractor
    private val eduClock = kosmos.fakeEduClock
    private val minDurationForNextEdu =
        KeyboardTouchpadEduInteractor.minIntervalBetweenEdu + 1.seconds
    private val initialDelayElapsedDuration =
        KeyboardTouchpadEduInteractor.initialDelayDuration + 1.seconds

    @Before
    fun setup() {
        underTest.start()
        contextualEduInteractor.start()
        userRepository.setUserInfos(USER_INFOS)
        testScope.launch {
            contextualEduInteractor.updateKeyboardFirstConnectionTime()
            contextualEduInteractor.updateTouchpadFirstConnectionTime()
        }
    }

    @Test
    fun newEducationInfoOnMaxSignalCountReached() =
        testScope.runTest {
            triggerMaxEducationSignals(gestureType)
            val model by collectLastValue(underTest.educationTriggered)

            assertThat(model?.gestureType).isEqualTo(gestureType)
        }

    @Test
    fun newEducationToastOn1stEducation() =
        testScope.runTest {
            val model by collectLastValue(underTest.educationTriggered)
            triggerMaxEducationSignals(gestureType)

            assertThat(model?.educationUiType).isEqualTo(EducationUiType.Toast)
        }

    @Test
    fun newEducationNotificationOn2ndEducation() =
        testScope.runTest {
            val model by collectLastValue(underTest.educationTriggered)
            triggerMaxEducationSignals(gestureType)
            // runCurrent() to trigger 1st education
            runCurrent()

            eduClock.offset(minDurationForNextEdu)
            triggerMaxEducationSignals(gestureType)

            assertThat(model?.educationUiType).isEqualTo(EducationUiType.Notification)
        }

    @Test
    fun noEducationInfoBeforeMaxSignalCountReached() =
        testScope.runTest {
            contextualEduInteractor.incrementSignalCount(gestureType)
            val model by collectLastValue(underTest.educationTriggered)
            assertThat(model).isNull()
        }

    @Test
    fun noEducationInfoWhenShortcutTriggeredPreviously() =
        testScope.runTest {
            val model by collectLastValue(underTest.educationTriggered)
            contextualEduInteractor.updateShortcutTriggerTime(gestureType)
            triggerMaxEducationSignals(gestureType)
            assertThat(model).isNull()
        }

    @Test
    fun no2ndEducationBeforeMinEduIntervalReached() =
        testScope.runTest {
            val models by collectValues(underTest.educationTriggered)
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            // Offset a duration that is less than the required education interval
            eduClock.offset(1.seconds)
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            assertThat(models.filterNotNull().size).isEqualTo(1)
        }

    @Test
    fun noNewEducationInfoAfterMaxEducationCountReached() =
        testScope.runTest {
            val models by collectValues(underTest.educationTriggered)
            // Trigger 2 educations
            triggerMaxEducationSignals(gestureType)
            runCurrent()
            eduClock.offset(minDurationForNextEdu)
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            // Try triggering 3rd education
            eduClock.offset(minDurationForNextEdu)
            triggerMaxEducationSignals(gestureType)

            assertThat(models.filterNotNull().size).isEqualTo(2)
        }

    @Test
    fun startNewUsageSessionWhen2ndSignalReceivedAfterSessionDeadline() =
        testScope.runTest {
            val model by
                collectLastValue(
                    kosmos.contextualEducationRepository.readGestureEduModelFlow(gestureType)
                )
            contextualEduInteractor.incrementSignalCount(gestureType)
            eduClock.offset(KeyboardTouchpadEduInteractor.usageSessionDuration.plus(1.seconds))
            val secondSignalReceivedTime = eduClock.instant()
            contextualEduInteractor.incrementSignalCount(gestureType)

            assertThat(model)
                .isEqualTo(
                    GestureEduModel(
                        signalCount = 1,
                        usageSessionStartTime = secondSignalReceivedTime,
                        userId = 0,
                        gestureType = gestureType,
                    )
                )
        }

    @Test
    fun newTouchpadConnectionTimeOnFirstTouchpadConnected() =
        testScope.runTest {
            setIsAnyTouchpadConnected(true)
            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.touchpadFirstConnectionTime).isEqualTo(eduClock.instant())
        }

    @Test
    fun unchangedTouchpadConnectionTimeOnSecondConnection() =
        testScope.runTest {
            val firstConnectionTime = eduClock.instant()
            setIsAnyTouchpadConnected(true)
            setIsAnyTouchpadConnected(false)

            eduClock.offset(1.hours)
            setIsAnyTouchpadConnected(true)

            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.touchpadFirstConnectionTime).isEqualTo(firstConnectionTime)
        }

    @Test
    fun newTouchpadConnectionTimeOnUserChanged() =
        testScope.runTest {
            // Touchpad connected for user 0
            setIsAnyTouchpadConnected(true)

            // Change user
            eduClock.offset(1.hours)
            val newUserFirstConnectionTime = eduClock.instant()
            userRepository.setSelectedUserInfo(USER_INFOS[0])
            runCurrent()

            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.touchpadFirstConnectionTime).isEqualTo(newUserFirstConnectionTime)
        }

    @Test
    fun newKeyboardConnectionTimeOnKeyboardConnected() =
        testScope.runTest {
            setIsAnyKeyboardConnected(true)
            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.keyboardFirstConnectionTime).isEqualTo(eduClock.instant())
        }

    @Test
    fun unchangedKeyboardConnectionTimeOnSecondConnection() =
        testScope.runTest {
            val firstConnectionTime = eduClock.instant()
            setIsAnyKeyboardConnected(true)
            setIsAnyKeyboardConnected(false)

            eduClock.offset(1.hours)
            setIsAnyKeyboardConnected(true)

            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.keyboardFirstConnectionTime).isEqualTo(firstConnectionTime)
        }

    @Test
    fun newKeyboardConnectionTimeOnUserChanged() =
        testScope.runTest {
            // Keyboard connected for user 0
            setIsAnyKeyboardConnected(true)

            // Change user
            eduClock.offset(1.hours)
            val newUserFirstConnectionTime = eduClock.instant()
            userRepository.setSelectedUserInfo(USER_INFOS[0])
            runCurrent()

            val model = contextualEduInteractor.getEduDeviceConnectionTime()
            assertThat(model.keyboardFirstConnectionTime).isEqualTo(newUserFirstConnectionTime)
        }

    @Test
    fun updateShortcutTimeOnKeyboardShortcutTriggered() =
        testScope.runTest {
            // Only All Apps needs to update the keyboard shortcut
            assumeTrue(gestureType == ALL_APPS)
            kosmos.contextualEducationRepository.setKeyboardShortcutTriggered(ALL_APPS)

            val model by
                collectLastValue(
                    kosmos.contextualEducationRepository.readGestureEduModelFlow(ALL_APPS)
                )
            assertThat(model?.lastShortcutTriggeredTime).isEqualTo(eduClock.instant())
        }

    @Test
    fun dataUpdatedOnIncrementSignalCountWhenTouchpadConnected() =
        testScope.runTest {
            assumeTrue(gestureType != ALL_APPS)
            setUpForInitialDelayElapse()
            touchpadRepository.setIsAnyTouchpadConnected(true)

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue + 1)
        }

    @Test
    fun dataUnchangedOnIncrementSignalCountWhenTouchpadDisconnected() =
        testScope.runTest {
            setUpForInitialDelayElapse()
            touchpadRepository.setIsAnyTouchpadConnected(false)

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue)
        }

    @Test
    fun dataUpdatedOnIncrementSignalCountWhenKeyboardConnected() =
        testScope.runTest {
            assumeTrue(gestureType == ALL_APPS)
            setUpForInitialDelayElapse()
            keyboardRepository.setIsAnyKeyboardConnected(true)

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue + 1)
        }

    @Test
    fun dataUnchangedOnIncrementSignalCountWhenKeyboardDisconnected() =
        testScope.runTest {
            setUpForInitialDelayElapse()
            keyboardRepository.setIsAnyKeyboardConnected(false)

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue)
        }

    @Test
    fun dataAddedOnUpdateShortcutTriggerTime() =
        testScope.runTest {
            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            assertThat(model?.lastShortcutTriggeredTime).isNull()

            updateContextualEduStats(/* isTrackpadGesture= */ true, gestureType)

            assertThat(model?.lastShortcutTriggeredTime).isEqualTo(kosmos.fakeEduClock.instant())
        }

    @Test
    fun dataUpdatedOnIncrementSignalCountAfterInitialDelay() =
        testScope.runTest {
            setUpForDeviceConnection()
            tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            eduClock.offset(initialDelayElapsedDuration)
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue + 1)
        }

    @Test
    fun dataUnchangedOnIncrementSignalCountBeforeInitialDelay() =
        testScope.runTest {
            setUpForDeviceConnection()
            tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            // No offset to the clock to simulate update before initial delay
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue)
        }

    @Test
    fun dataUnchangedOnIncrementSignalCountWithoutOobeLaunchOrNotifyTime() =
        testScope.runTest {
            // No update to OOBE launch/notify time to simulate no OOBE is launched yet
            setUpForDeviceConnection()

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue)
        }

    @Test
    fun dataUpdatedOnIncrementSignalCountAfterNotifyTimeDelayWithoutLaunchTime() =
        testScope.runTest {
            setUpForDeviceConnection()
            tutorialSchedulerRepository.setNotifiedTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )

            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            eduClock.offset(initialDelayElapsedDuration)
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue + 1)
        }

    @Test
    fun dataUnchangedOnIncrementSignalCountBeforeLaunchTimeDelayWithNotifyTime() =
        testScope.runTest {
            setUpForDeviceConnection()
            tutorialSchedulerRepository.setNotifiedTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )
            eduClock.offset(initialDelayElapsedDuration)

            tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )
            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            // No offset to the clock to simulate update before initial delay of launch time
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue)
        }

    @Test
    fun dataUpdatedOnIncrementSignalCountAfterLaunchTimeDelayWithNotifyTime() =
        testScope.runTest {
            setUpForDeviceConnection()
            tutorialSchedulerRepository.setNotifiedTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )
            eduClock.offset(initialDelayElapsedDuration)

            tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
                getTargetDevice(gestureType),
                eduClock.instant(),
            )
            val model by collectLastValue(repository.readGestureEduModelFlow(gestureType))
            val originalValue = model!!.signalCount
            eduClock.offset(initialDelayElapsedDuration)
            updateContextualEduStats(/* isTrackpadGesture= */ false, gestureType)

            assertThat(model?.signalCount).isEqualTo(originalValue + 1)
        }

    private suspend fun setUpForInitialDelayElapse() {
        tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
            DeviceType.TOUCHPAD,
            eduClock.instant(),
        )
        tutorialSchedulerRepository.setScheduledTutorialLaunchTime(
            DeviceType.KEYBOARD,
            eduClock.instant(),
        )
        eduClock.offset(initialDelayElapsedDuration)
    }

    fun logMetricsForToastEducation() =
        testScope.runTest {
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            verify(kosmos.mockEduMetricsLogger)
                .logContextualEducationTriggered(gestureType, EducationUiType.Toast)
        }

    @Test
    fun logMetricsForNotificationEducation() =
        testScope.runTest {
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            eduClock.offset(minDurationForNextEdu)
            triggerMaxEducationSignals(gestureType)
            runCurrent()

            verify(kosmos.mockEduMetricsLogger)
                .logContextualEducationTriggered(gestureType, EducationUiType.Notification)
        }

    @After
    fun clear() {
        testScope.launch { tutorialSchedulerRepository.clear() }
    }

    private suspend fun triggerMaxEducationSignals(gestureType: GestureType) {
        // Increment max number of signal to try triggering education
        for (i in 1..KeyboardTouchpadEduInteractor.MAX_SIGNAL_COUNT) {
            contextualEduInteractor.incrementSignalCount(gestureType)
        }
    }

    private fun TestScope.setIsAnyTouchpadConnected(isConnected: Boolean) {
        touchpadRepository.setIsAnyTouchpadConnected(isConnected)
        runCurrent()
    }

    private fun TestScope.setIsAnyKeyboardConnected(isConnected: Boolean) {
        keyboardRepository.setIsAnyKeyboardConnected(isConnected)
        runCurrent()
    }

    private fun setUpForDeviceConnection() {
        touchpadRepository.setIsAnyTouchpadConnected(true)
        keyboardRepository.setIsAnyKeyboardConnected(true)
    }

    private fun updateContextualEduStats(isTrackpadGesture: Boolean, gestureType: GestureType) {
        val listenerCaptor = argumentCaptor<LauncherProxyListener>()
        verify(launcherProxyService).addCallback(listenerCaptor.capture())
        listenerCaptor.firstValue.updateContextualEduStats(isTrackpadGesture, gestureType)
    }

    private fun getTargetDevice(gestureType: GestureType) =
        when (gestureType) {
            ALL_APPS -> DeviceType.KEYBOARD
            else -> DeviceType.TOUCHPAD
        }

    companion object {
        private val USER_INFOS = listOf(UserInfo(101, "Second User", 0))

        @JvmStatic
        @Parameters(name = "{0}")
        fun getGestureTypes(): List<GestureType> {
            return listOf(BACK, HOME, OVERVIEW, ALL_APPS)
        }
    }
}
