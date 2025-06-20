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

package com.android.systemui.statusbar.notification.stack.domain.interactor

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.kosmos.testScope
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.shade.data.repository.shadeRepository
import com.android.systemui.statusbar.notification.stack.shared.model.ShadeScrimBounds
import com.android.systemui.statusbar.notification.stack.shared.model.ShadeScrimRounding
import com.android.systemui.statusbar.notification.stack.shared.model.ShadeScrimShape
import com.android.systemui.testKosmos
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith

@SmallTest
@RunWith(AndroidJUnit4::class)
class NotificationStackAppearanceInteractorTest : SysuiTestCase() {

    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val underTest = kosmos.notificationStackAppearanceInteractor

    @Test
    fun stackNotificationScrimBounds() =
        testScope.runTest {
            val stackBounds by collectLastValue(underTest.notificationShadeScrimBounds)

            val bounds1 = ShadeScrimBounds(top = 100f, bottom = 200f)
            underTest.setNotificationShadeScrimBounds(bounds1)
            assertThat(stackBounds).isEqualTo(bounds1)

            val bounds2 = ShadeScrimBounds(top = 200f, bottom = 300f)
            underTest.setNotificationShadeScrimBounds(bounds2)
            assertThat(stackBounds).isEqualTo(bounds2)
        }

    fun setQsPanelShape() =
        testScope.runTest {
            var actual: ShadeScrimShape? = null
            underTest.setQsPanelShapeConsumer { shape -> actual = shape }

            val expected1 =
                ShadeScrimShape(
                    bounds = ShadeScrimBounds(top = 0f, bottom = 100f),
                    topRadius = 0,
                    bottomRadius = 10,
                )
            assertThat(actual).isEqualTo(expected1)

            val expected2 = expected1.copy(topRadius = 10)
            assertThat(expected2).isEqualTo(actual)
        }

    @Test
    fun stackRounding() =
        testScope.runTest {
            val stackRounding by collectLastValue(underTest.shadeScrimRounding)

            kosmos.shadeRepository.setShadeLayoutWide(false)
            assertThat(stackRounding)
                .isEqualTo(ShadeScrimRounding(isTopRounded = true, isBottomRounded = false))

            kosmos.shadeRepository.setShadeLayoutWide(true)
            assertThat(stackRounding)
                .isEqualTo(ShadeScrimRounding(isTopRounded = true, isBottomRounded = true))
        }

    @Test(expected = IllegalStateException::class)
    fun stackNotificationScrimBounds_withImproperBounds_throwsException() =
        testScope.runTest {
            underTest.setNotificationShadeScrimBounds(ShadeScrimBounds(top = 100f, bottom = 99f))
        }

    @Test(expected = IllegalStateException::class)
    fun setQsPanelShape_withImproperBounds_throwsException() =
        testScope.runTest {
            val invalidBounds = ShadeScrimBounds(top = 0f, bottom = -10f)
            underTest.sendQsPanelShape(
                ShadeScrimShape(bounds = invalidBounds, topRadius = 10, bottomRadius = 10)
            )
        }

    @Test
    fun shouldCloseGuts_userInputOngoing_currentGestureInGuts() =
        testScope.runTest {
            val shouldCloseGuts by collectLastValue(underTest.shouldCloseGuts)

            kosmos.sceneInteractor.onSceneContainerUserInputStarted()
            underTest.setCurrentGestureInGuts(true)

            assertThat(shouldCloseGuts).isFalse()
        }

    @Test
    fun shouldCloseGuts_userInputOngoing_currentGestureNotInGuts() =
        testScope.runTest {
            val shouldCloseGuts by collectLastValue(underTest.shouldCloseGuts)

            kosmos.sceneInteractor.onSceneContainerUserInputStarted()
            underTest.setCurrentGestureInGuts(false)

            assertThat(shouldCloseGuts).isTrue()
        }

    @Test
    fun shouldCloseGuts_userInputNotOngoing_currentGestureInGuts() =
        testScope.runTest {
            val shouldCloseGuts by collectLastValue(underTest.shouldCloseGuts)

            kosmos.sceneInteractor.onUserInputFinished()
            underTest.setCurrentGestureInGuts(true)

            assertThat(shouldCloseGuts).isFalse()
        }

    @Test
    fun shouldCloseGuts_userInputNotOngoing_currentGestureNotInGuts() =
        testScope.runTest {
            val shouldCloseGuts by collectLastValue(underTest.shouldCloseGuts)

            kosmos.sceneInteractor.onUserInputFinished()
            underTest.setCurrentGestureInGuts(false)

            assertThat(shouldCloseGuts).isFalse()
        }
}
