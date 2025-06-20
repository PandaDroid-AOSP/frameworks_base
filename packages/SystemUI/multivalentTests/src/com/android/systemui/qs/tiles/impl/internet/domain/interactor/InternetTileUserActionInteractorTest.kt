/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.systemui.qs.tiles.impl.internet.domain.interactor

import android.platform.test.annotations.EnabledOnRavenwood
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.kosmos.testScope
import com.android.systemui.qs.tiles.base.domain.actions.FakeQSTileIntentUserInputHandler
import com.android.systemui.qs.tiles.base.domain.actions.QSTileIntentUserInputHandlerSubject
import com.android.systemui.qs.tiles.base.domain.model.QSTileInputTestKtx
import com.android.systemui.qs.tiles.dialog.InternetDialogManager
import com.android.systemui.qs.tiles.impl.internet.domain.model.InternetTileModel
import com.android.systemui.statusbar.connectivity.AccessPointController
import com.android.systemui.testKosmos
import com.android.systemui.util.mockito.nullable
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify

@SmallTest
@EnabledOnRavenwood
@RunWith(AndroidJUnit4::class)
class InternetTileUserActionInteractorTest : SysuiTestCase() {
    private val kosmos = testKosmos()
    private val inputHandler = FakeQSTileIntentUserInputHandler()

    private lateinit var underTest: InternetTileUserActionInteractor

    private lateinit var internetDialogManager: InternetDialogManager
    private lateinit var controller: AccessPointController

    @Before
    fun setup() {
        internetDialogManager = mock<InternetDialogManager>()
        controller = mock<AccessPointController>()
        underTest =
            InternetTileUserActionInteractor(
                kosmos.testScope.coroutineContext,
                internetDialogManager,
                controller,
                inputHandler,
            )
    }

    @Test
    fun handleClickWhenActive() =
        kosmos.testScope.runTest {
            val input = InternetTileModel.Active()

            underTest.handleInput(QSTileInputTestKtx.click(input))

            verify(internetDialogManager).create(eq(true), anyBoolean(), anyBoolean(), nullable())
        }

    @Test
    fun handleClickWhenInactive() =
        kosmos.testScope.runTest {
            val input = InternetTileModel.Inactive()

            underTest.handleInput(QSTileInputTestKtx.click(input))

            verify(internetDialogManager).create(eq(true), anyBoolean(), anyBoolean(), nullable())
        }

    @Test
    fun handleLongClickWhenActive() =
        kosmos.testScope.runTest {
            val input = InternetTileModel.Active()

            underTest.handleInput(QSTileInputTestKtx.longClick(input))

            QSTileIntentUserInputHandlerSubject.assertThat(inputHandler).handledOneIntentInput {
                assertThat(it.intent.action).isEqualTo(Settings.ACTION_WIFI_SETTINGS)
            }
        }

    @Test
    fun handleLongClickWhenInactive() =
        kosmos.testScope.runTest {
            val input = InternetTileModel.Inactive()

            underTest.handleInput(QSTileInputTestKtx.longClick(input))

            QSTileIntentUserInputHandlerSubject.assertThat(inputHandler).handledOneIntentInput {
                assertThat(it.intent.action).isEqualTo(Settings.ACTION_WIFI_SETTINGS)
            }
        }
}
