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

package com.android.systemui.communal

import android.platform.test.annotations.EnableFlags
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.Flags.FLAG_COMMUNAL_HUB
import com.android.systemui.SysuiTestCase
import com.android.systemui.communal.data.repository.communalMediaRepository
import com.android.systemui.communal.data.repository.communalSmartspaceRepository
import com.android.systemui.communal.data.repository.fakeCommunalMediaRepository
import com.android.systemui.communal.data.repository.fakeCommunalSmartspaceRepository
import com.android.systemui.communal.domain.interactor.communalInteractor
import com.android.systemui.communal.domain.interactor.communalSettingsInteractor
import com.android.systemui.communal.domain.interactor.setCommunalEnabled
import com.android.systemui.flags.Flags
import com.android.systemui.flags.fakeFeatureFlagsClassic
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.useUnconfinedTestDispatcher
import com.android.systemui.testKosmos
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@SmallTest
@EnableFlags(FLAG_COMMUNAL_HUB)
@RunWith(AndroidJUnit4::class)
class CommunalOngoingContentStartableTest : SysuiTestCase() {
    private val kosmos = testKosmos().useUnconfinedTestDispatcher()

    private var showUmoOnHub = true

    private val Kosmos.underTest by
        Kosmos.Fixture {
            CommunalOngoingContentStartable(
                bgScope = applicationCoroutineScope,
                communalInteractor = communalInteractor,
                communalMediaRepository = communalMediaRepository,
                communalSettingsInteractor = communalSettingsInteractor,
                communalSmartspaceRepository = communalSmartspaceRepository,
                showUmoOnHub = showUmoOnHub,
            )
        }

    @Before
    fun setUp() {
        kosmos.fakeFeatureFlagsClassic.set(Flags.COMMUNAL_SERVICE_ENABLED, true)
    }

    @Test
    fun testListenForOngoingContent() =
        kosmos.runTest {
            underTest.start()

            assertThat(fakeCommunalMediaRepository.isListening()).isFalse()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isFalse()

            setCommunalEnabled(true)

            assertThat(fakeCommunalMediaRepository.isListening()).isTrue()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isTrue()

            setCommunalEnabled(false)

            assertThat(fakeCommunalMediaRepository.isListening()).isFalse()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isFalse()
        }

    @Test
    fun testListenForOngoingContent_showUmoFalse() =
        kosmos.runTest {
            showUmoOnHub = false
            underTest.start()

            assertThat(fakeCommunalMediaRepository.isListening()).isFalse()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isFalse()

            setCommunalEnabled(true)

            // Media listening does not start when UMO is disabled.
            assertThat(fakeCommunalMediaRepository.isListening()).isFalse()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isTrue()

            setCommunalEnabled(false)

            assertThat(fakeCommunalMediaRepository.isListening()).isFalse()
            assertThat(fakeCommunalSmartspaceRepository.isListening()).isFalse()
        }
}
