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

package com.android.systemui.communal.data.db

import android.content.ComponentName
import android.os.UserHandle
import android.os.userManager
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.communal.data.db.DefaultWidgetPopulation.SkipReason.RESTORED_FROM_BACKUP
import com.android.systemui.communal.shared.model.SpanValue
import com.android.systemui.communal.widgets.CommunalWidgetHost
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.useUnconfinedTestDispatcher
import com.android.systemui.log.logcatLogBuffer
import com.android.systemui.testKosmos
import com.android.systemui.user.data.repository.FakeUserRepository.Companion.MAIN_USER_ID
import com.android.systemui.user.data.repository.fakeUserRepository
import com.android.systemui.user.domain.interactor.userLockedInteractor
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify

@SmallTest
@RunWith(AndroidJUnit4::class)
class DefaultWidgetPopulationTest : SysuiTestCase() {
    private val kosmos = testKosmos().useUnconfinedTestDispatcher()

    private val communalWidgetHost =
        mock<CommunalWidgetHost> {
            var nextId = 0
            on { allocateIdAndBindWidget(any(), anyOrNull()) }.thenAnswer { nextId++ }
        }
    private val communalWidgetDao = mock<CommunalWidgetDao>()
    private val database = mock<SupportSQLiteDatabase>()
    private val mainUser = UserHandle(0)

    private val defaultWidgets =
        arrayOf(
            "com.android.test_package_1/fake_widget_1",
            "com.android.test_package_2/fake_widget_2",
            "com.android.test_package_3/fake_widget_3",
        )

    private lateinit var underTest: DefaultWidgetPopulation

    @Before
    fun setUp() {
        kosmos.fakeUserRepository.setUserUnlocked(MAIN_USER_ID, true)
        underTest =
            DefaultWidgetPopulation(
                bgScope = kosmos.applicationCoroutineScope,
                communalWidgetHost = communalWidgetHost,
                communalWidgetDaoProvider = { communalWidgetDao },
                defaultWidgets = defaultWidgets,
                logBuffer = logcatLogBuffer("DefaultWidgetPopulationTest"),
                userManager = kosmos.userManager,
                userLockedInteractor = kosmos.userLockedInteractor,
            )
    }

    @Test
    fun testNoInteractionUntilMainUserUnlocked() =
        kosmos.runTest {
            kosmos.fakeUserRepository.setUserUnlocked(MAIN_USER_ID, false)
            // Database created
            underTest.onCreate(database)
            verify(communalWidgetHost, never())
                .allocateIdAndBindWidget(provider = any(), user = any())
            kosmos.fakeUserRepository.setUserUnlocked(MAIN_USER_ID, true)
            verify(communalWidgetHost, atLeastOnce())
                .allocateIdAndBindWidget(provider = any(), user = any())
        }

    @Test
    fun testPopulateDefaultWidgetsWhenDatabaseCreated() =
        kosmos.runTest {
            // Database created
            underTest.onCreate(database)

            // Verify default widgets bound
            verify(communalWidgetHost)
                .allocateIdAndBindWidget(
                    provider = eq(ComponentName.unflattenFromString(defaultWidgets[0])!!),
                    user = eq(UserHandle(MAIN_USER_ID)),
                )
            verify(communalWidgetHost)
                .allocateIdAndBindWidget(
                    provider = eq(ComponentName.unflattenFromString(defaultWidgets[1])!!),
                    user = eq(UserHandle(MAIN_USER_ID)),
                )
            verify(communalWidgetHost)
                .allocateIdAndBindWidget(
                    provider = eq(ComponentName.unflattenFromString(defaultWidgets[2])!!),
                    user = eq(UserHandle(MAIN_USER_ID)),
                )

            // Verify default widgets added in database
            verify(communalWidgetDao)
                .addWidget(
                    widgetId = 0,
                    componentName = defaultWidgets[0],
                    rank = 0,
                    userSerialNumber = 0,
                    spanY = SpanValue.Fixed(3),
                )
            verify(communalWidgetDao)
                .addWidget(
                    widgetId = 1,
                    componentName = defaultWidgets[1],
                    rank = 1,
                    userSerialNumber = 0,
                    spanY = SpanValue.Fixed(3),
                )
            verify(communalWidgetDao)
                .addWidget(
                    widgetId = 2,
                    componentName = defaultWidgets[2],
                    rank = 2,
                    userSerialNumber = 0,
                    spanY = SpanValue.Fixed(3),
                )
        }

    @Test
    fun testSkipDefaultWidgetsPopulation() =
        kosmos.runTest {
            // Skip default widgets population
            underTest.skipDefaultWidgetsPopulation(RESTORED_FROM_BACKUP)

            // Database created
            underTest.onCreate(database)

            // Verify no widget bounded or added to the database
            verify(communalWidgetHost, never()).allocateIdAndBindWidget(any(), any())
            verify(communalWidgetDao, never())
                .addWidget(
                    widgetId = anyInt(),
                    componentName = any(),
                    rank = anyInt(),
                    userSerialNumber = anyInt(),
                    spanY = any(),
                )
        }
}
