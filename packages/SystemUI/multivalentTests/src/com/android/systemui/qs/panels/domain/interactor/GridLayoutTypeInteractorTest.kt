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

package com.android.systemui.qs.panels.domain.interactor

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.flags.EnableSceneContainer
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.runTest
import com.android.systemui.qs.panels.shared.model.InfiniteGridLayoutType
import com.android.systemui.qs.panels.shared.model.PaginatedGridLayoutType
import com.android.systemui.shade.domain.interactor.enableDualShade
import com.android.systemui.shade.domain.interactor.enableSingleShade
import com.android.systemui.shade.domain.interactor.enableSplitShade
import com.android.systemui.testKosmos
import com.google.common.truth.Truth.assertThat
import kotlin.test.Test
import org.junit.runner.RunWith

@SmallTest
@RunWith(AndroidJUnit4::class)
@EnableSceneContainer
class GridLayoutTypeInteractorTest : SysuiTestCase() {
    val kosmos = testKosmos()

    val Kosmos.underTest by Kosmos.Fixture { kosmos.gridLayoutTypeInteractor }

    @Test
    fun noDualShade_gridAlwaysPaginated() =
        kosmos.runTest {
            val type by collectLastValue(underTest.layout)

            kosmos.enableSingleShade()
            assertThat(type).isEqualTo(PaginatedGridLayoutType)

            kosmos.enableSplitShade()
            assertThat(type).isEqualTo(PaginatedGridLayoutType)
        }

    @Test
    fun dualShade_gridAlwaysInfinite() =
        kosmos.runTest {
            val type by collectLastValue(underTest.layout)

            kosmos.enableDualShade(wideLayout = false)
            assertThat(type).isEqualTo(InfiniteGridLayoutType)

            kosmos.enableDualShade(wideLayout = true)
            assertThat(type).isEqualTo(InfiniteGridLayoutType)
        }
}
