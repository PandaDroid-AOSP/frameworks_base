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

package com.android.systemui.qs.panels.ui.compose

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performCustomAccessibilityActionWithLabel
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeLeft
import androidx.compose.ui.test.swipeRight
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.compose.theme.PlatformTheme
import com.android.systemui.SysuiTestCase
import com.android.systemui.common.shared.model.ContentDescription
import com.android.systemui.common.shared.model.Icon
import com.android.systemui.qs.panels.shared.model.SizedTile
import com.android.systemui.qs.panels.shared.model.SizedTileImpl
import com.android.systemui.qs.panels.ui.compose.infinitegrid.DefaultEditTileGrid
import com.android.systemui.qs.panels.ui.viewmodel.EditTileViewModel
import com.android.systemui.qs.pipeline.shared.TileSpec
import com.android.systemui.qs.shared.model.TileCategory
import com.android.systemui.res.R
import com.google.common.truth.Truth.assertThat
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@OptIn(ExperimentalTestApi::class)
@SmallTest
@RunWith(AndroidJUnit4::class)
class ResizingTest : SysuiTestCase() {
    @get:Rule val composeRule = createComposeRule()

    @Composable
    private fun EditTileGridUnderTest(
        listState: EditTileListState,
        onResize: (TileSpec, Boolean) -> Unit,
    ) {
        PlatformTheme {
            DefaultEditTileGrid(
                listState = listState,
                otherTiles = listOf(),
                columns = 4,
                largeTilesSpan = 4,
                modifier = Modifier.fillMaxSize(),
                onAddTile = { _, _ -> },
                onRemoveTile = {},
                onSetTiles = {},
                onResize = onResize,
                onStopEditing = {},
                onReset = null,
            )
        }
    }

    @Test
    fun toggleIconTileWithA11yAction_shouldBeLarge() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileA")
            .onFirst()
            .performCustomAccessibilityActionWithLabel(
                context.getString(R.string.accessibility_qs_edit_toggle_tile_size_action)
            )

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileA" }?.width).isEqualTo(2)
    }

    @Test
    fun toggleLargeTileWithA11yAction_shouldBeIcon() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileD_large")
            .onFirst()
            .performCustomAccessibilityActionWithLabel(
                context.getString(R.string.accessibility_qs_edit_toggle_tile_size_action)
            )

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileD_large" }?.width).isEqualTo(1)
    }

    @Test
    fun tapOnIconResizingHandle_shouldBeLarge() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileA")
            .onFirst()
            .performClick() // Select
            .performTouchInput { // Tap on resizing handle
                click(centerRight)
            }
        composeRule.waitForIdle()

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileA" }?.width).isEqualTo(2)
    }

    @Test
    fun tapOnLargeResizingHandle_shouldBeIcon() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileD_large")
            .onFirst()
            .performClick() // Select
            .performTouchInput { // Tap on resizing handle
                click(centerRight)
            }
        composeRule.waitForIdle()

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileD_large" }?.width).isEqualTo(1)
    }

    @Test
    fun resizedIcon_shouldBeLarge() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileA")
            .onFirst()
            .performClick() // Select
            .performTouchInput { // Resize up
                swipeRight(startX = right, endX = right * 2)
            }
        composeRule.waitForIdle()

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileA" }?.width).isEqualTo(2)
    }

    @Test
    fun resizedLarge_shouldBeIcon() {
        var tiles by mutableStateOf(TestEditTiles)
        val listState = EditTileListState(tiles, columns = 4, largeTilesSpan = 2)
        composeRule.setContent {
            EditTileGridUnderTest(listState) { spec, toIcon -> tiles = tiles.resize(spec, toIcon) }
        }
        composeRule.waitForIdle()

        composeRule
            .onAllNodesWithText("tileD_large")
            .onFirst()
            .performClick() // Select
            .performTouchInput { // Resize down
                swipeLeft()
            }
        composeRule.waitForIdle()

        assertThat(tiles.find { it.tile.tileSpec.spec == "tileD_large" }?.width).isEqualTo(1)
    }

    companion object {
        private fun List<SizedTile<EditTileViewModel>>.resize(
            spec: TileSpec,
            toIcon: Boolean,
        ): List<SizedTile<EditTileViewModel>> {
            return map {
                if (it.tile.tileSpec == spec) {
                    SizedTileImpl(it.tile, width = if (toIcon) 1 else 2)
                } else {
                    it
                }
            }
        }

        private fun createEditTile(tileSpec: String): SizedTile<EditTileViewModel> {
            return SizedTileImpl(
                EditTileViewModel(
                    tileSpec = TileSpec.create(tileSpec),
                    icon =
                        Icon.Resource(
                            android.R.drawable.star_on,
                            ContentDescription.Loaded(tileSpec),
                        ),
                    label = AnnotatedString(tileSpec),
                    appName = null,
                    isCurrent = true,
                    availableEditActions = emptySet(),
                    category = TileCategory.UNKNOWN,
                ),
                getWidth(tileSpec),
            )
        }

        private fun getWidth(tileSpec: String): Int {
            return if (tileSpec.endsWith("large")) {
                2
            } else {
                1
            }
        }

        private val TestEditTiles =
            listOf(
                createEditTile("tileA"),
                createEditTile("tileB"),
                createEditTile("tileC"),
                createEditTile("tileD_large"),
                createEditTile("tileE"),
            )
    }
}
