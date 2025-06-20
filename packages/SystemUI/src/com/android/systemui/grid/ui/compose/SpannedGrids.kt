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
package com.android.systemui.grid.ui.compose

import androidx.collection.IntIntPair
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.semantics.CollectionInfo
import androidx.compose.ui.semantics.CollectionItemInfo
import androidx.compose.ui.semantics.collectionInfo
import androidx.compose.ui.semantics.collectionItemInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.util.fastForEachIndexed
import androidx.compose.ui.util.fastMapIndexed
import kotlin.math.max

/**
 * Horizontal (non lazy) grid that supports [spans] for its elements.
 *
 * The elements will be laid down vertically first, and then by columns. So assuming LTR layout, it
 * will be (for a span list `[2, 1, 2, 1, 1, 1, 1, 1]` and 4 rows):
 * ```
 * 0  2  5
 * 0  2  6
 * 1  3  7
 *    4
 * ```
 *
 * where repeated numbers show larger span. If an element doesn't fit in a column due to its span,
 * it will start a new column.
 *
 * Elements in [spans] must be in the interval `[1, rows]` ([rows] > 0), and the composables are
 * associated with the corresponding span based on their index.
 *
 * Due to the fact that elements are seen as a linear list that's laid out in a grid, the semantics
 * represent the collection as a list of elements.
 */
@Composable
fun HorizontalSpannedGrid(
    rows: Int,
    columnSpacing: Dp,
    rowSpacing: Dp,
    spans: List<Int>,
    modifier: Modifier = Modifier,
    keys: (spanIndex: Int) -> Any = { it },
    composables:
        @Composable
        BoxScope.(
            spanIndex: Int, row: Int, isFirstInColumn: Boolean, isLastInColumn: Boolean,
        ) -> Unit,
) {
    SpannedGrid(
        primarySpaces = rows,
        crossAxisSpacing = rowSpacing,
        mainAxisSpacing = columnSpacing,
        spans = spans,
        isVertical = false,
        modifier = modifier,
        keys = keys,
        composables = composables,
    )
}

/**
 * Vertical (non lazy) grid that supports [spans] for its elements.
 *
 * The elements will be laid down horizontally first, and then by rows. So assuming LTR layout, it
 * will be (for a span list `[2, 1, 2, 1, 1, 1, 1, 1]` and 4 columns):
 * ```
 * 0  0  1
 * 2  2  3  4
 * 5  6  7
 * ```
 *
 * where repeated numbers show larger span. If an element doesn't fit in a row due to its span, it
 * will start a new row.
 *
 * Elements in [spans] must be in the interval `[1, columns]` ([columns] > 0), and the composables
 * are associated with the corresponding span based on their index.
 *
 * Due to the fact that elements are seen as a linear list that's laid out in a grid, the semantics
 * represent the collection as a list of elements.
 */
@Composable
fun VerticalSpannedGrid(
    columns: Int,
    columnSpacing: Dp,
    rowSpacing: Dp,
    spans: List<Int>,
    modifier: Modifier = Modifier,
    keys: (spanIndex: Int) -> Any = { it },
    composables:
        @Composable
        BoxScope.(spanIndex: Int, column: Int, isFirstInRow: Boolean, isLastInRow: Boolean) -> Unit,
) {
    SpannedGrid(
        primarySpaces = columns,
        crossAxisSpacing = columnSpacing,
        mainAxisSpacing = rowSpacing,
        spans = spans,
        isVertical = true,
        modifier = modifier,
        keys = keys,
        composables = composables,
    )
}

@Composable
private fun SpannedGrid(
    primarySpaces: Int,
    crossAxisSpacing: Dp,
    mainAxisSpacing: Dp,
    spans: List<Int>,
    isVertical: Boolean,
    modifier: Modifier = Modifier,
    keys: (spanIndex: Int) -> Any = { it },
    composables:
        @Composable
        BoxScope.(spanIndex: Int, secondaryAxis: Int, isFirst: Boolean, isLast: Boolean) -> Unit,
) {
    val crossAxisArrangement = Arrangement.spacedBy(crossAxisSpacing)
    spans.forEachIndexed { index, span ->
        check(span in 1..primarySpaces) {
            "Span out of bounds. Span at index $index has value of $span which is outside of the " +
                "expected rance of [1, $primarySpaces]"
        }
    }
    if (isVertical) {
        check(crossAxisSpacing >= 0.dp) { "Negative columnSpacing $crossAxisSpacing" }
        check(mainAxisSpacing >= 0.dp) { "Negative rowSpacing $mainAxisSpacing" }
    } else {
        check(mainAxisSpacing >= 0.dp) { "Negative columnSpacing $mainAxisSpacing" }
        check(crossAxisSpacing >= 0.dp) { "Negative rowSpacing $crossAxisSpacing" }
    }
    // List of primary axis index to secondary axis index
    // This is keyed to the size of the spans list for performance reasons as we don't expect the
    // spans value to change outside of edit mode.
    val positions = remember(spans.size) { Array(spans.size) { IntIntPair(0, 0) } }
    val totalMainAxisGroups =
        remember(primarySpaces, spans) {
            var mainAxisGroup = 0
            var currentSlot = 0
            spans.fastForEachIndexed { index, span ->
                if (currentSlot + span > primarySpaces) {
                    currentSlot = 0
                    mainAxisGroup += 1
                }
                positions[index] = IntIntPair(mainAxisGroup, currentSlot)
                currentSlot += span
            }
            mainAxisGroup + 1
        }
    val slotPositionsAndSizesCache = remember {
        object {
            var sizes = IntArray(0)
            var positions = IntArray(0)
        }
    }
    Layout(
        {
            (0 until spans.size).map { spanIndex ->
                key(keys(spanIndex)) {
                    Box(
                        Modifier.semantics {
                            collectionItemInfo =
                                if (isVertical) {
                                    CollectionItemInfo(spanIndex, 1, 0, 1)
                                } else {
                                    CollectionItemInfo(0, 1, spanIndex, 1)
                                }
                        }
                    ) {
                        val position = positions[spanIndex]
                        composables(
                            spanIndex,
                            position.second,
                            position.second == 0,
                            positions.getOrNull(spanIndex + 1)?.first != position.first,
                        )
                    }
                }
            }
        },
        modifier.semantics { collectionInfo = CollectionInfo(spans.size, 1) },
    ) { measurables, constraints ->
        check(measurables.size == spans.size)
        val crossAxisSize = if (isVertical) constraints.maxWidth else constraints.maxHeight
        check(crossAxisSize != Constraints.Infinity) { "Width must be constrained" }
        if (slotPositionsAndSizesCache.sizes.size != primarySpaces) {
            slotPositionsAndSizesCache.sizes = IntArray(primarySpaces)
            slotPositionsAndSizesCache.positions = IntArray(primarySpaces)
        }
        calculateCellsCrossAxisSize(
            crossAxisSize,
            primarySpaces,
            crossAxisSpacing.roundToPx(),
            slotPositionsAndSizesCache.sizes,
        )
        val cellSizesInCrossAxis = slotPositionsAndSizesCache.sizes
        // with is needed because of the double receiver (Density, Arrangement).
        with(crossAxisArrangement) {
            arrange(
                crossAxisSize,
                slotPositionsAndSizesCache.sizes,
                LayoutDirection.Ltr,
                slotPositionsAndSizesCache.positions,
            )
        }
        val startPositions = slotPositionsAndSizesCache.positions
        val mainAxisSpacingPx = mainAxisSpacing.roundToPx()
        val mainAxisTotalGaps = (totalMainAxisGroups - 1) * mainAxisSpacingPx
        val mainAxisMaxSize = if (isVertical) constraints.maxHeight else constraints.maxWidth
        val mainAxisElementConstraint =
            if (mainAxisMaxSize == Constraints.Infinity) {
                Constraints.Infinity
            } else {
                max(0, (mainAxisMaxSize - mainAxisTotalGaps) / totalMainAxisGroups)
            }

        var mainAxisTotalSize = mainAxisTotalGaps
        var currentMainAxis = 0
        var currentMainAxisMax = 0
        val placeables =
            measurables.fastMapIndexed { index, measurable ->
                val span = spans[index]
                val position = positions[index]
                val crossAxisConstraint =
                    calculateWidth(cellSizesInCrossAxis, startPositions, position.second, span)

                measurable
                    .measure(
                        makeConstraint(isVertical, mainAxisElementConstraint, crossAxisConstraint)
                    )
                    .also {
                        val placeableSize = if (isVertical) it.height else it.width
                        if (position.first != currentMainAxis) {
                            // New row -- Add the max size to the total and reset the max
                            mainAxisTotalSize += currentMainAxisMax
                            currentMainAxisMax = placeableSize
                            currentMainAxis = position.first
                        } else {
                            currentMainAxisMax = max(currentMainAxisMax, placeableSize)
                        }
                    }
            }
        mainAxisTotalSize += currentMainAxisMax

        val height = if (isVertical) mainAxisTotalSize else crossAxisSize
        val width = if (isVertical) crossAxisSize else mainAxisTotalSize

        layout(width, height) {
            var previousMainAxis = 0
            var currentMainAxisPosition = 0
            var currentMainAxisMax = 0
            placeables.forEachIndexed { index, placeable ->
                val slot = positions[index].second
                val mainAxisSize = if (isVertical) placeable.height else placeable.width

                if (positions[index].first != previousMainAxis) {
                    // Move up a row + padding
                    currentMainAxisPosition += currentMainAxisMax + mainAxisSpacingPx
                    currentMainAxisMax = mainAxisSize
                    previousMainAxis = positions[index].first
                } else {
                    currentMainAxisMax = max(currentMainAxisMax, mainAxisSize)
                }

                val x =
                    if (isVertical) {
                        startPositions[slot]
                    } else {
                        currentMainAxisPosition
                    }
                val y =
                    if (isVertical) {
                        currentMainAxisPosition
                    } else {
                        startPositions[slot]
                    }
                placeable.placeRelative(x, y)
            }
        }
    }
}

fun makeConstraint(isVertical: Boolean, mainAxisSize: Int, crossAxisSize: Int): Constraints {
    return if (isVertical) {
        Constraints(maxHeight = mainAxisSize, minWidth = crossAxisSize, maxWidth = crossAxisSize)
    } else {
        Constraints(maxWidth = mainAxisSize, minHeight = crossAxisSize, maxHeight = crossAxisSize)
    }
}

private fun calculateWidth(sizes: IntArray, positions: IntArray, startSlot: Int, span: Int): Int {
    val crossAxisSize =
        if (span == 1) {
                sizes[startSlot]
            } else {
                val endSlot = startSlot + span - 1
                positions[endSlot] + sizes[endSlot] - positions[startSlot]
            }
            .coerceAtLeast(0)
    return crossAxisSize
}

private fun calculateCellsCrossAxisSize(
    gridSize: Int,
    slotCount: Int,
    spacingPx: Int,
    outArray: IntArray,
) {
    check(outArray.size == slotCount)
    val gridSizeWithoutSpacing = gridSize - spacingPx * (slotCount - 1)
    val slotSize = gridSizeWithoutSpacing / slotCount
    val remainingPixels = gridSizeWithoutSpacing % slotCount
    outArray.indices.forEach { index ->
        outArray[index] = slotSize + if (index < remainingPixels) 1 else 0
    }
}
