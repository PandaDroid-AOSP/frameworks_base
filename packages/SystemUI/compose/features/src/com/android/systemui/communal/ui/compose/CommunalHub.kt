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

package com.android.systemui.communal.ui.compose

import android.appwidget.AppWidgetProviderInfo
import android.content.Context
import android.content.res.Configuration
import android.graphics.drawable.Icon
import android.os.SystemClock
import android.util.SizeF
import android.view.MotionEvent
import android.widget.FrameLayout
import android.widget.RemoteViews
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.focusable
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.snapping.SnapPosition
import androidx.compose.foundation.gestures.snapping.rememberSnapFlingBehavior
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyGridScope
import androidx.compose.foundation.lazy.grid.LazyGridState
import androidx.compose.foundation.lazy.grid.LazyHorizontalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Widgets
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonColors
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.windowsizeclass.WindowHeightSizeClass
import androidx.compose.material3.windowsizeclass.WindowWidthSizeClass
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.changedToUp
import androidx.compose.ui.input.pointer.changedToUpIgnoreConsumed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.LayoutCoordinates
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.round
import androidx.compose.ui.unit.sp
import androidx.compose.ui.unit.times
import androidx.compose.ui.util.fastAll
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.viewinterop.NoOpUpdate
import androidx.compose.ui.zIndex
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.window.layout.WindowMetricsCalculator
import com.android.compose.animation.Easings.Emphasized
import com.android.compose.animation.scene.ContentScope
import com.android.compose.modifiers.thenIf
import com.android.compose.ui.graphics.painter.rememberDrawablePainter
import com.android.compose.windowsizeclass.LocalWindowSizeClass
import com.android.internal.R.dimen.system_app_widget_background_radius
import com.android.systemui.Flags
import com.android.systemui.Flags.communalResponsiveGrid
import com.android.systemui.Flags.communalTimerFlickerFix
import com.android.systemui.Flags.communalWidgetResizing
import com.android.systemui.communal.domain.model.CommunalContentModel
import com.android.systemui.communal.shared.model.CommunalContentSize
import com.android.systemui.communal.shared.model.CommunalScenes
import com.android.systemui.communal.ui.compose.extensions.allowGestures
import com.android.systemui.communal.ui.compose.extensions.detectLongPressGesture
import com.android.systemui.communal.ui.compose.extensions.firstItemAtOffset
import com.android.systemui.communal.ui.compose.extensions.observeTaps
import com.android.systemui.communal.ui.view.layout.sections.CommunalAppWidgetSection
import com.android.systemui.communal.ui.viewmodel.BaseCommunalViewModel
import com.android.systemui.communal.ui.viewmodel.CommunalEditModeViewModel
import com.android.systemui.communal.ui.viewmodel.CommunalViewModel
import com.android.systemui.communal.ui.viewmodel.ResizeInfo
import com.android.systemui.communal.ui.viewmodel.ResizeableItemFrameViewModel
import com.android.systemui.communal.util.DensityUtils.Companion.adjustedDp
import com.android.systemui.communal.util.ResizeUtils.resizeOngoingItems
import com.android.systemui.communal.widgets.SmartspaceAppWidgetHostView
import com.android.systemui.communal.widgets.WidgetConfigurator
import com.android.systemui.lifecycle.rememberViewModel
import com.android.systemui.media.controls.ui.composable.MediaCarousel
import com.android.systemui.res.R
import com.android.systemui.scene.shared.flag.SceneContainerFlag
import com.android.systemui.statusbar.phone.SystemUIDialogFactory
import kotlin.math.max
import kotlin.math.min
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CommunalHub(
    modifier: Modifier = Modifier,
    viewModel: BaseCommunalViewModel,
    widgetSection: CommunalAppWidgetSection,
    interactionHandler: RemoteViews.InteractionHandler? = null,
    dialogFactory: SystemUIDialogFactory? = null,
    widgetConfigurator: WidgetConfigurator? = null,
    onOpenWidgetPicker: (() -> Unit)? = null,
    onEditDone: (() -> Unit)? = null,
    contentScope: ContentScope? = null,
) {
    val communalContent by
        viewModel.communalContent.collectAsStateWithLifecycle(initialValue = emptyList())
    var removeButtonCoordinates: LayoutCoordinates? by remember { mutableStateOf(null) }
    var toolbarSize: IntSize? by remember { mutableStateOf(null) }
    var gridCoordinates: LayoutCoordinates? by remember { mutableStateOf(null) }
    var contentOffset: Offset by remember { mutableStateOf(Offset.Zero) }

    val gridState =
        rememberLazyGridState(viewModel.savedFirstScrollIndex, viewModel.savedFirstScrollOffset)

    LaunchedEffect(Unit) {
        if (!viewModel.isEditMode) {
            viewModel.clearPersistedScrollPosition()
        }
    }

    val contentListState = rememberContentListState(widgetConfigurator, communalContent, viewModel)
    val reorderingWidgets by viewModel.reorderingWidgets.collectAsStateWithLifecycle()
    val selectedKey = viewModel.selectedKey.collectAsStateWithLifecycle()
    val removeButtonEnabled by remember {
        derivedStateOf { selectedKey.value != null || reorderingWidgets }
    }
    val isEmptyState by viewModel.isEmptyState.collectAsStateWithLifecycle(initialValue = false)
    val isCommunalContentVisible by
        viewModel.isCommunalContentVisible.collectAsStateWithLifecycle(
            initialValue = !viewModel.isEditMode
        )

    val minContentPadding = gridContentPadding(viewModel.isEditMode, toolbarSize)
    ObserveScrollEffect(gridState, viewModel)

    val context = LocalContext.current
    val windowMetrics = WindowMetricsCalculator.getOrCreate().computeCurrentWindowMetrics(context)
    val screenWidth = windowMetrics.bounds.width()
    val layoutDirection = LocalLayoutDirection.current

    if (viewModel.isEditMode) {
        ObserveNewWidgetAddedEffect(communalContent, gridState, viewModel)
    } else {
        ScrollOnUpdatedLiveContentEffect(communalContent, gridState)
    }

    val nestedScrollConnection = remember {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                // Begin tracking nested scrolling
                viewModel.onNestedScrolling()
                return super.onPreScroll(available, source)
            }
        }
    }

    val paneTitle = stringResource(R.string.accessibility_content_description_for_communal_hub)

    Box(
        modifier =
            modifier
                .semantics {
                    testTagsAsResourceId = true
                    this.paneTitle = paneTitle
                }
                .testTag(COMMUNAL_HUB_TEST_TAG)
                .fillMaxSize()
                // Observe taps for selecting items
                .thenIf(viewModel.isEditMode) {
                    Modifier.pointerInput(
                        layoutDirection,
                        gridState,
                        contentOffset,
                        contentListState,
                    ) {
                        observeTaps { offset ->
                            // if RTL, flip offset direction from Left side to Right
                            val adjustedOffset =
                                Offset(
                                    if (layoutDirection == LayoutDirection.Rtl)
                                        screenWidth - offset.x
                                    else offset.x,
                                    offset.y,
                                ) - contentOffset
                            val index = firstIndexAtOffset(gridState, adjustedOffset)
                            val tappedKey =
                                index?.let { keyAtIndexIfEditable(contentListState.list, index) }

                            viewModel.setSelectedKey(
                                if (
                                    Flags.hubEditModeTouchAdjustments() &&
                                        selectedKey.value == tappedKey
                                ) {
                                    null
                                } else {
                                    tappedKey
                                }
                            )
                        }
                    }
                }
                // Nested scroll for full screen swipe to get to shade and bouncer
                .thenIf(!viewModel.isEditMode && Flags.hubmodeFullscreenVerticalSwipeFix()) {
                    Modifier.nestedScroll(nestedScrollConnection).pointerInput(viewModel) {
                        awaitPointerEventScope {
                            while (true) {
                                val firstDownEvent = awaitFirstDown(requireUnconsumed = false)
                                // Reset touch on first event.
                                viewModel.onResetTouchState()

                                // Process down event in case it's consumed immediately
                                if (firstDownEvent.isConsumed) {
                                    viewModel.onHubTouchConsumed()
                                }

                                do {
                                    val event = awaitPointerEvent()
                                    for (change in event.changes) {
                                        if (change.isConsumed) {
                                            // Signal touch consumption on any consumed event.
                                            viewModel.onHubTouchConsumed()
                                        }
                                    }
                                } while (
                                    !event.changes.fastAll {
                                        it.changedToUp() || it.changedToUpIgnoreConsumed()
                                    }
                                )

                                // Reset state once touch ends.
                                viewModel.onResetTouchState()
                            }
                        }
                    }
                }
                .thenIf(!viewModel.isEditMode && !isEmptyState) {
                    Modifier.pointerInput(
                        gridState,
                        contentOffset,
                        communalContent,
                        gridCoordinates,
                    ) {
                        detectLongPressGesture { offset ->
                            // Deduct both grid offset relative to its container and content
                            // offset.
                            val adjustedOffset =
                                gridCoordinates?.let {
                                    Offset(
                                        if (layoutDirection == LayoutDirection.Rtl)
                                            screenWidth - offset.x
                                        else offset.x,
                                        offset.y,
                                    ) - it.positionInWindow() - contentOffset
                                }
                            val index = adjustedOffset?.let { firstIndexAtOffset(gridState, it) }
                            val key = index?.let { keyAtIndexIfEditable(communalContent, index) }
                            // Handle long-click on widgets and set the selected index
                            // correctly. We only handle widgets here because long click on
                            // empty spaces is handled by CommunalPopupSection.
                            if (key != null) {
                                viewModel.onLongClick()
                                viewModel.setSelectedKey(key)
                            }
                        }
                    }
                }
    ) {
        AccessibilityContainer(viewModel) {
            if (!viewModel.isEditMode && isEmptyState) {
                EmptyStateCta(contentPadding = minContentPadding, viewModel = viewModel)
            } else {
                val slideOffsetInPx =
                    with(LocalDensity.current) { Dimensions.SlideOffsetY.toPx().toInt() }
                AnimatedVisibility(
                    visible = isCommunalContentVisible,
                    enter =
                        fadeIn(
                            animationSpec =
                                tween(durationMillis = 83, delayMillis = 83, easing = LinearEasing)
                        ) +
                            slideInVertically(
                                animationSpec = tween(durationMillis = 1000, easing = Emphasized),
                                initialOffsetY = { -slideOffsetInPx },
                            ),
                    exit =
                        fadeOut(
                            animationSpec = tween(durationMillis = 167, easing = LinearEasing)
                        ) +
                            slideOutVertically(
                                animationSpec = tween(durationMillis = 1000, easing = Emphasized),
                                targetOffsetY = { -slideOffsetInPx },
                            ),
                    modifier = Modifier.fillMaxSize(),
                ) {
                    Box {
                        CommunalHubLazyGrid(
                            communalContent = communalContent,
                            viewModel = viewModel,
                            minContentPadding = minContentPadding,
                            contentOffset = contentOffset,
                            screenWidth = screenWidth,
                            setGridCoordinates = { gridCoordinates = it },
                            setContentOffset = { contentOffset = it },
                            updateDragPositionForRemove = { boundingBox ->
                                val gridOffset = gridCoordinates?.positionInWindow()
                                val removeButtonCenter =
                                    removeButtonCoordinates?.boundsInWindow()?.center
                                removeButtonEnabled &&
                                    gridOffset != null &&
                                    removeButtonCenter != null &&
                                    boundingBox
                                        // The bounding box is relative to the grid, so we need to
                                        // normalize it by adding the grid offset and the content
                                        // offset.
                                        .translate((gridOffset + contentOffset).round())
                                        .contains(removeButtonCenter.round())
                            },
                            gridState = gridState,
                            contentListState = contentListState,
                            selectedKey = selectedKey,
                            widgetConfigurator = widgetConfigurator,
                            interactionHandler = interactionHandler,
                            widgetSection = widgetSection,
                            contentScope = contentScope,
                        )
                    }
                }
            }
        }

        if (onOpenWidgetPicker != null && onEditDone != null) {
            AnimatedVisibility(
                visible = viewModel.isEditMode && isCommunalContentVisible,
                enter =
                    fadeIn(animationSpec = tween(durationMillis = 250, easing = LinearEasing)) +
                        slideInVertically(
                            animationSpec = tween(durationMillis = 1000, easing = Emphasized)
                        ),
                exit =
                    fadeOut(animationSpec = tween(durationMillis = 167, easing = LinearEasing)) +
                        slideOutVertically(
                            animationSpec = tween(durationMillis = 1000, easing = Emphasized)
                        ),
            ) {
                Toolbar(
                    setToolbarSize = { toolbarSize = it },
                    setRemoveButtonCoordinates = { removeButtonCoordinates = it },
                    onEditDone = onEditDone,
                    onOpenWidgetPicker = onOpenWidgetPicker,
                    onRemoveClicked = {
                        val index =
                            selectedKey.value?.let { key ->
                                contentListState.list.indexOfFirst { it.key == key }
                            }
                        index?.let {
                            contentListState.onRemove(it)
                            contentListState.onSaveList()
                            viewModel.setSelectedKey(null)
                        }
                    },
                    removeEnabled = removeButtonEnabled,
                )
            }
        }

        if (viewModel is CommunalViewModel && dialogFactory != null) {
            val isEnableWidgetDialogShowing by
                viewModel.isEnableWidgetDialogShowing.collectAsStateWithLifecycle(false)
            val isEnableWorkProfileDialogShowing by
                viewModel.isEnableWorkProfileDialogShowing.collectAsStateWithLifecycle(false)

            EnableWidgetDialog(
                isEnableWidgetDialogVisible = isEnableWidgetDialogShowing,
                dialogFactory = dialogFactory,
                title = stringResource(id = R.string.dialog_title_to_allow_any_widget),
                positiveButtonText = stringResource(id = R.string.button_text_to_open_settings),
                onConfirm = viewModel::onEnableWidgetDialogConfirm,
                onCancel = viewModel::onEnableWidgetDialogCancel,
            )

            EnableWidgetDialog(
                isEnableWidgetDialogVisible = isEnableWorkProfileDialogShowing,
                dialogFactory = dialogFactory,
                title = stringResource(id = R.string.work_mode_off_title),
                positiveButtonText = stringResource(id = R.string.work_mode_turn_on),
                onConfirm = viewModel::onEnableWorkProfileDialogConfirm,
                onCancel = viewModel::onEnableWorkProfileDialogCancel,
            )
        }

        if (viewModel is CommunalEditModeViewModel) {
            val showBottomSheet by viewModel.showDisclaimer.collectAsStateWithLifecycle(false)

            if (showBottomSheet) {
                val scope = rememberCoroutineScope()
                val sheetState = rememberModalBottomSheetState()
                val colors = MaterialTheme.colorScheme

                ModalBottomSheet(
                    onDismissRequest = viewModel::onDisclaimerDismissed,
                    sheetState = sheetState,
                    dragHandle = null,
                    containerColor = colors.surfaceContainer,
                ) {
                    DisclaimerBottomSheetContent {
                        scope
                            .launch { sheetState.hide() }
                            .invokeOnCompletion {
                                if (!sheetState.isVisible) {
                                    viewModel.onDisclaimerDismissed()
                                }
                            }
                    }
                }
            }
        }
    }
}

val hubDimensions: Dimensions
    @Composable get() = Dimensions(LocalContext.current, LocalConfiguration.current)

@Composable
private fun DisclaimerBottomSheetContent(onButtonClicked: () -> Unit) {
    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Outlined.Widgets,
            contentDescription = null,
            tint = colors.primary,
            modifier = Modifier.size(32.dp),
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.communal_widgets_disclaimer_title),
            style = MaterialTheme.typography.headlineMedium,
            color = colors.onSurface,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.communal_widgets_disclaimer_text),
            color = colors.onSurfaceVariant,
        )
        Button(
            modifier =
                Modifier.padding(horizontal = 26.dp, vertical = 16.dp)
                    .widthIn(min = 200.dp)
                    .heightIn(min = 56.dp),
            onClick = { onButtonClicked() },
        ) {
            Text(
                stringResource(R.string.communal_widgets_disclaimer_button),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

@Composable
private fun ObserveScrollEffect(
    gridState: LazyGridState,
    communalViewModel: BaseCommunalViewModel,
) {

    LaunchedEffect(gridState) {
        snapshotFlow {
                Pair(gridState.firstVisibleItemIndex, gridState.firstVisibleItemScrollOffset)
            }
            .collect { communalViewModel.onScrollPositionUpdated(it.first, it.second) }
    }
}

/**
 * Observes communal content and scrolls to any added or updated live content, e.g. a new media
 * session is started, or a paused timer is resumed.
 */
@Composable
private fun ScrollOnUpdatedLiveContentEffect(
    communalContent: List<CommunalContentModel>,
    gridState: LazyGridState,
) {
    val liveContentKeys = remember { mutableListOf<String>() }
    var communalContentPending by remember { mutableStateOf(true) }

    LaunchedEffect(communalContent) {
        // Do nothing until any communal content comes in
        if (communalContentPending && communalContent.isEmpty()) {
            return@LaunchedEffect
        }

        val prevLiveContentKeys = liveContentKeys.toList()
        val newLiveContentKeys = communalContent.filter { it.isLiveContent() }.map { it.key }
        liveContentKeys.clear()
        liveContentKeys.addAll(newLiveContentKeys)

        // Do nothing on first communal content since we don't have a delta
        if (communalContentPending) {
            communalContentPending = false
            return@LaunchedEffect
        }

        // Do nothing if there is no new live content
        val indexOfFirstUpdatedContent =
            newLiveContentKeys.indexOfFirst { !prevLiveContentKeys.contains(it) }
        if (indexOfFirstUpdatedContent in 0 until gridState.firstVisibleItemIndex) {
            gridState.scrollToItem(indexOfFirstUpdatedContent)
        }
    }
}

/**
 * Observes communal content and determines whether a new widget has been added, upon which case:
 * - Announce for accessibility
 * - Scroll if the new widget is not visible
 */
@Composable
private fun ObserveNewWidgetAddedEffect(
    communalContent: List<CommunalContentModel>,
    gridState: LazyGridState,
    viewModel: BaseCommunalViewModel,
) {
    val coroutineScope = rememberCoroutineScope()
    val widgetKeys = remember { mutableListOf<String>() }
    var communalContentPending by remember { mutableStateOf(true) }

    LaunchedEffect(communalContent) {
        // Do nothing until any communal content comes in
        if (communalContentPending && communalContent.isEmpty()) {
            return@LaunchedEffect
        }

        val oldWidgetKeys = widgetKeys.toList()
        val widgets = communalContent.filterIsInstance<CommunalContentModel.WidgetContent.Widget>()
        widgetKeys.clear()
        widgetKeys.addAll(widgets.map { it.key })

        // Do nothing on first communal content since we don't have a delta
        if (communalContentPending) {
            communalContentPending = false
            return@LaunchedEffect
        }

        // Do nothing if there is no new widget
        val indexOfFirstNewWidget = widgetKeys.indexOfFirst { !oldWidgetKeys.contains(it) }
        if (indexOfFirstNewWidget < 0) {
            return@LaunchedEffect
        }

        viewModel.onNewWidgetAdded(widgets[indexOfFirstNewWidget].providerInfo)

        // Scroll if the new widget is not visible
        val lastVisibleItemIndex = gridState.layoutInfo.visibleItemsInfo.lastOrNull()?.index
        if (lastVisibleItemIndex != null && indexOfFirstNewWidget > lastVisibleItemIndex) {
            // Launching with a scope to prevent the job from being canceled in the case of a
            // recomposition during scrolling
            coroutineScope.launch { gridState.animateScrollToItem(indexOfFirstNewWidget) }
        }
    }
}

@Composable
private fun ResizableItemFrameWrapper(
    key: String,
    currentSpan: GridItemSpan,
    gridState: LazyGridState,
    gridContentPadding: PaddingValues,
    verticalArrangement: Arrangement.Vertical,
    enabled: Boolean,
    minHeightPx: Int,
    maxHeightPx: Int,
    modifier: Modifier = Modifier,
    alpha: () -> Float = { 1f },
    viewModel: ResizeableItemFrameViewModel,
    onResize: (info: ResizeInfo) -> Unit = {},
    content: @Composable (modifier: Modifier) -> Unit,
) {
    if (!communalWidgetResizing()) {
        content(modifier)
    } else {
        ResizableItemFrame(
            key = key,
            currentSpan = currentSpan,
            gridState = gridState,
            gridContentPadding = gridContentPadding,
            verticalArrangement = verticalArrangement,
            enabled = enabled,
            alpha = alpha,
            modifier = modifier,
            viewModel = viewModel,
            onResize = onResize,
            minHeightPx = minHeightPx,
            maxHeightPx = maxHeightPx,
            resizeMultiple =
                if (communalResponsiveGrid()) {
                    1
                } else {
                    CommunalContentSize.FixedSize.HALF.span
                },
        ) {
            content(Modifier)
        }
    }
}

@Composable
fun calculateWidgetSize(
    cellHeight: Dp?,
    availableHeight: Dp?,
    item: CommunalContentModel,
    isResizable: Boolean,
): WidgetSizeInfo {
    val density = LocalDensity.current

    val minHeight = cellHeight ?: CommunalContentSize.FixedSize.HALF.dp()
    val maxHeight = availableHeight ?: CommunalContentSize.FixedSize.FULL.dp()

    return if (isResizable && item is CommunalContentModel.WidgetContent.Widget) {
        with(density) {
            val minHeightPx =
                (min(item.providerInfo.minResizeHeight, item.providerInfo.minHeight)
                    .coerceAtLeast(minHeight.roundToPx()))

            val maxHeightPx =
                (if (item.providerInfo.maxResizeHeight > 0) {
                        max(item.providerInfo.maxResizeHeight, item.providerInfo.minHeight)
                    } else {
                        Int.MAX_VALUE
                    })
                    .coerceIn(minHeightPx, maxHeight.roundToPx())

            WidgetSizeInfo(minHeightPx, maxHeightPx)
        }
    } else {
        WidgetSizeInfo(0, 0)
    }
}

@Composable
private fun horizontalPaddingWithInsets(padding: Dp): Dp {
    val orientation = LocalConfiguration.current.orientation
    val displayCutoutPaddings = WindowInsets.displayCutout.asPaddingValues()
    val horizontalDisplayCutoutPadding =
        remember(orientation, displayCutoutPaddings) {
            if (orientation == Configuration.ORIENTATION_LANDSCAPE) {
                maxOf(
                    // Top in portrait becomes startPadding (or endPadding) in landscape
                    displayCutoutPaddings.calculateTopPadding(),
                    // Bottom in portrait becomes endPadding (or startPadding) in landscape
                    displayCutoutPaddings.calculateBottomPadding(),
                )
            } else {
                0.dp
            }
        }
    return padding + horizontalDisplayCutoutPadding
}

@Composable
private fun HorizontalGridWrapper(
    minContentPadding: PaddingValues,
    gridState: LazyGridState,
    dragDropState: GridDragDropState?,
    setContentOffset: (offset: Offset) -> Unit,
    minHorizontalArrangement: Dp,
    minVerticalArrangement: Dp,
    modifier: Modifier = Modifier,
    content: LazyGridScope.(sizeInfo: SizeInfo?) -> Unit,
) {
    val isDragging = dragDropState?.draggingItemKey != null
    if (communalResponsiveGrid()) {
        val flingBehavior =
            rememberSnapFlingBehavior(lazyGridState = gridState, snapPosition = SnapPosition.Start)
        ResponsiveLazyHorizontalGrid(
            cellAspectRatio = 1.5f,
            modifier = modifier,
            state = gridState,
            flingBehavior = flingBehavior,
            minContentPadding = minContentPadding,
            minHorizontalArrangement = minHorizontalArrangement,
            minVerticalArrangement = minVerticalArrangement,
            setContentOffset = setContentOffset,
            // Temporarily disable user gesture scrolling while dragging a widget to prevent
            // conflicts between the drag and scroll gestures. Programmatic scrolling remains
            // enabled to allow dragging a widget beyond the visible boundaries.
            userScrollEnabled = !isDragging,
            content = content,
        )
    } else {
        val layoutDirection = LocalLayoutDirection.current
        val density = LocalDensity.current

        val minStartPadding = minContentPadding.calculateStartPadding(layoutDirection)
        val minTopPadding = minContentPadding.calculateTopPadding()

        with(density) { setContentOffset(Offset(minStartPadding.toPx(), minTopPadding.toPx())) }

        LazyHorizontalGrid(
            modifier = modifier,
            state = gridState,
            rows = GridCells.Fixed(CommunalContentSize.FixedSize.FULL.span),
            contentPadding = minContentPadding,
            horizontalArrangement = Arrangement.spacedBy(Dimensions.ItemSpacing),
            verticalArrangement = Arrangement.spacedBy(Dimensions.ItemSpacing),
            // Temporarily disable user gesture scrolling while dragging a widget to prevent
            // conflicts between the drag and scroll gestures. Programmatic scrolling remains
            // enabled to allow dragging a widget beyond the visible boundaries.
            userScrollEnabled = !isDragging,
        ) {
            content(null)
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun BoxScope.CommunalHubLazyGrid(
    communalContent: List<CommunalContentModel>,
    viewModel: BaseCommunalViewModel,
    minContentPadding: PaddingValues,
    selectedKey: State<String?>,
    screenWidth: Int,
    contentOffset: Offset,
    gridState: LazyGridState,
    contentListState: ContentListState,
    setGridCoordinates: (coordinates: LayoutCoordinates) -> Unit,
    setContentOffset: (offset: Offset) -> Unit,
    updateDragPositionForRemove: (boundingBox: IntRect) -> Boolean,
    widgetConfigurator: WidgetConfigurator?,
    interactionHandler: RemoteViews.InteractionHandler?,
    widgetSection: CommunalAppWidgetSection,
    contentScope: ContentScope?,
) {
    var gridModifier =
        Modifier.align(Alignment.TopStart).onGloballyPositioned { setGridCoordinates(it) }
    var list = communalContent
    var dragDropState: GridDragDropState? = null
    var arrangementSpacing = Dimensions.ItemSpacing
    if (viewModel.isEditMode && viewModel is CommunalEditModeViewModel) {
        list = contentListState.list
        // for drag & drop operations within the communal hub grid
        dragDropState =
            rememberGridDragDropState(
                gridState = gridState,
                contentListState = contentListState,
                updateDragPositionForRemove = updateDragPositionForRemove,
            )
        gridModifier =
            gridModifier
                .fillMaxSize()
                .dragContainer(
                    dragDropState,
                    LocalLayoutDirection.current,
                    screenWidth,
                    contentOffset,
                    viewModel,
                )
        // for widgets dropped from other activities
        val dragAndDropTargetState =
            rememberDragAndDropTargetState(
                gridState = gridState,
                contentListState = contentListState,
                contentOffset = contentOffset,
            )

        // A full size box in background that listens to widget drops from the picker.
        // Since the grid has its own listener for in-grid drag events, we use a separate element
        // for android drag events.
        Box(Modifier.fillMaxSize().dragAndDropTarget(dragAndDropTargetState)) {}
    } else if (communalResponsiveGrid()) {
        gridModifier = gridModifier.fillMaxSize()
        if (isCompactWindow()) {
            arrangementSpacing = Dimensions.ItemSpacingCompact
        }
    } else {
        gridModifier = gridModifier.height(hubDimensions.GridHeight)
    }

    HorizontalGridWrapper(
        modifier = gridModifier,
        gridState = gridState,
        dragDropState = dragDropState,
        minContentPadding = minContentPadding,
        minHorizontalArrangement = arrangementSpacing,
        minVerticalArrangement = arrangementSpacing,
        setContentOffset = setContentOffset,
    ) { sizeInfo ->
        /** Override spans based on the responsive grid size */
        val finalizedList =
            if (sizeInfo != null) {
                resizeOngoingItems(list, sizeInfo.gridSize.height)
            } else {
                list
            }

        itemsIndexed(
            items = finalizedList,
            key = { _, item -> item.key },
            contentType = { _, item -> item.key },
            span = { _, item -> GridItemSpan(item.getSpanOrMax(sizeInfo?.gridSize?.height)) },
        ) { index, item ->
            val currentItemSpan = item.getSpanOrMax(sizeInfo?.gridSize?.height)
            val dpSize =
                if (sizeInfo != null) {
                    DpSize(sizeInfo.cellSize.width, sizeInfo.calculateHeight(currentItemSpan))
                } else {
                    DpSize(Dimensions.CardWidth, (item.size as CommunalContentSize.FixedSize).dp())
                }
            val size = SizeF(dpSize.width.value, dpSize.height.value)
            val selected = item.key == selectedKey.value
            val isResizable =
                if (item is CommunalContentModel.WidgetContent.Widget) {
                    item.providerInfo.resizeMode and AppWidgetProviderInfo.RESIZE_VERTICAL != 0
                } else {
                    false
                }

            val resizeableItemFrameViewModel =
                rememberViewModel(
                    key = currentItemSpan,
                    traceName = "ResizeableItemFrame.viewModel.$index",
                ) {
                    ResizeableItemFrameViewModel()
                }
            if (viewModel.isEditMode && dragDropState != null) {
                val isItemDragging = dragDropState.draggingItemKey == item.key
                val outlineAlpha by
                    animateFloatAsState(
                        targetValue = if (selected) 1f else 0f,
                        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
                        label = "Widget resizing outline alpha",
                    )

                val widgetSizeInfo =
                    calculateWidgetSize(
                        cellHeight = sizeInfo?.cellSize?.height,
                        availableHeight = sizeInfo?.availableHeight,
                        item = item,
                        isResizable = isResizable,
                    )
                ResizableItemFrameWrapper(
                    key = item.key,
                    currentSpan = GridItemSpan(currentItemSpan),
                    gridState = gridState,
                    gridContentPadding = sizeInfo?.contentPadding ?: minContentPadding,
                    verticalArrangement =
                        Arrangement.spacedBy(
                            sizeInfo?.verticalArrangement ?: Dimensions.ItemSpacing
                        ),
                    enabled = selected && !isItemDragging,
                    alpha = { outlineAlpha },
                    modifier =
                        Modifier.requiredSize(dpSize)
                            .thenIf(!isItemDragging) {
                                Modifier.animateItem(
                                    placementSpec = spring(stiffness = Spring.StiffnessMediumLow),
                                    // See b/376495198 - not supported with AndroidView
                                    fadeOutSpec = null,
                                )
                            }
                            .thenIf(isItemDragging) { Modifier.zIndex(1f) },
                    viewModel = resizeableItemFrameViewModel,
                    onResize = { resizeInfo -> contentListState.resize(index, resizeInfo) },
                    minHeightPx = widgetSizeInfo.minHeightPx,
                    maxHeightPx = widgetSizeInfo.maxHeightPx,
                ) { modifier ->
                    DraggableItem(
                        modifier = modifier,
                        dragDropState = dragDropState,
                        selected = selected,
                        enabled = item.isWidgetContent(),
                        key = item.key,
                    ) { isDragging ->
                        CommunalContent(
                            modifier = Modifier.requiredSize(dpSize),
                            model = item,
                            viewModel = viewModel,
                            size = size,
                            selected = selected && !isDragging,
                            widgetConfigurator = widgetConfigurator,
                            index = index,
                            contentListState = contentListState,
                            interactionHandler = interactionHandler,
                            widgetSection = widgetSection,
                            resizeableItemFrameViewModel = resizeableItemFrameViewModel,
                        )
                    }
                }
            } else {
                val itemAlpha =
                    if (communalResponsiveGrid()) {
                        val percentVisible by
                            remember(gridState, index) {
                                derivedStateOf { calculatePercentVisible(gridState, index) }
                            }
                        animateFloatAsState(percentVisible)
                    } else {
                        null
                    }

                CommunalContent(
                    model = item,
                    viewModel = viewModel,
                    size = size,
                    selected = false,
                    modifier =
                        Modifier.requiredSize(dpSize)
                            .animateItem(
                                // See b/376495198 - not supported with AndroidView
                                fadeOutSpec = null
                            )
                            .thenIf(communalResponsiveGrid()) {
                                Modifier.graphicsLayer { alpha = itemAlpha?.value ?: 1f }
                            },
                    index = index,
                    contentListState = contentListState,
                    interactionHandler = interactionHandler,
                    widgetSection = widgetSection,
                    resizeableItemFrameViewModel = resizeableItemFrameViewModel,
                    contentScope = contentScope,
                )
            }
        }
    }
}

/**
 * The empty state displays a fullscreen call-to-action (CTA) tile when no widgets are available.
 */
@Composable
private fun EmptyStateCta(contentPadding: PaddingValues, viewModel: BaseCommunalViewModel) {
    val colors = MaterialTheme.colorScheme
    Card(
        modifier = Modifier.height(hubDimensions.GridHeight).padding(contentPadding),
        colors =
            CardDefaults.cardColors(
                containerColor = colors.primary,
                contentColor = colors.onPrimary,
            ),
        shape = RoundedCornerShape(size = 80.adjustedDp),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 110.adjustedDp),
            verticalArrangement =
                Arrangement.spacedBy(Dimensions.Spacing, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            val titleForEmptyStateCTA = stringResource(R.string.title_for_empty_state_cta)
            BasicText(
                text = titleForEmptyStateCTA,
                style =
                    MaterialTheme.typography.displaySmall.merge(
                        color = colors.onPrimary,
                        textAlign = TextAlign.Center,
                    ),
                autoSize = TextAutoSize.StepBased(maxFontSize = 36.sp, stepSize = 0.1.sp),
                modifier =
                    Modifier.focusable().semantics(mergeDescendants = true) {
                        contentDescription = titleForEmptyStateCTA
                        heading()
                    },
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                Button(
                    modifier = Modifier.height(56.dp),
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = colors.primaryContainer,
                            contentColor = colors.onPrimaryContainer,
                        ),
                    onClick = { viewModel.onOpenWidgetEditor(shouldOpenWidgetPickerOnStart = true) },
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(24.dp),
                    )
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text(
                        text = stringResource(R.string.label_for_button_in_empty_state_cta),
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
            }
        }
    }
}

/**
 * Toolbar that contains action buttons to
 * 1) open the widget picker
 * 2) remove a widget from the grid and
 * 3) exit the edit mode.
 */
@Composable
private fun Toolbar(
    removeEnabled: Boolean,
    onRemoveClicked: () -> Unit,
    setToolbarSize: (toolbarSize: IntSize) -> Unit,
    setRemoveButtonCoordinates: (coordinates: LayoutCoordinates?) -> Unit,
    onOpenWidgetPicker: () -> Unit,
    onEditDone: () -> Unit,
) {
    if (!removeEnabled) {
        // Clear any existing coordinates when remove is not enabled.
        setRemoveButtonCoordinates(null)
    }
    val removeButtonAlpha: Float by
        animateFloatAsState(
            targetValue = if (removeEnabled) 1f else 0.5f,
            label = "RemoveButtonAlphaAnimation",
        )

    Box(
        modifier =
            Modifier.fillMaxWidth()
                .padding(
                    top = Dimensions.ToolbarPaddingTop,
                    start = Dimensions.ToolbarPaddingHorizontal,
                    end = Dimensions.ToolbarPaddingHorizontal,
                )
                .onSizeChanged { setToolbarSize(it) }
    ) {
        val addWidgetText = stringResource(R.string.hub_mode_add_widget_button_text)

        if (!(Flags.hubEditModeTouchAdjustments() && removeEnabled)) {
            ToolbarButton(
                isPrimary = !removeEnabled,
                modifier = Modifier.align(Alignment.CenterStart),
                onClick = onOpenWidgetPicker,
            ) {
                Icon(Icons.Default.Add, null)
                Text(text = addWidgetText)
            }
        }

        AnimatedVisibility(
            modifier =
                Modifier.align(
                    if (Flags.hubEditModeTouchAdjustments()) {
                        Alignment.CenterStart
                    } else {
                        Alignment.Center
                    }
                ),
            visible = removeEnabled,
            enter = fadeIn(),
            exit = fadeOut(),
        ) {
            Button(
                onClick = onRemoveClicked,
                colors = filledButtonColors(),
                contentPadding = Dimensions.ButtonPadding,
                modifier =
                    Modifier.graphicsLayer { alpha = removeButtonAlpha }
                        .onGloballyPositioned {
                            // It's possible for this callback to fire after remove has been
                            // disabled. Check enabled state before setting.
                            if (removeEnabled) {
                                setRemoveButtonCoordinates(it)
                            }
                        },
            ) {
                Row(
                    horizontalArrangement =
                        Arrangement.spacedBy(
                            ButtonDefaults.IconSpacing,
                            if (Flags.hubEditModeTouchAdjustments()) {
                                Alignment.Start
                            } else {
                                Alignment.CenterHorizontally
                            },
                        ),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(Icons.Default.Close, contentDescription = null)
                    Text(text = stringResource(R.string.button_to_remove_widget))
                }
            }
        }

        ToolbarButton(
            isPrimary = !removeEnabled,
            modifier = Modifier.align(Alignment.CenterEnd),
            onClick = onEditDone,
        ) {
            Icon(Icons.Default.Check, contentDescription = null)
            Text(text = stringResource(R.string.hub_mode_editing_exit_button_text))
        }
    }
}

/**
 * Toolbar button that displays as a filled button if primary, and an outline button if secondary.
 */
@Composable
private fun ToolbarButton(
    isPrimary: Boolean = true,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    AnimatedVisibility(
        visible = isPrimary,
        modifier = modifier,
        enter = fadeIn(),
        exit = fadeOut(),
    ) {
        Button(
            onClick = onClick,
            colors = filledButtonColors(),
            contentPadding = Dimensions.ButtonPadding,
        ) {
            Row(
                horizontalArrangement =
                    Arrangement.spacedBy(ButtonDefaults.IconSpacing, Alignment.CenterHorizontally),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                content()
            }
        }
    }

    AnimatedVisibility(
        visible = !isPrimary,
        modifier = modifier,
        enter = fadeIn(),
        exit = fadeOut(),
    ) {
        OutlinedButton(
            onClick = onClick,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = colors.onPrimaryContainer),
            border = BorderStroke(width = 2.0.dp, color = colors.primary),
            contentPadding = Dimensions.ButtonPadding,
        ) {
            Row(
                horizontalArrangement =
                    Arrangement.spacedBy(ButtonDefaults.IconSpacing, Alignment.CenterHorizontally),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                content()
            }
        }
    }
}

@Composable
private fun filledButtonColors(): ButtonColors {
    val colors = MaterialTheme.colorScheme
    return ButtonDefaults.buttonColors(
        containerColor = colors.primary,
        contentColor = colors.onPrimary,
    )
}

@Composable
private fun CommunalContent(
    model: CommunalContentModel,
    viewModel: BaseCommunalViewModel,
    size: SizeF,
    selected: Boolean,
    modifier: Modifier = Modifier,
    widgetConfigurator: WidgetConfigurator? = null,
    index: Int,
    contentListState: ContentListState,
    interactionHandler: RemoteViews.InteractionHandler?,
    widgetSection: CommunalAppWidgetSection,
    resizeableItemFrameViewModel: ResizeableItemFrameViewModel,
    contentScope: ContentScope? = null,
) {
    when (model) {
        is CommunalContentModel.WidgetContent.Widget ->
            WidgetContent(
                viewModel,
                model,
                size,
                selected,
                widgetConfigurator,
                modifier,
                index,
                contentListState,
                widgetSection,
                resizeableItemFrameViewModel,
            )
        is CommunalContentModel.WidgetPlaceholder -> HighlightedItem(modifier)
        is CommunalContentModel.WidgetContent.DisabledWidget ->
            DisabledWidgetPlaceholder(model, viewModel, modifier)
        is CommunalContentModel.WidgetContent.PendingWidget ->
            PendingWidgetPlaceholder(model, modifier)
        is CommunalContentModel.CtaTileInViewMode -> CtaTileInViewModeContent(viewModel, modifier)
        is CommunalContentModel.Smartspace -> SmartspaceContent(interactionHandler, model, modifier)
        is CommunalContentModel.Tutorial -> TutorialContent(modifier)
        is CommunalContentModel.Umo -> Umo(viewModel, contentScope, modifier)
        is CommunalContentModel.Spacer -> Box(Modifier.fillMaxSize())
    }
}

/** Creates an empty card used to highlight a particular spot on the grid. */
@Composable
fun HighlightedItem(modifier: Modifier = Modifier, alpha: Float = 1.0f) {
    val brush = SolidColor(MaterialTheme.colorScheme.primary)
    Box(
        modifier =
            // drawBehind lets us draw outside the bounds of the widgets so that we don't need to
            // resize grid items to account for the border.
            modifier.drawBehind {
                // 8dp of padding between the widget and the highlight on every side.
                val padding = 8.adjustedDp.toPx()
                drawRoundRect(
                    brush,
                    alpha = alpha,
                    topLeft = Offset(-padding, -padding),
                    size =
                        Size(width = size.width + padding * 2, height = size.height + padding * 2),
                    cornerRadius = CornerRadius(37.adjustedDp.toPx()),
                    style = Stroke(width = 3.adjustedDp.toPx()),
                )
            }
    )
}

/** Presents a CTA tile at the end of the grid, to customize the hub. */
@Composable
private fun CtaTileInViewModeContent(
    viewModel: BaseCommunalViewModel,
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme
    Card(
        modifier = modifier,
        colors =
            CardDefaults.cardColors(
                containerColor = colors.primary,
                contentColor = colors.onPrimary,
            ),
        shape = RoundedCornerShape(68.adjustedDp, 34.adjustedDp, 68.adjustedDp, 34.adjustedDp),
    ) {
        Column(
            modifier =
                Modifier.fillMaxSize()
                    .padding(vertical = 32.adjustedDp, horizontal = 50.adjustedDp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = Icons.Outlined.Widgets,
                contentDescription = stringResource(R.string.cta_label_to_open_widget_picker),
                modifier = Modifier.size(Dimensions.IconSize).clearAndSetSemantics {},
            )
            Spacer(modifier = Modifier.size(6.adjustedDp))
            Text(
                text = stringResource(R.string.cta_label_to_edit_widget),
                style = MaterialTheme.typography.titleLarge,
                fontSize = nonScalableTextSize(22.dp),
                lineHeight = nonScalableTextSize(28.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()).weight(1F),
            )
            Spacer(modifier = Modifier.size(16.adjustedDp))
            Row(
                modifier = Modifier.fillMaxWidth().height(56.adjustedDp),
                horizontalArrangement =
                    Arrangement.spacedBy(16.adjustedDp, Alignment.CenterHorizontally),
            ) {
                CompositionLocalProvider(
                    LocalDensity provides
                        Density(
                            LocalDensity.current.density,
                            LocalDensity.current.fontScale.coerceIn(0f, 1.25f),
                        )
                ) {
                    OutlinedButton(
                        modifier = Modifier.fillMaxHeight().weight(1F),
                        colors = ButtonDefaults.buttonColors(contentColor = colors.onPrimary),
                        border = BorderStroke(width = 1.0.dp, color = colors.primaryContainer),
                        onClick = viewModel::onDismissCtaTile,
                        contentPadding = PaddingValues(0.dp, 0.dp, 0.dp, 0.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.cta_tile_button_to_dismiss),
                            fontSize = 14.sp,
                        )
                    }
                    Button(
                        modifier = Modifier.fillMaxHeight().weight(1F),
                        colors =
                            ButtonDefaults.buttonColors(
                                containerColor = colors.primaryContainer,
                                contentColor = colors.onPrimaryContainer,
                            ),
                        onClick = viewModel::onOpenWidgetEditor,
                        contentPadding = PaddingValues(0.dp, 0.dp, 0.dp, 0.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.cta_tile_button_to_open_widget_editor),
                            fontSize = 14.sp,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun WidgetContent(
    viewModel: BaseCommunalViewModel,
    model: CommunalContentModel.WidgetContent.Widget,
    size: SizeF,
    selected: Boolean,
    widgetConfigurator: WidgetConfigurator?,
    modifier: Modifier = Modifier,
    index: Int,
    contentListState: ContentListState,
    widgetSection: CommunalAppWidgetSection,
    resizeableItemFrameViewModel: ResizeableItemFrameViewModel,
) {
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val accessibilityLabel =
        remember(model, context) {
            model.providerInfo.loadLabel(context.packageManager).toString().trim()
        }
    val clickActionLabel = stringResource(R.string.accessibility_action_label_select_widget)
    val removeWidgetActionLabel = stringResource(R.string.accessibility_action_label_remove_widget)
    val placeWidgetActionLabel = stringResource(R.string.accessibility_action_label_place_widget)
    val unselectWidgetActionLabel =
        stringResource(R.string.accessibility_action_label_unselect_widget)

    val shrinkWidgetLabel = stringResource(R.string.accessibility_action_label_shrink_widget)
    val expandWidgetLabel = stringResource(R.string.accessibility_action_label_expand_widget)

    val isFocusable by viewModel.isFocusable.collectAsStateWithLifecycle(initialValue = false)
    val selectedKey by viewModel.selectedKey.collectAsStateWithLifecycle()
    val selectedIndex =
        selectedKey?.let { key -> contentListState.list.indexOfFirst { it.key == key } }

    val interactionSource = remember { MutableInteractionSource() }
    val focusRequester = remember { FocusRequester() }
    if (viewModel.isEditMode && selected) {
        LaunchedEffect(Unit) {
            delay(TransitionDuration.BETWEEN_HUB_AND_EDIT_MODE_MS.toLong())
            focusRequester.requestFocus()
        }
    }

    val isSelected = selectedKey == model.key

    val selectableModifier =
        if (viewModel.isEditMode) {
            Modifier.selectable(
                selected = isSelected,
                onClick = { viewModel.setSelectedKey(model.key) },
                interactionSource = interactionSource,
                indication = null,
            )
        } else {
            Modifier
        }
    Box(
        modifier =
            modifier
                .focusRequester(focusRequester)
                .focusable(interactionSource = interactionSource)
                .then(selectableModifier)
                .thenIf(!viewModel.isEditMode && !model.inQuietMode) {
                    Modifier.pointerInput(Unit) {
                        observeTaps { viewModel.onTapWidget(model.componentName, model.rank) }
                    }
                }
                .thenIf(!viewModel.isEditMode && model.inQuietMode) {
                    Modifier.pointerInput(Unit) {
                        // consume tap to prevent the child view from triggering interactions with
                        // the app widget
                        observeTaps(shouldConsume = true) { _ ->
                            viewModel.onOpenEnableWorkProfileDialog()
                        }
                    }
                }
                .thenIf(viewModel.isEditMode) {
                    Modifier.semantics {
                        onClick(clickActionLabel, null)
                        contentDescription = accessibilityLabel
                        val deleteAction =
                            CustomAccessibilityAction(removeWidgetActionLabel) {
                                contentListState.onRemove(index)
                                contentListState.onSaveList()
                                true
                            }
                        val actions = mutableListOf(deleteAction)

                        if (communalWidgetResizing() && resizeableItemFrameViewModel.canShrink()) {
                            actions.add(
                                CustomAccessibilityAction(shrinkWidgetLabel) {
                                    coroutineScope.launch {
                                        resizeableItemFrameViewModel.shrinkToNextAnchor()
                                    }
                                    true
                                }
                            )
                        }

                        if (communalWidgetResizing() && resizeableItemFrameViewModel.canExpand()) {
                            actions.add(
                                CustomAccessibilityAction(expandWidgetLabel) {
                                    coroutineScope.launch {
                                        resizeableItemFrameViewModel.expandToNextAnchor()
                                    }
                                    true
                                }
                            )
                        }

                        if (selectedIndex != null && selectedIndex != index) {
                            actions.add(
                                CustomAccessibilityAction(placeWidgetActionLabel) {
                                    contentListState.onMove(selectedIndex!!, index)
                                    contentListState.onSaveList()
                                    viewModel.setSelectedKey(null)
                                    true
                                }
                            )
                        }

                        if (!selected) {
                            actions.add(
                                CustomAccessibilityAction(clickActionLabel) {
                                    viewModel.setSelectedKey(model.key)
                                    true
                                }
                            )
                        } else {
                            actions.add(
                                CustomAccessibilityAction(unselectWidgetActionLabel) {
                                    viewModel.setSelectedKey(null)
                                    true
                                }
                            )
                        }
                        customActions = actions
                    }
                }
    ) {
        with(widgetSection) {
            Widget(
                isFocusable = isFocusable,
                openWidgetEditor = {
                    viewModel.setSelectedKey(model.key)
                    viewModel.onOpenWidgetEditor()
                },
                model = model,
                size = size,
                modifier = Modifier.fillMaxSize().allowGestures(allowed = !viewModel.isEditMode),
            )
        }
        if (
            viewModel is CommunalEditModeViewModel &&
                model.reconfigurable &&
                widgetConfigurator != null
        ) {
            WidgetConfigureButton(
                visible = selected,
                model = model,
                widgetConfigurator = widgetConfigurator,
                modifier = Modifier.align(Alignment.BottomEnd),
            )
        }
    }
}

@Composable
fun WidgetConfigureButton(
    visible: Boolean,
    model: CommunalContentModel.WidgetContent.Widget,
    modifier: Modifier = Modifier,
    widgetConfigurator: WidgetConfigurator,
) {
    val colors = MaterialTheme.colorScheme
    val scope = rememberCoroutineScope()

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(),
        exit = fadeOut(),
        modifier = modifier.padding(16.adjustedDp),
    ) {
        FilledIconButton(
            shape = RoundedCornerShape(16.adjustedDp),
            modifier = Modifier.size(48.adjustedDp),
            colors =
                IconButtonColors(
                    containerColor = colors.primary,
                    contentColor = colors.onPrimary,
                    disabledContainerColor = Color.Transparent,
                    disabledContentColor = Color.Transparent,
                ),
            onClick = { scope.launch { widgetConfigurator.configureWidget(model.appWidgetId) } },
        ) {
            Icon(
                imageVector = Icons.Outlined.Edit,
                contentDescription = stringResource(id = R.string.edit_widget),
                modifier = Modifier.padding(12.adjustedDp),
            )
        }
    }
}

@Composable
fun DisabledWidgetPlaceholder(
    model: CommunalContentModel.WidgetContent.DisabledWidget,
    viewModel: BaseCommunalViewModel,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val appInfo = model.appInfo
    val icon: Icon =
        if (appInfo == null || appInfo.icon == 0) {
            Icon.createWithResource(context, android.R.drawable.sym_def_app_icon)
        } else {
            Icon.createWithResource(appInfo.packageName, appInfo.icon)
        }

    Column(
        modifier =
            modifier
                .background(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape =
                        RoundedCornerShape(dimensionResource(system_app_widget_background_radius)),
                )
                .clickable(
                    enabled = !viewModel.isEditMode,
                    interactionSource = null,
                    indication = null,
                    onClick = viewModel::onOpenEnableWidgetDialog,
                ),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Image(
            painter = rememberDrawablePainter(icon.loadDrawable(context)),
            contentDescription = stringResource(R.string.icon_description_for_disabled_widget),
            modifier = Modifier.size(Dimensions.IconSize),
            colorFilter = ColorFilter.colorMatrix(Colors.DisabledColorFilter),
        )
    }
}

@Composable
fun PendingWidgetPlaceholder(
    model: CommunalContentModel.WidgetContent.PendingWidget,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val icon: Icon =
        if (model.icon != null) {
            Icon.createWithBitmap(model.icon)
        } else {
            Icon.createWithResource(context, android.R.drawable.sym_def_app_icon)
        }

    Column(
        modifier =
            modifier.background(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(dimensionResource(system_app_widget_background_radius)),
            ),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Image(
            painter = rememberDrawablePainter(icon.loadDrawable(context)),
            contentDescription = stringResource(R.string.icon_description_for_pending_widget),
            modifier = Modifier.size(Dimensions.IconSize),
        )
    }
}

@Composable
private fun SmartspaceContent(
    interactionHandler: RemoteViews.InteractionHandler?,
    model: CommunalContentModel.Smartspace,
    modifier: Modifier = Modifier,
) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            SmartspaceAppWidgetHostView(context).apply {
                interactionHandler?.let { setInteractionHandler(it) }
                if (!communalTimerFlickerFix()) {
                    updateAppWidget(model.remoteViews)
                }
            }
        },
        update =
            if (communalTimerFlickerFix()) {
                { view: SmartspaceAppWidgetHostView -> view.updateAppWidget(model.remoteViews) }
            } else NoOpUpdate,
        // For reusing composition in lazy lists.
        onReset = {},
    )
}

@Composable
private fun TutorialContent(modifier: Modifier = Modifier) {
    Card(modifier = modifier, content = {})
}

@Composable
private fun Umo(
    viewModel: BaseCommunalViewModel,
    contentScope: ContentScope?,
    modifier: Modifier = Modifier,
) {
    val showNextActionLabel = stringResource(R.string.accessibility_action_label_umo_show_next)
    val showPreviousActionLabel =
        stringResource(R.string.accessibility_action_label_umo_show_previous)

    Box(
        modifier =
            modifier.thenIf(!viewModel.isEditMode) {
                Modifier.semantics {
                    customActions =
                        listOf(
                            CustomAccessibilityAction(showNextActionLabel) {
                                viewModel.onShowNextMedia()
                                true
                            },
                            CustomAccessibilityAction(showPreviousActionLabel) {
                                viewModel.onShowPreviousMedia()
                                true
                            },
                        )
                }
            }
    ) {
        if (SceneContainerFlag.isEnabled && contentScope != null) {
            contentScope.MediaCarousel(
                modifier = modifier.fillMaxSize(),
                isVisible = true,
                mediaHost = viewModel.mediaHost,
                carouselController = viewModel.mediaCarouselController,
            )
        } else {
            UmoLegacy(viewModel, modifier)
        }
    }
}

@Composable
private fun UmoLegacy(viewModel: BaseCommunalViewModel, modifier: Modifier = Modifier) {
    AndroidView(
        modifier =
            modifier
                .clip(
                    shape =
                        RoundedCornerShape(dimensionResource(R.dimen.notification_corner_radius))
                )
                .background(MaterialTheme.colorScheme.primary)
                .pointerInput(Unit) {
                    detectHorizontalDragGestures { change, _ ->
                        change.consume()
                        val upTime = SystemClock.uptimeMillis()
                        val event =
                            MotionEvent.obtain(
                                upTime,
                                upTime,
                                MotionEvent.ACTION_MOVE,
                                change.position.x,
                                change.position.y,
                                0,
                            )
                        viewModel.mediaHost.hostView.dispatchTouchEvent(event)
                        event.recycle()
                    }
                },
        factory = { _ ->
            viewModel.mediaHost.hostView.apply {
                layoutParams =
                    FrameLayout.LayoutParams(
                        FrameLayout.LayoutParams.MATCH_PARENT,
                        FrameLayout.LayoutParams.MATCH_PARENT,
                    )
            }
            viewModel.mediaHost.hostView
        },
        onReset = {},
    )
}

/** Container of the glanceable hub grid to enable accessibility actions when focused. */
@Composable
fun AccessibilityContainer(viewModel: BaseCommunalViewModel, content: @Composable () -> Unit) {
    val context = LocalContext.current
    val isFocusable by viewModel.isFocusable.collectAsStateWithLifecycle(initialValue = false)
    Box(
        modifier =
            Modifier.fillMaxWidth().wrapContentHeight().thenIf(
                isFocusable && !viewModel.isEditMode
            ) {
                Modifier.focusable(isFocusable).semantics {
                    contentDescription =
                        context.getString(
                            R.string.accessibility_content_description_for_communal_hub
                        )
                    customActions =
                        listOf(
                            CustomAccessibilityAction(
                                context.getString(
                                    R.string.accessibility_action_label_close_communal_hub
                                )
                            ) {
                                viewModel.changeScene(
                                    CommunalScenes.Blank,
                                    "closed by accessibility",
                                )
                                true
                            },
                            CustomAccessibilityAction(
                                context.getString(R.string.accessibility_action_label_edit_widgets)
                            ) {
                                viewModel.setSelectedKey(null)
                                viewModel.onOpenWidgetEditor()
                                true
                            },
                        )
                }
            }
    ) {
        content()
    }
}

/**
 * Text size converted from dp value to the equivalent sp value using the current screen density,
 * ensuring it does not scale with the font size setting.
 */
@Composable
private fun nonScalableTextSize(sizeInDp: Dp) = with(LocalDensity.current) { sizeInDp.toSp() }

/**
 * Returns the `contentPadding` of the grid. Use the vertical padding to push the grid content area
 * below the toolbar and let the grid take the max size. This ensures the item can be dragged
 * outside the grid over the toolbar, without part of it getting clipped by the container.
 */
@Composable
private fun gridContentPadding(isEditMode: Boolean, toolbarSize: IntSize?): PaddingValues {
    if (!isEditMode || toolbarSize == null) {
        return if (communalResponsiveGrid()) {
            val horizontalPaddings: Dp =
                if (isCompactWindow()) {
                    horizontalPaddingWithInsets(Dimensions.ItemSpacingCompact)
                } else {
                    Dimensions.ItemSpacing
                }
            PaddingValues(start = horizontalPaddings, end = horizontalPaddings)
        } else {
            PaddingValues(
                start = Dimensions.ItemSpacing,
                end = Dimensions.ItemSpacing,
                top = hubDimensions.GridTopSpacing,
            )
        }
    }
    val context = LocalContext.current
    val density = LocalDensity.current
    val windowMetrics = WindowMetricsCalculator.getOrCreate().computeCurrentWindowMetrics(context)
    val screenHeight = with(density) { windowMetrics.bounds.height().toDp() }
    val toolbarHeight = with(density) { Dimensions.ToolbarPaddingTop + toolbarSize.height.toDp() }
    return if (communalResponsiveGrid()) {
        PaddingValues(
            start = Dimensions.ToolbarPaddingHorizontal,
            end = Dimensions.ToolbarPaddingHorizontal,
            top = hubDimensions.GridTopSpacing,
        )
    } else {
        val verticalPadding =
            ((screenHeight - toolbarHeight - hubDimensions.GridHeight +
                    hubDimensions.GridTopSpacing) / 2)
                .coerceAtLeast(Dimensions.Spacing)
        PaddingValues(
            start = Dimensions.ToolbarPaddingHorizontal,
            end = Dimensions.ToolbarPaddingHorizontal,
            top = verticalPadding + toolbarHeight,
            bottom = verticalPadding,
        )
    }
}

/** Compact size in landscape or portrait */
@Composable
fun isCompactWindow(): Boolean {
    val windowSizeClass = LocalWindowSizeClass.current
    return remember(windowSizeClass) {
        windowSizeClass.widthSizeClass == WindowWidthSizeClass.Compact ||
            windowSizeClass.heightSizeClass == WindowHeightSizeClass.Compact
    }
}

private fun CommunalContentSize.FixedSize.dp(): Dp {
    return when (this) {
        CommunalContentSize.FixedSize.FULL -> Dimensions.CardHeightFull
        CommunalContentSize.FixedSize.HALF -> Dimensions.CardHeightHalf
        CommunalContentSize.FixedSize.THIRD -> Dimensions.CardHeightThird
    }
}

private fun firstIndexAtOffset(gridState: LazyGridState, offset: Offset): Int? =
    gridState.layoutInfo.visibleItemsInfo.firstItemAtOffset(offset)?.index

/** Returns the key of item if it's editable at the given index. Only widget is editable. */
private fun keyAtIndexIfEditable(list: List<CommunalContentModel>, index: Int): String? =
    if (index in list.indices && list[index].isWidgetContent()) list[index].key else null

class Dimensions(val context: Context, val config: Configuration) {
    val GridTopSpacing: Dp
        get() {
            val result =
                if (
                    communalResponsiveGrid() ||
                        config.orientation == Configuration.ORIENTATION_LANDSCAPE
                ) {
                    114.dp
                } else {
                    val windowMetrics =
                        WindowMetricsCalculator.getOrCreate().computeCurrentWindowMetrics(context)
                    val density = context.resources.displayMetrics.density
                    val screenHeight = (windowMetrics.bounds.height() / density).dp
                    ((screenHeight - CardHeightFull) / 2)
                }
            return result
        }

    val GridHeight: Dp
        get() = CardHeightFull + GridTopSpacing

    companion object {
        val CardHeightFull
            get() = 530.adjustedDp

        val ItemSpacingCompact
            get() = 12.adjustedDp

        val ItemSpacing
            get() = if (communalResponsiveGrid()) 32.adjustedDp else 50.adjustedDp

        val CardHeightHalf
            get() = (CardHeightFull - ItemSpacing) / 2

        val CardHeightThird
            get() = (CardHeightFull - (2 * ItemSpacing)) / 3

        val CardWidth
            get() = 360.adjustedDp

        val CardOutlineWidth
            get() = 3.adjustedDp

        val Spacing
            get() = ItemSpacing / 2

        // The sizing/padding of the toolbar in glanceable hub edit mode
        val ToolbarPaddingTop
            get() = 27.adjustedDp

        val ToolbarPaddingHorizontal
            get() = ItemSpacing

        val ToolbarButtonPaddingHorizontal
            get() = 24.adjustedDp

        val ToolbarButtonPaddingVertical
            get() = 16.adjustedDp

        val ButtonPadding =
            PaddingValues(
                vertical = ToolbarButtonPaddingVertical,
                horizontal = ToolbarButtonPaddingHorizontal,
            )
        val IconSize = 40.adjustedDp
        val SlideOffsetY = 30.adjustedDp
    }
}

data class WidgetSizeInfo(val minHeightPx: Int, val maxHeightPx: Int)

private fun CommunalContentModel.getSpanOrMax(maxSpan: Int?) =
    if (maxSpan != null) {
        size.span.coerceAtMost(maxSpan)
    } else {
        size.span
    }

private fun IntRect.percentOverlap(other: IntRect): Float {
    val intersection = intersect(other)
    if (intersection.width < 0 || intersection.height < 0) {
        return 0f
    }
    val overlapArea = intersection.width * intersection.height
    val area = width * height
    return overlapArea.toFloat() / area.toFloat()
}

private fun calculatePercentVisible(state: LazyGridState, index: Int): Float {
    val viewportSize = state.layoutInfo.viewportSize
    val visibleRect =
        IntRect(
            offset =
                IntOffset(
                    state.layoutInfo.viewportStartOffset + state.layoutInfo.beforeContentPadding,
                    0,
                ),
            size =
                IntSize(
                    width =
                        viewportSize.width -
                            state.layoutInfo.beforeContentPadding -
                            state.layoutInfo.afterContentPadding,
                    height = viewportSize.height,
                ),
        )

    val itemInfo = state.layoutInfo.visibleItemsInfo.find { it.index == index }
    return if (itemInfo != null) {
        val boundingBox = IntRect(itemInfo.offset, itemInfo.size)
        boundingBox.percentOverlap(visibleRect)
    } else {
        0f
    }
}

private object Colors {
    val DisabledColorFilter by lazy { disabledColorMatrix() }

    /** Returns the disabled image filter. Ported over from [DisableImageView]. */
    private fun disabledColorMatrix(): ColorMatrix {
        val brightnessMatrix = ColorMatrix()
        val brightnessAmount = 0.5f
        val brightnessRgb = (255 * brightnessAmount).toInt().toFloat()
        // Brightness: C-new = C-old*(1-amount) + amount
        val scale = 1f - brightnessAmount
        val mat = brightnessMatrix.values
        mat[0] = scale
        mat[6] = scale
        mat[12] = scale
        mat[4] = brightnessRgb
        mat[9] = brightnessRgb
        mat[14] = brightnessRgb

        return ColorMatrix().apply {
            setToSaturation(0F)
            timesAssign(brightnessMatrix)
        }
    }
}

/** The resource id of communal hub accessible from UiAutomator. */
private const val COMMUNAL_HUB_TEST_TAG = "communal_hub"
