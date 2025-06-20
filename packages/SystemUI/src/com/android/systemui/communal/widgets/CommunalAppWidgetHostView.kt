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

package com.android.systemui.communal.widgets

import android.appwidget.AppWidgetHostView
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProviderInfo
import android.content.Context
import android.content.pm.LauncherActivityInfo
import android.content.pm.LauncherApps
import android.graphics.Outline
import android.graphics.Rect
import android.view.View
import android.view.ViewOutlineProvider
import android.widget.RemoteViews
import android.widget.RemoteViews.RemoteResponse
import androidx.core.view.doOnLayout
import com.android.systemui.animation.LaunchableView
import com.android.systemui.animation.LaunchableViewDelegate

/** AppWidgetHostView that displays in communal hub with support for rounded corners. */
class CommunalAppWidgetHostView(
    context: Context,
    private val interactionHandler: RemoteViews.InteractionHandler,
) : AppWidgetHostView(context, interactionHandler), LaunchableView {
    private val launchableViewDelegate =
        LaunchableViewDelegate(this, superSetVisibility = { super.setVisibility(it) })

    // Mutable corner radius.
    var enforcedCornerRadius: Float

    // Mutable `Rect`. The size will be mutated when the widget is reapplied.
    var enforcedRectangle: Rect

    private var pendingUpdate: Boolean = false
    private var pendingRemoteViews: RemoteViews? = null

    init {
        enforcedCornerRadius = RoundedCornerEnforcement.computeEnforcedRadius(context)
        enforcedRectangle = Rect()
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        super.onLayout(changed, l, t, r, b)

        enforceRoundedCorners()
    }

    override fun setAppWidget(appWidgetId: Int, info: AppWidgetProviderInfo?) {
        super.setAppWidget(appWidgetId, info)
        setPadding(0, 0, 0, 0)
    }

    private val cornerRadiusEnforcementOutline: ViewOutlineProvider =
        object : ViewOutlineProvider() {
            override fun getOutline(view: View?, outline: Outline) {
                if (enforcedRectangle.isEmpty || enforcedCornerRadius <= 0) {
                    outline.setEmpty()
                } else {
                    outline.setRoundRect(enforcedRectangle, enforcedCornerRadius)
                }
            }
        }

    override fun updateAppWidget(remoteViews: RemoteViews?) {
        // Workaround for Jetpack Compose bug which fails to render the widget if we add the
        // RemoteViews before this parent view has been laid out. Therefore we wait for layout
        // before calling the super.updateAppWidget() to actually render the widget.
        // See b/387938328
        pendingRemoteViews = remoteViews

        if (!pendingUpdate) {
            pendingUpdate = true
            doOnLayout {
                super.updateAppWidget(pendingRemoteViews)
                pendingRemoteViews = null
                pendingUpdate = false
            }
        }
    }

    private fun enforceRoundedCorners() {
        if (enforcedCornerRadius <= 0) {
            resetRoundedCorners()
            return
        }
        val background: View? = RoundedCornerEnforcement.findBackground(this)
        if (background == null || RoundedCornerEnforcement.hasAppWidgetOptedOut(this, background)) {
            resetRoundedCorners()
            return
        }
        RoundedCornerEnforcement.computeRoundedRectangle(this, background, enforcedRectangle)
        outlineProvider = cornerRadiusEnforcementOutline
        clipToOutline = true
        invalidateOutline()
    }

    private fun resetRoundedCorners() {
        outlineProvider = ViewOutlineProvider.BACKGROUND
        clipToOutline = false
    }

    override fun setShouldBlockVisibilityChanges(block: Boolean) =
        launchableViewDelegate.setShouldBlockVisibilityChanges(block)

    override fun setVisibility(visibility: Int) = launchableViewDelegate.setVisibility(visibility)

    override fun onDefaultViewClicked(view: View) {
        AppWidgetManager.getInstance(context)?.noteAppWidgetTapped(appWidgetId)
        if (appWidgetInfo == null) {
            return
        }
        val launcherApps = context.getSystemService(LauncherApps::class.java)
        val activityInfo: LauncherActivityInfo =
            launcherApps
                .getActivityList(appWidgetInfo.provider.packageName, appWidgetInfo.profile)
                ?.getOrNull(0) ?: return

        val intent =
            launcherApps.getMainActivityLaunchIntent(
                activityInfo.componentName,
                null,
                activityInfo.user,
            )
        if (intent != null) {
            interactionHandler.onInteraction(view, intent, RemoteResponse.fromPendingIntent(intent))
        }
    }
}
