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

package com.android.systemui.inputdevice.tutorial.ui

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.app.NotificationCompat
import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.inputdevice.tutorial.domain.interactor.TutorialSchedulerInteractor
import com.android.systemui.inputdevice.tutorial.domain.interactor.TutorialSchedulerInteractor.Companion.TAG
import com.android.systemui.inputdevice.tutorial.domain.interactor.TutorialSchedulerInteractor.TutorialType
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_ENTRY_POINT_KEY
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_ENTRY_POINT_SCHEDULER
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_SCOPE_ALL
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_SCOPE_KEY
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_SCOPE_KEYBOARD
import com.android.systemui.inputdevice.tutorial.ui.view.KeyboardTouchpadTutorialActivity.Companion.INTENT_TUTORIAL_SCOPE_TOUCHPAD
import com.android.systemui.res.R
import com.android.systemui.settings.UserTracker
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.merge

/** When the scheduler is due, show a notification to launch tutorial */
@SysUISingleton
class TutorialNotificationCoordinator
@Inject
constructor(
    @Background private val backgroundScope: CoroutineScope,
    @Application private val context: Context,
    private val tutorialSchedulerInteractor: TutorialSchedulerInteractor,
    private val notificationManager: NotificationManager,
    private val userTracker: UserTracker,
) {
    private var updaterJob: Job? = null

    fun start() {
        backgroundScope.launch {
            merge(
                    tutorialSchedulerInteractor.tutorials,
                    tutorialSchedulerInteractor.commandTutorials,
                )
                .filter { it != TutorialType.NONE }
                .collectLatest {
                    showNotification(it)
                    updaterJob?.cancel()
                    updaterJob = backgroundScope.launch { updateWhenDeviceDisconnects() }
                }
        }
    }

    private suspend fun updateWhenDeviceDisconnects() {
        // Only update the notification when there is an active one (i.e. if the notification has
        // been dismissed by the user, or if the tutorial has been launched, there's no need to
        // update)
        tutorialSchedulerInteractor.tutorialTypeUpdates
            .filter { hasNotification() }
            .collect {
                if (it == TutorialType.NONE)
                    notificationManager.cancelAsUser(TAG, NOTIFICATION_ID, userTracker.userHandle)
                else showNotification(it)
            }
    }

    private fun hasNotification() =
        notificationManager.activeNotifications.any { it.id == NOTIFICATION_ID }

    // By sharing the same tag and id, we update the content of existing notification instead of
    // creating multiple notifications
    private fun showNotification(tutorialType: TutorialType) {
        // Safe guard - but this should never been reached
        if (tutorialType == TutorialType.NONE) return

        if (notificationManager.getNotificationChannel(CHANNEL_ID) == null)
            createNotificationChannel()

        // Replace "System UI" app name with "Android System"
        val extras = Bundle()
        extras.putString(
            Notification.EXTRA_SUBSTITUTE_APP_NAME,
            context.getString(com.android.internal.R.string.android_system_label),
        )

        val info = getNotificationInfo(tutorialType)!!
        val notification =
            NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_settings)
                .setContentTitle(info.title)
                .setContentText(info.text)
                .setContentIntent(createPendingIntent(info.type))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .addExtras(extras)
                .build()

        notificationManager.notifyAsUser(TAG, NOTIFICATION_ID, notification, userTracker.userHandle)
    }

    private fun createNotificationChannel() {
        val channel =
            NotificationChannel(
                CHANNEL_ID,
                context.getString(com.android.internal.R.string.android_system_label),
                NotificationManager.IMPORTANCE_DEFAULT,
            )
        notificationManager.createNotificationChannel(channel)
    }

    private fun createPendingIntent(tutorialType: String): PendingIntent {
        val intent =
            Intent(context, KeyboardTouchpadTutorialActivity::class.java).apply {
                putExtra(INTENT_TUTORIAL_SCOPE_KEY, tutorialType)
                putExtra(INTENT_TUTORIAL_ENTRY_POINT_KEY, INTENT_TUTORIAL_ENTRY_POINT_SCHEDULER)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
        return PendingIntent.getActivity(
            context,
            /* requestCode= */ 0,
            intent,
            PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private data class NotificationInfo(val title: String, val text: String, val type: String)

    private fun getNotificationInfo(tutorialType: TutorialType): NotificationInfo? =
        when (tutorialType) {
            TutorialType.KEYBOARD ->
                NotificationInfo(
                    context.getString(R.string.launch_keyboard_tutorial_notification_title),
                    context.getString(R.string.launch_keyboard_tutorial_notification_content),
                    INTENT_TUTORIAL_SCOPE_KEYBOARD,
                )
            TutorialType.TOUCHPAD ->
                NotificationInfo(
                    context.getString(R.string.launch_touchpad_tutorial_notification_title),
                    context.getString(R.string.launch_touchpad_tutorial_notification_content),
                    INTENT_TUTORIAL_SCOPE_TOUCHPAD,
                )
            TutorialType.BOTH ->
                NotificationInfo(
                    context.getString(
                        R.string.launch_keyboard_touchpad_tutorial_notification_title
                    ),
                    context.getString(
                        R.string.launch_keyboard_touchpad_tutorial_notification_content
                    ),
                    INTENT_TUTORIAL_SCOPE_ALL,
                )
            TutorialType.NONE -> null
        }

    companion object {
        private const val CHANNEL_ID = "TutorialSchedulerNotificationChannel"
        private const val NOTIFICATION_ID = 5566
    }
}
