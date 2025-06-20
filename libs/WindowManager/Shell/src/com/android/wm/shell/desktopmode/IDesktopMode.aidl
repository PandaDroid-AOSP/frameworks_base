/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.wm.shell.desktopmode;

import android.app.ActivityManager.RunningTaskInfo;
import android.content.Intent;
import android.os.Bundle;
import android.window.RemoteTransition;
import com.android.wm.shell.desktopmode.IDesktopTaskListener;
import com.android.wm.shell.shared.desktopmode.DesktopModeTransitionSource;
import com.android.wm.shell.shared.desktopmode.DesktopTaskToFrontReason;
import com.android.wm.shell.desktopmode.IMoveToDesktopCallback;

/**
 * Interface that is exposed to remote callers to manipulate desktop mode features.
 */
interface IDesktopMode {
    /** If possible, creates a new desk on the display whose ID is `displayId`. */
    oneway void createDesk(int displayId);

    /** Activates the desk whose ID is `deskId` on whatever display it currently exists on. */
    oneway void activateDesk(int deskId, in RemoteTransition remoteTransition);

    /** Removes the desk with the given `deskId`. */
    oneway void removeDesk(int deskId);

    /** Removes all the available desks on all displays. */
    oneway void removeAllDesks();

    /** Show apps on the desktop on the given display */
    void showDesktopApps(int displayId, in RemoteTransition remoteTransition);

    /** @deprecated use {@link #showDesktopApps} instead. */
    void stashDesktopApps(int displayId);

    /** @deprecated this is no longer supported. */
    void hideStashedDesktopApps(int displayId);

    /**
     * Bring task with the given id to front, using the given remote transition.
     *
     * <p> Note: beyond moving a task to the front, this method will minimize a task if we reach the
     * Desktop task limit, so {@code remoteTransition} should also handle any such minimize change.
     */
    oneway void showDesktopApp(int taskId, in @nullable RemoteTransition remoteTransition,
            in DesktopTaskToFrontReason toFrontReason);

    /** Perform cleanup transactions after the animation to split select is complete */
    oneway void onDesktopSplitSelectAnimComplete(in RunningTaskInfo taskInfo);

    /** Set listener that will receive callbacks about updates to desktop tasks */
    oneway void setTaskListener(IDesktopTaskListener listener);

    /** Move a task with given `taskId` to desktop */
    void moveToDesktop(int taskId, in DesktopModeTransitionSource transitionSource,
                        in @nullable RemoteTransition remoteTransition,
                        in @nullable IMoveToDesktopCallback callback);

    /**
     * Removes the default desktop on the given display.
     * @deprecated with multi-desks, we should use `removeDesk()`.
     */
    oneway void removeDefaultDeskInDisplay(int displayId);

    /** Move a task with given `taskId` to external display */
    void moveToExternalDisplay(int taskId);

    /** Start a transition when launching an intent in desktop mode */
    void startLaunchIntentTransition(in Intent intent, in Bundle options, in int displayId);
}
