/*
 * Copyright (C) 2020 The Android Open Source Project
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
package com.android.wm.shell.bubbles;

import static android.app.ActivityTaskManager.INVALID_TASK_ID;
import static android.os.AsyncTask.Status.FINISHED;

import static com.android.internal.annotations.VisibleForTesting.Visibility.PRIVATE;
import static com.android.wm.shell.protolog.ShellProtoLogGroup.WM_SHELL_BUBBLES;

import android.annotation.DimenRes;
import android.annotation.Hide;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Person;
import android.app.TaskInfo;
import android.content.Context;
import android.content.Intent;
import android.content.LocusId;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutInfo;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Path;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;
import android.os.Parcelable;
import android.os.UserHandle;
import android.provider.Settings;
import android.service.notification.StatusBarNotification;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.logging.InstanceId;
import com.android.internal.protolog.ProtoLog;
import com.android.launcher3.icons.BubbleIconFactory;
import com.android.wm.shell.Flags;
import com.android.wm.shell.bubbles.bar.BubbleBarExpandedView;
import com.android.wm.shell.bubbles.bar.BubbleBarLayerView;
import com.android.wm.shell.common.ComponentUtils;
import com.android.wm.shell.shared.annotations.ShellBackgroundThread;
import com.android.wm.shell.shared.annotations.ShellMainThread;
import com.android.wm.shell.shared.bubbles.BubbleInfo;
import com.android.wm.shell.shared.bubbles.ParcelableFlyoutMessage;
import com.android.wm.shell.taskview.TaskView;

import java.io.PrintWriter;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Encapsulates the data and UI elements of a bubble.
 */
public class Bubble implements BubbleViewProvider {
    private static final String TAG = "Bubble";

    /** A string prefix used in app bubbles' {@link #mKey}. */
    public static final String KEY_APP_BUBBLE = "key_app_bubble";

    /** A string prefix used in note bubbles' {@link #mKey}. */
    public static final String KEY_NOTE_BUBBLE = "key_note_bubble";

    /** The possible types a bubble may be. */
    public enum BubbleType {
        /** Chat is from a notification. */
        TYPE_CHAT,
        /** Notes are from the note taking API. */
        TYPE_NOTE,
        /** Shortcuts from bubble anything, based on {@link ShortcutInfo}. */
        TYPE_SHORTCUT,
        /** Apps are from bubble anything. */
        TYPE_APP,
    }

    private final BubbleType mType;

    private final String mKey;
    @Nullable
    private final String mGroupKey;
    @Nullable
    private final LocusId mLocusId;

    private final Executor mMainExecutor;
    private final Executor mBgExecutor;

    private long mLastUpdated;
    private long mLastAccessed;

    @Nullable
    private Bubbles.BubbleMetadataFlagListener mBubbleMetadataFlagListener;

    /** Whether the bubble should show a dot for the notification indicating updated content. */
    private boolean mShowBubbleUpdateDot = true;

    /** Whether flyout text should be suppressed, regardless of any other flags or state. */
    private boolean mSuppressFlyout;

    // Items that are typically loaded later
    private String mAppName;
    private ShortcutInfo mShortcutInfo;
    private String mMetadataShortcutId;

    /**
     * If {@link BubbleController#isShowingAsBubbleBar()} is true, the only view that will be
     * populated will be {@link #mBubbleBarExpandedView}. If it is false, {@link #mIconView}
     * and {@link #mExpandedView} will be populated.
     */
    @Nullable
    private BadgedImageView mIconView;
    @Nullable
    private BubbleExpandedView mExpandedView;
    @Nullable
    private BubbleBarExpandedView mBubbleBarExpandedView;
    @Nullable
    private BubbleTaskView mBubbleTaskView;

    @Nullable
    private BubbleViewInfoTask mInflationTask;
    @Nullable
    private BubbleViewInfoTaskLegacy mInflationTaskLegacy;
    private boolean mInflateSynchronously;
    private boolean mPendingIntentCanceled;
    private boolean mIsImportantConversation;

    /**
     * Presentational info about the flyout.
     */
    public static class FlyoutMessage {
        @Nullable public Icon senderIcon;
        @Nullable public Drawable senderAvatar;
        @Nullable public CharSequence senderName;
        @Nullable public CharSequence message;
        @Nullable public boolean isGroupChat;
    }

    private FlyoutMessage mFlyoutMessage;
    // The developer provided image for the bubble
    private Bitmap mBubbleBitmap;
    // The app badge for the bubble
    private Bitmap mBadgeBitmap;
    // App badge without any markings for important conversations
    private Bitmap mRawBadgeBitmap;
    private int mDotColor;
    private Path mDotPath;
    private int mFlags;

    @NonNull
    private UserHandle mUser;
    @NonNull
    private String mPackageName;
    @Nullable
    private String mTitle;
    @Nullable
    private Icon mIcon;
    private boolean mIsBubble;
    private boolean mIsTextChanged;
    private boolean mIsDismissable;
    private boolean mShouldSuppressNotificationDot;
    private boolean mShouldSuppressNotificationList;
    private boolean mShouldSuppressPeek;
    private int mDesiredHeight;
    @DimenRes
    private int mDesiredHeightResId;
    private int mTaskId;

    /** for logging **/
    @Nullable
    private InstanceId mInstanceId;
    @Nullable
    private String mChannelId;
    private int mNotificationId;
    private int mAppUid = -1;

    /**
     * A bubble is created and can be updated. This intent is updated until the user first
     * expands the bubble. Once the user has expanded the contents, we ignore the intent updates
     * to prevent restarting the intent & possibly altering UI state in the activity in front of
     * the user.
     *
     * Once the bubble is overflowed, the activity is finished and updates to the
     * notification are respected. Typically an update to an overflowed bubble would result in
     * that bubble being added back to the stack anyways.
     */
    @Nullable
    private PendingIntent mPendingIntent;
    private boolean mPendingIntentActive;
    @Nullable
    private PendingIntent.CancelListener mPendingIntentCancelListener;

    /**
     * Sent when the bubble & notification are no longer visible to the user (i.e. no
     * notification in the shade, no bubble in the stack or overflow).
     */
    @Nullable
    private PendingIntent mDeleteIntent;

    /**
     * Used for app & note bubbles.
     */
    @Nullable
    private Intent mIntent;

    /**
     * Set while preparing a transition for animation. Several steps are needed before animation
     * starts, so this is used to detect and route associated events to the coordinating transition.
     */
    @Nullable
    private BubbleTransitions.BubbleTransition mPreparingTransition;

    /**
     * Create a bubble with limited information based on given {@link ShortcutInfo}.
     * Note: Currently this is only being used when the bubble is persisted to disk.
     */
    public Bubble(@NonNull final String key, @NonNull final ShortcutInfo shortcutInfo,
            final int desiredHeight, final int desiredHeightResId, @Nullable final String title,
            int taskId, @Nullable final String locus, boolean isDismissable,
            @ShellMainThread Executor mainExecutor,
            @ShellBackgroundThread Executor bgExecutor,
            final Bubbles.BubbleMetadataFlagListener listener) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(shortcutInfo);
        mMetadataShortcutId = shortcutInfo.getId();
        mShortcutInfo = shortcutInfo;
        mKey = key;
        mGroupKey = null;
        mLocusId = locus != null ? new LocusId(locus) : null;
        mIsDismissable = isDismissable;
        mFlags = 0;
        mUser = shortcutInfo.getUserHandle();
        mPackageName = shortcutInfo.getPackage();
        mIcon = shortcutInfo.getIcon();
        mDesiredHeight = desiredHeight;
        mDesiredHeightResId = desiredHeightResId;
        mTitle = title;
        mShowBubbleUpdateDot = false;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = taskId;
        mBubbleMetadataFlagListener = listener;
        // TODO (b/394085999) read/write type to xml
        mType = BubbleType.TYPE_CHAT;
    }

    private Bubble(
            Intent intent,
            UserHandle user,
            @Nullable Icon icon,
            BubbleType type,
            String key,
            @ShellMainThread Executor mainExecutor,
            @ShellBackgroundThread Executor bgExecutor) {
        mGroupKey = null;
        mLocusId = null;
        mFlags = 0;
        mUser = user;
        mIcon = icon;
        mType = type;
        mKey = key;
        mShowBubbleUpdateDot = false;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = INVALID_TASK_ID;
        mIntent = intent;
        mDesiredHeight = Integer.MAX_VALUE;
        mPackageName = intent.getPackage();
    }

    private Bubble(
            PendingIntent intent,
            UserHandle user,
            String key,
            @ShellMainThread Executor mainExecutor,
            @ShellBackgroundThread Executor bgExecutor) {
        mGroupKey = null;
        mLocusId = null;
        mFlags = 0;
        mUser = user;
        mIcon = null;
        mType = BubbleType.TYPE_APP;
        mKey = key;
        mShowBubbleUpdateDot = false;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = INVALID_TASK_ID;
        mPendingIntent = intent;
        mIntent = null;
        mDesiredHeight = Integer.MAX_VALUE;
        mPackageName = ComponentUtils.getPackageName(intent);
    }

    private Bubble(ShortcutInfo info, @ShellMainThread Executor mainExecutor,
            @ShellBackgroundThread Executor bgExecutor) {
        mGroupKey = null;
        mLocusId = null;
        mFlags = 0;
        mUser = info.getUserHandle();
        mIcon = info.getIcon();
        mType = BubbleType.TYPE_SHORTCUT;
        mKey = getBubbleKeyForShortcut(info);
        mShowBubbleUpdateDot = false;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = INVALID_TASK_ID;
        mIntent = null;
        mDesiredHeight = Integer.MAX_VALUE;
        mPackageName = info.getPackage();
        mShortcutInfo = info;
    }

    private Bubble(
            TaskInfo task,
            UserHandle user,
            @Nullable Icon icon,
            String key,
            @ShellMainThread Executor mainExecutor,
            @ShellBackgroundThread Executor bgExecutor) {
        mGroupKey = null;
        mLocusId = null;
        mFlags = 0;
        mUser = user;
        mIcon = icon;
        mType = BubbleType.TYPE_APP;
        mKey = key;
        mShowBubbleUpdateDot = false;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = task.taskId;
        mIntent = null;
        mDesiredHeight = Integer.MAX_VALUE;
        mPackageName = task.baseActivity.getPackageName();
    }

    /** Creates a note taking bubble. */
    public static Bubble createNotesBubble(Intent intent, UserHandle user, @Nullable Icon icon,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        return new Bubble(intent,
                user,
                icon,
                BubbleType.TYPE_NOTE,
                getNoteBubbleKeyForApp(intent.getPackage(), user),
                mainExecutor, bgExecutor);
    }

    /** Creates an app bubble. */
    public static Bubble createAppBubble(PendingIntent intent, UserHandle user,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        return new Bubble(intent,
                user,
                /* key= */ getAppBubbleKeyForApp(ComponentUtils.getPackageName(intent), user),
                mainExecutor, bgExecutor);
    }

    /** Creates an app bubble. */
    public static Bubble createAppBubble(Intent intent, UserHandle user, @Nullable Icon icon,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        return new Bubble(intent,
                user,
                icon,
                BubbleType.TYPE_APP,
                getAppBubbleKeyForApp(ComponentUtils.getPackageName(intent), user),
                mainExecutor, bgExecutor);
    }

    /** Creates a task bubble. */
    public static Bubble createTaskBubble(TaskInfo info, UserHandle user, @Nullable Icon icon,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        return new Bubble(info,
                user,
                icon,
                getAppBubbleKeyForTask(info),
                mainExecutor, bgExecutor);
    }

    /** Creates a shortcut bubble. */
    public static Bubble createShortcutBubble(
            ShortcutInfo info,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        return new Bubble(info, mainExecutor, bgExecutor);
    }

    /**
     * Returns the key for an app bubble from an app with package name, {@code packageName} on an
     * Android user, {@code user}.
     */
    public static String getAppBubbleKeyForApp(String packageName, UserHandle user) {
        Objects.requireNonNull(packageName);
        Objects.requireNonNull(user);
        return KEY_APP_BUBBLE + ":" + user.getIdentifier()  + ":" + packageName;
    }

    /**
     * Returns the key for a note bubble from an app with package name, {@code packageName} on an
     * Android user, {@code user}.
     */
    public static String getNoteBubbleKeyForApp(String packageName, UserHandle user) {
        Objects.requireNonNull(packageName);
        Objects.requireNonNull(user);
        return KEY_NOTE_BUBBLE + ":" + user.getIdentifier()  + ":" + packageName;
    }

    /**
     * Returns the key for a shortcut bubble using {@code packageName}, {@code user}, and the
     * {@code shortcutInfo} id.
     */
    public static String getBubbleKeyForShortcut(ShortcutInfo info) {
        return info.getPackage() + ":" + info.getUserId() + ":" + info.getId();
    }

    /**
     * Returns the key for an app bubble from an app with package name, {@code packageName} on an
     * Android user, {@code user}.
     */
    public static String getAppBubbleKeyForTask(TaskInfo taskInfo) {
        Objects.requireNonNull(taskInfo);
        return KEY_APP_BUBBLE + ":" + taskInfo.taskId;
    }

    /**
     * Creates a chat bubble based on a notification (contents of {@link BubbleEntry}.
     */
    @VisibleForTesting(visibility = PRIVATE)
    public Bubble(@NonNull final BubbleEntry entry,
            final Bubbles.BubbleMetadataFlagListener listener,
            final Bubbles.PendingIntentCanceledListener intentCancelListener,
            @ShellMainThread Executor mainExecutor, @ShellBackgroundThread Executor bgExecutor) {
        mType = BubbleType.TYPE_CHAT;
        mKey = entry.getKey();
        mGroupKey = entry.getGroupKey();
        mLocusId = entry.getLocusId();
        mBubbleMetadataFlagListener = listener;
        mPendingIntentCancelListener = intent -> {
            if (mPendingIntent != null) {
                mPendingIntent.unregisterCancelListener(mPendingIntentCancelListener);
            }
            mainExecutor.execute(() -> {
                intentCancelListener.onPendingIntentCanceled(this);
            });
        };
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mTaskId = INVALID_TASK_ID;
        setEntry(entry);
    }

    /** Converts this bubble into a {@link BubbleInfo} object to be shared with external callers. */
    public BubbleInfo asBubbleBarBubble() {
        return new BubbleInfo(getKey(),
                getFlags(),
                getShortcutId(),
                getIcon(),
                getUser().getIdentifier(),
                getPackageName(),
                getTitle(),
                getAppName(),
                isImportantConversation(),
                showAppBadge(),
                getParcelableFlyoutMessage());
    }

    /** Creates a parcelable flyout message to send to launcher. */
    @Nullable
    private ParcelableFlyoutMessage getParcelableFlyoutMessage() {
        if (mFlyoutMessage == null) {
            return null;
        }
        // the icon is only used in group chats
        Icon icon = mFlyoutMessage.isGroupChat ? mFlyoutMessage.senderIcon : null;
        String title =
                mFlyoutMessage.senderName == null ? null : mFlyoutMessage.senderName.toString();
        String message = mFlyoutMessage.message == null ? null : mFlyoutMessage.message.toString();
        return new ParcelableFlyoutMessage(icon, title, message);
    }

    @Override
    public String getKey() {
        return mKey;
    }

    @Hide
    public boolean isDismissable() {
        return mIsDismissable;
    }

    /**
     * @see StatusBarNotification#getGroupKey()
     * @return the group key for this bubble, if one exists.
     */
    public String getGroupKey() {
        return mGroupKey;
    }

    public LocusId getLocusId() {
        return mLocusId;
    }

    public UserHandle getUser() {
        return mUser;
    }

    @NonNull
    public String getPackageName() {
        return mPackageName;
    }

    @Override
    public Bitmap getBubbleIcon() {
        return mBubbleBitmap;
    }

    @Override
    public Bitmap getAppBadge() {
        return mBadgeBitmap;
    }

    @Override
    public Bitmap getRawAppBadge() {
        return mRawBadgeBitmap;
    }

    @Override
    public int getDotColor() {
        return mDotColor;
    }

    @Override
    public Path getDotPath() {
        return mDotPath;
    }

    @Nullable
    public String getAppName() {
        return mAppName;
    }

    @Nullable
    public ShortcutInfo getShortcutInfo() {
        return mShortcutInfo;
    }

    @Nullable
    @Override
    public BadgedImageView getIconView() {
        return mIconView;
    }

    @Nullable
    @Override
    public BubbleExpandedView getExpandedView() {
        return mExpandedView;
    }

    @Nullable
    @Override
    public BubbleBarExpandedView getBubbleBarExpandedView() {
        return mBubbleBarExpandedView;
    }

    @Nullable
    public String getTitle() {
        return mTitle;
    }

    /**
     * Returns the existing {@link #mBubbleTaskView} if it's not {@code null}. Otherwise a new
     * instance of {@link BubbleTaskView} is created.
     */
    public BubbleTaskView getOrCreateBubbleTaskView(BubbleTaskViewFactory taskViewFactory) {
        if (mBubbleTaskView == null) {
            mBubbleTaskView = taskViewFactory.create();
        }
        return mBubbleTaskView;
    }

    public TaskView getTaskView() {
        return mBubbleTaskView.getTaskView();
    }

    /**
     * @return the ShortcutInfo id if it exists, or the metadata shortcut id otherwise.
     */
    String getShortcutId() {
        return getShortcutInfo() != null
                ? getShortcutInfo().getId()
                : getMetadataShortcutId();
    }

    String getMetadataShortcutId() {
        return mMetadataShortcutId;
    }

    boolean hasMetadataShortcutId() {
        return (mMetadataShortcutId != null && !mMetadataShortcutId.isEmpty());
    }

    public BubbleTransitions.BubbleTransition getPreparingTransition() {
        return mPreparingTransition;
    }

    /**
     * Call this to clean up the task for the bubble. Ensure this is always called when done with
     * the bubble.
     */
    void cleanupExpandedView() {
        cleanupExpandedView(true);
    }

    private void cleanupExpandedView(boolean cleanupTaskView) {
        if (mExpandedView != null) {
            mExpandedView.cleanUpExpandedState();
            mExpandedView = null;
        }
        if (mBubbleBarExpandedView != null) {
            mBubbleBarExpandedView.cleanUpExpandedState();
            mBubbleBarExpandedView = null;
        }
        if (cleanupTaskView) {
            cleanupTaskView();
        }
        if (mPendingIntent != null) {
            mPendingIntent.unregisterCancelListener(mPendingIntentCancelListener);
        }
        mPendingIntentActive = false;
    }

    /** Cleans-up the taskview associated with this bubble (possibly removing the task from wm) */
    public void cleanupTaskView() {
        if (mBubbleTaskView != null) {
            mBubbleTaskView.cleanup();
            mBubbleTaskView = null;
        }
    }

    /**
     * Call when all the views should be removed/cleaned up.
     */
    public void cleanupViews() {
        ProtoLog.d(WM_SHELL_BUBBLES, "Bubble#cleanupViews=%s", getKey());
        cleanupViews(true);
    }

    /**
     * Call when all the views should be removed/cleaned up.
     *
     * <p>If we're switching between bar and floating modes, pass {@code false} on
     * {@code cleanupTaskView} to avoid recreating it in the new mode.
     */
    public void cleanupViews(boolean cleanupTaskView) {
        cleanupExpandedView(cleanupTaskView);
        mIconView = null;
    }

    void setPendingIntentCanceled() {
        mPendingIntentCanceled = true;
    }

    boolean getPendingIntentCanceled() {
        return mPendingIntentCanceled;
    }

    /**
     * Sets whether to perform inflation on the same thread as the caller. This method should only
     * be used in tests, not in production.
     */
    @VisibleForTesting
    void setInflateSynchronously(boolean inflateSynchronously) {
        mInflateSynchronously = inflateSynchronously;
    }

    /**
     * Sets the current bubble-transition that is coordinating a change in this bubble.
     */
    void setPreparingTransition(BubbleTransitions.BubbleTransition transit) {
        mPreparingTransition = transit;
    }

    /**
     * Sets whether this bubble is considered text changed. This method is purely for
     * testing.
     */
    @VisibleForTesting
    void setTextChangedForTest(boolean textChanged) {
        mIsTextChanged = textChanged;
    }

    /**
     * Starts a task to inflate & load any necessary information to display a bubble.
     *
     * @param callback the callback to notify one the bubble is ready to be displayed.
     * @param context the context for the bubble.
     * @param expandedViewManager the bubble expanded view manager.
     * @param taskViewFactory the task view factory used to create the task view for the bubble.
     * @param positioner the bubble positioner.
     * @param stackView the view the bubble is added to, iff showing as floating.
     * @param layerView the layer the bubble is added to, iff showing in the bubble bar.
     * @param iconFactory the icon factory used to create images for the bubble.
     */
    void inflate(BubbleViewInfoTask.Callback callback,
            Context context,
            BubbleExpandedViewManager expandedViewManager,
            BubbleTaskViewFactory taskViewFactory,
            BubblePositioner positioner,
            @Nullable BubbleStackView stackView,
            @Nullable BubbleBarLayerView layerView,
            BubbleIconFactory iconFactory,
            boolean skipInflation) {
        ProtoLog.v(WM_SHELL_BUBBLES, "Inflate bubble key=%s", getKey());
        if (Flags.bubbleViewInfoExecutors()) {
            if (mInflationTask != null && !mInflationTask.isFinished()) {
                mInflationTask.cancel();
            }
            mInflationTask = new BubbleViewInfoTask(this,
                    context,
                    expandedViewManager,
                    taskViewFactory,
                    positioner,
                    stackView,
                    layerView,
                    iconFactory,
                    skipInflation,
                    callback,
                    mMainExecutor,
                    mBgExecutor);
            if (mInflateSynchronously) {
                mInflationTask.startSync();
            } else {
                mInflationTask.start();
            }
        } else {
            if (mInflationTaskLegacy != null && mInflationTaskLegacy.getStatus() != FINISHED) {
                mInflationTaskLegacy.cancel(true /* mayInterruptIfRunning */);
            }
            mInflationTaskLegacy = new BubbleViewInfoTaskLegacy(this,
                    context,
                    expandedViewManager,
                    taskViewFactory,
                    positioner,
                    stackView,
                    layerView,
                    iconFactory,
                    skipInflation,
                    bubble -> {
                        if (callback != null) {
                            callback.onBubbleViewsReady(bubble);
                        }
                    },
                    mMainExecutor,
                    mBgExecutor);
            if (mInflateSynchronously) {
                mInflationTaskLegacy.onPostExecute(mInflationTaskLegacy.doInBackground());
            } else {
                mInflationTaskLegacy.execute();
            }
        }
    }

    boolean isInflated() {
        return (mIconView != null && mExpandedView != null) || mBubbleBarExpandedView != null;
    }

    void stopInflation() {
        if (Flags.bubbleViewInfoExecutors()) {
            if (mInflationTask == null) {
                return;
            }
            mInflationTask.cancel();
        } else {
            if (mInflationTaskLegacy == null) {
                return;
            }
            mInflationTaskLegacy.cancel(true /* mayInterruptIfRunning */);
        }
    }

    void setViewInfo(BubbleViewInfoTask.BubbleViewInfo info) {
        if (!isInflated()) {
            mIconView = info.imageView;
            mExpandedView = info.expandedView;
            mBubbleBarExpandedView = info.bubbleBarExpandedView;
        }

        mShortcutInfo = info.shortcutInfo;
        mAppName = info.appName;
        if (mTitle == null) {
            mTitle = mAppName;
        }
        mFlyoutMessage = info.flyoutMessage;

        mBadgeBitmap = info.badgeBitmap;
        mRawBadgeBitmap = info.rawBadgeBitmap;
        mBubbleBitmap = info.bubbleBitmap;

        mDotColor = info.dotColor;
        mDotPath = info.dotPath;

        if (mExpandedView != null) {
            mExpandedView.update(this /* bubble */);
        }
        if (mBubbleBarExpandedView != null) {
            mBubbleBarExpandedView.update(this /* bubble */);
        }
        if (mIconView != null) {
            mIconView.setRenderedBubble(this /* bubble */);
        }
    }

    /**
     * @deprecated {@link BubbleViewInfoTaskLegacy} is deprecated.
     */
    @Deprecated
    void setViewInfoLegacy(BubbleViewInfoTaskLegacy.BubbleViewInfo info) {
        if (!isInflated()) {
            mIconView = info.imageView;
            mExpandedView = info.expandedView;
            mBubbleBarExpandedView = info.bubbleBarExpandedView;
        }

        mShortcutInfo = info.shortcutInfo;
        mAppName = info.appName;
        if (mTitle == null) {
            mTitle = mAppName;
        }
        mFlyoutMessage = info.flyoutMessage;

        mBadgeBitmap = info.badgeBitmap;
        mRawBadgeBitmap = info.rawBadgeBitmap;
        mBubbleBitmap = info.bubbleBitmap;

        mDotColor = info.dotColor;
        mDotPath = info.dotPath;

        if (mExpandedView != null) {
            mExpandedView.update(this /* bubble */);
        }
        if (mBubbleBarExpandedView != null) {
            mBubbleBarExpandedView.update(this /* bubble */);
        }
        if (mIconView != null) {
            mIconView.setRenderedBubble(this /* bubble */);
        }
    }

    /**
     * Set visibility of bubble in the expanded state.
     *
     * <p>Note that this contents visibility doesn't affect visibility at {@link android.view.View},
     * and setting {@code false} actually means rendering the expanded view in transparent.
     *
     * @param visibility {@code true} if the expanded bubble should be visible on the screen.
     */
    @Override
    public void setTaskViewVisibility(boolean visibility) {
        if (mExpandedView != null) {
            mExpandedView.setContentVisibility(visibility);
        }
    }

    /**
     * Sets the entry associated with this bubble.
     */
    void setEntry(@NonNull final BubbleEntry entry) {
        Objects.requireNonNull(entry);
        boolean showingDotPreviously = showDot();
        mLastUpdated = entry.getStatusBarNotification().getPostTime();
        mIsBubble = entry.getStatusBarNotification().getNotification().isBubbleNotification();
        mPackageName = entry.getStatusBarNotification().getPackageName();
        mUser = entry.getStatusBarNotification().getUser();
        mTitle = getTitle(entry);
        mChannelId = entry.getStatusBarNotification().getNotification().getChannelId();
        mNotificationId = entry.getStatusBarNotification().getId();
        mAppUid = entry.getStatusBarNotification().getUid();
        mInstanceId = entry.getStatusBarNotification().getInstanceId();
        mFlyoutMessage = extractFlyoutMessage(entry);
        if (entry.getRanking() != null) {
            mShortcutInfo = entry.getRanking().getConversationShortcutInfo();
            mIsTextChanged = entry.getRanking().isTextChanged();
            if (entry.getRanking().getChannel() != null) {
                mIsImportantConversation =
                        entry.getRanking().getChannel().isImportantConversation();
            }
        }
        if (entry.getBubbleMetadata() != null) {
            mMetadataShortcutId = entry.getBubbleMetadata().getShortcutId();
            mFlags = entry.getBubbleMetadata().getFlags();
            mDesiredHeight = entry.getBubbleMetadata().getDesiredHeight();
            mDesiredHeightResId = entry.getBubbleMetadata().getDesiredHeightResId();
            mIcon = entry.getBubbleMetadata().getIcon();

            if (!mPendingIntentActive || mPendingIntent == null) {
                if (mPendingIntent != null) {
                    mPendingIntent.unregisterCancelListener(mPendingIntentCancelListener);
                }
                mPendingIntent = entry.getBubbleMetadata().getIntent();
                if (mPendingIntent != null) {
                    mPendingIntent.registerCancelListener(mPendingIntentCancelListener);
                }
            } else if (mPendingIntent != null && entry.getBubbleMetadata().getIntent() == null) {
                // Was an intent bubble now it's a shortcut bubble... still unregister the listener
                mPendingIntent.unregisterCancelListener(mPendingIntentCancelListener);
                mPendingIntentActive = false;
                mPendingIntent = null;
            }
            mDeleteIntent = entry.getBubbleMetadata().getDeleteIntent();
        }

        mIsDismissable = entry.isDismissable();
        mShouldSuppressNotificationDot = entry.shouldSuppressNotificationDot();
        mShouldSuppressNotificationList = entry.shouldSuppressNotificationList();
        mShouldSuppressPeek = entry.shouldSuppressPeek();
        if (showingDotPreviously != showDot()) {
            // This will update the UI if needed
            setShowDot(showDot());
        }
    }

    /**
     * @return the icon set on BubbleMetadata, if it exists. This is only non-null for bubbles
     * created via a PendingIntent. This is null for bubbles created by a shortcut, as we use the
     * icon from the shortcut.
     */
    @Nullable
    public Icon getIcon() {
        return mIcon;
    }

    boolean isTextChanged() {
        return mIsTextChanged;
    }

    /**
     * @return the last time this bubble was updated or accessed, whichever is most recent.
     */
    long getLastActivity() {
        return Math.max(mLastUpdated, mLastAccessed);
    }

    /**
     * Sets if the intent used for this bubble is currently active (i.e. populating an
     * expanded view, expanded or not).
     */
    void setPendingIntentActive() {
        mPendingIntentActive = true;
    }

    /**
     * Whether the pending intent of this bubble is active (i.e. has been sent).
     */
    boolean isPendingIntentActive() {
        return mPendingIntentActive;
    }

    public InstanceId getInstanceId() {
        return mInstanceId;
    }

    @Nullable
    public String getChannelId() {
        return mChannelId;
    }

    public int getNotificationId() {
        return mNotificationId;
    }

    /**
     * @return the task id of the task in which bubble contents is drawn.
     */
    @Override
    public int getTaskId() {
        if (mBubbleBarExpandedView != null) {
            return mBubbleBarExpandedView.getTaskId();
        }
        return mExpandedView != null ? mExpandedView.getTaskId() : mTaskId;
    }

    /**
     * Should be invoked whenever a Bubble is accessed (selected while expanded).
     */
    void markAsAccessedAt(long lastAccessedMillis) {
        mLastAccessed = lastAccessedMillis;
        setSuppressNotification(true);
        setShowDot(false /* show */);
    }

    /**
     * Should be invoked whenever a Bubble is promoted from overflow.
     */
    void markUpdatedAt(long lastAccessedMillis) {
        mLastUpdated = lastAccessedMillis;
    }

    /**
     * Whether this notification should be shown in the shade.
     */
    boolean showInShade() {
        return !shouldSuppressNotification() || !mIsDismissable;
    }

    /**
     * Whether this bubble is currently being hidden from the stack.
     */
    boolean isSuppressed() {
        return (mFlags & Notification.BubbleMetadata.FLAG_SUPPRESS_BUBBLE) != 0;
    }

    /**
     * Whether this bubble is able to be suppressed (i.e. has the developer opted into the API to
     * hide the bubble when in the same content).
     */
    boolean isSuppressable() {
        return (mFlags & Notification.BubbleMetadata.FLAG_SUPPRESSABLE_BUBBLE) != 0;
    }

    /**
     * Whether this notification conversation is important.
     */
    boolean isImportantConversation() {
        return mIsImportantConversation;
    }

    /**
     * Sets whether this notification should be suppressed in the shade.
     */
    @VisibleForTesting
    public void setSuppressNotification(boolean suppressNotification) {
        boolean prevShowInShade = showInShade();
        if (suppressNotification) {
            mFlags |= Notification.BubbleMetadata.FLAG_SUPPRESS_NOTIFICATION;
        } else {
            mFlags &= ~Notification.BubbleMetadata.FLAG_SUPPRESS_NOTIFICATION;
        }

        if (showInShade() != prevShowInShade && mBubbleMetadataFlagListener != null) {
            mBubbleMetadataFlagListener.onBubbleMetadataFlagChanged(this);
        }
    }

    /**
     * Sets whether this bubble should be suppressed from the stack.
     */
    public void setSuppressBubble(boolean suppressBubble) {
        if (!isSuppressable()) {
            Log.e(TAG, "calling setSuppressBubble on "
                    + getKey() + " when bubble not suppressable");
            return;
        }
        boolean prevSuppressed = isSuppressed();
        if (suppressBubble) {
            mFlags |= Notification.BubbleMetadata.FLAG_SUPPRESS_BUBBLE;
        } else {
            mFlags &= ~Notification.BubbleMetadata.FLAG_SUPPRESS_BUBBLE;
        }
        if (prevSuppressed != suppressBubble && mBubbleMetadataFlagListener != null) {
            mBubbleMetadataFlagListener.onBubbleMetadataFlagChanged(this);
        }
    }

    /**
     * Sets whether the bubble for this notification should show a dot indicating updated content.
     */
    void setShowDot(boolean showDot) {
        mShowBubbleUpdateDot = showDot;

        if (mIconView != null) {
            mIconView.updateDotVisibility(true /* animate */);
        }
    }

    /**
     * Whether the bubble for this notification should show a dot indicating updated content.
     */
    @Override
    public boolean showDot() {
        return mShowBubbleUpdateDot
                && !mShouldSuppressNotificationDot
                && !shouldSuppressNotification();
    }

    /**
     * Whether the flyout for the bubble should be shown.
     */
    @VisibleForTesting
    public boolean showFlyout() {
        return !mSuppressFlyout && !mShouldSuppressPeek
                && !shouldSuppressNotification()
                && !mShouldSuppressNotificationList;
    }

    /**
     * Set whether the flyout text for the bubble should be shown when an update is received.
     *
     * @param suppressFlyout whether the flyout text is shown
     */
    void setSuppressFlyout(boolean suppressFlyout) {
        mSuppressFlyout = suppressFlyout;
    }

    FlyoutMessage getFlyoutMessage() {
        return mFlyoutMessage;
    }

    int getRawDesiredHeight() {
        return mDesiredHeight;
    }

    int getRawDesiredHeightResId() {
        return mDesiredHeightResId;
    }

    float getDesiredHeight(Context context) {
        boolean useRes = mDesiredHeightResId != 0;
        if (useRes) {
            return getDimenForPackageUser(context, mDesiredHeightResId, mPackageName,
                    mUser.getIdentifier());
        } else {
            return mDesiredHeight * context.getResources().getDisplayMetrics().density;
        }
    }

    String getDesiredHeightString() {
        boolean useRes = mDesiredHeightResId != 0;
        if (useRes) {
            return String.valueOf(mDesiredHeightResId);
        } else {
            return String.valueOf(mDesiredHeight);
        }
    }

    /**
     * Returns the pending intent used to populate the bubble.
     */
    @Nullable
    PendingIntent getPendingIntent() {
        return mPendingIntent;
    }

    /**
     * Whether an app badge should be shown for this bubble.
     */
    public boolean showAppBadge() {
        return isChat() || isShortcut() || isNote();
    }

    /**
     * Returns the pending intent to send when a bubble is dismissed (set via the notification API).
     */
    @Nullable
    PendingIntent getDeleteIntent() {
        return mDeleteIntent;
    }

    /**
     * Returns the intent used to populate the bubble.
     */
    @Nullable
    public Intent getIntent() {
        return mIntent;
    }

    /**
     * Sets the intent used to populate the bubble.
     */
    void setIntent(Intent intent) {
        mIntent = intent;
    }

    /**
     * Returns whether this bubble is a conversation from the notification API.
     */
    public boolean isChat() {
        return mType == BubbleType.TYPE_CHAT;
    }

    /**
     * Returns whether this bubble is a note from the note taking API.
     */
    public boolean isNote() {
        return mType == BubbleType.TYPE_NOTE;
    }

    /**
     * Returns whether this bubble is a shortcut.
     */
    public boolean isShortcut() {
        return mType == BubbleType.TYPE_SHORTCUT;
    }

    /**
     * Returns whether this bubble is an app.
     */
    public boolean isApp() {
        return mType == BubbleType.TYPE_APP;
    }

    /** Creates open app settings intent */
    public Intent getSettingsIntent(final Context context) {
        final Intent intent = new Intent(Settings.ACTION_APP_NOTIFICATION_BUBBLE_SETTINGS);
        intent.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
        final int uid = getUid(context);
        if (uid != -1) {
            intent.putExtra(Settings.EXTRA_APP_UID, uid);
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return intent;
    }

    public int getAppUid() {
        return mAppUid;
    }

    private int getUid(final Context context) {
        if (mAppUid != -1) return mAppUid;
        final PackageManager pm = BubbleController.getPackageManagerForUser(context,
                mUser.getIdentifier());
        if (pm == null) return -1;
        try {
            final ApplicationInfo info = pm.getApplicationInfo(mShortcutInfo.getPackage(), 0);
            return info.uid;
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "cannot find uid", e);
        }
        return -1;
    }

    private int getDimenForPackageUser(Context context, int resId, String pkg, int userId) {
        Resources r;
        if (pkg != null) {
            try {
                if (userId == UserHandle.USER_ALL) {
                    userId = UserHandle.USER_SYSTEM;
                }
                r = context.createContextAsUser(UserHandle.of(userId), /* flags */ 0)
                        .getPackageManager().getResourcesForApplication(pkg);
                return r.getDimensionPixelSize(resId);
            } catch (PackageManager.NameNotFoundException ex) {
                // Uninstalled, don't care
            } catch (Resources.NotFoundException e) {
                // Invalid res id, return 0 and user our default
                Log.e(TAG, "Couldn't find desired height res id", e);
            }
        }
        return 0;
    }

    private boolean shouldSuppressNotification() {
        return isEnabled(Notification.BubbleMetadata.FLAG_SUPPRESS_NOTIFICATION);
    }

    public boolean shouldAutoExpand() {
        return isEnabled(Notification.BubbleMetadata.FLAG_AUTO_EXPAND_BUBBLE);
    }

    @VisibleForTesting
    public void setShouldAutoExpand(boolean shouldAutoExpand) {
        boolean prevAutoExpand = shouldAutoExpand();
        if (shouldAutoExpand) {
            enable(Notification.BubbleMetadata.FLAG_AUTO_EXPAND_BUBBLE);
        } else {
            disable(Notification.BubbleMetadata.FLAG_AUTO_EXPAND_BUBBLE);
        }
        if (prevAutoExpand != shouldAutoExpand && mBubbleMetadataFlagListener != null) {
            mBubbleMetadataFlagListener.onBubbleMetadataFlagChanged(this);
        }
    }

    public void setIsBubble(final boolean isBubble) {
        mIsBubble = isBubble;
    }

    public boolean isBubble() {
        return mIsBubble;
    }

    public void enable(int option) {
        mFlags |= option;
    }

    public void disable(int option) {
        mFlags &= ~option;
    }

    public boolean isEnabled(int option) {
        return (mFlags & option) != 0;
    }

    public int getFlags() {
        return mFlags;
    }

    @Override
    public String toString() {
        return "Bubble{" + mKey + '}';
    }

    /**
     * Description of current bubble state.
     */
    public void dump(@NonNull PrintWriter pw) {
        pw.print("key: "); pw.println(mKey);
        pw.print("  showInShade:   "); pw.println(showInShade());
        pw.print("  showDot:       "); pw.println(showDot());
        pw.print("  showFlyout:    "); pw.println(showFlyout());
        pw.print("  lastActivity:  "); pw.println(getLastActivity());
        pw.print("  desiredHeight: "); pw.println(getDesiredHeightString());
        pw.print("  suppressNotif: "); pw.println(shouldSuppressNotification());
        pw.print("  autoExpand:    "); pw.println(shouldAutoExpand());
        pw.print("  isDismissable: "); pw.println(mIsDismissable);
        pw.println("  bubbleMetadataFlagListener null?: " + (mBubbleMetadataFlagListener == null));
        if (mExpandedView != null) {
            mExpandedView.dump(pw, "  ");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Bubble)) return false;
        Bubble bubble = (Bubble) o;
        return Objects.equals(mKey, bubble.mKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mKey);
    }

    @Nullable
    private static String getTitle(@NonNull final BubbleEntry e) {
        final CharSequence titleCharSeq = e.getStatusBarNotification()
                .getNotification().extras.getCharSequence(Notification.EXTRA_TITLE);
        return titleCharSeq == null ? null : titleCharSeq.toString();
    }

    /**
     * Returns our best guess for the most relevant text summary of the latest update to this
     * notification, based on its type. Returns null if there should not be an update message.
     */
    @NonNull
    static Bubble.FlyoutMessage extractFlyoutMessage(BubbleEntry entry) {
        Objects.requireNonNull(entry);
        final Notification underlyingNotif = entry.getStatusBarNotification().getNotification();
        final Class<? extends Notification.Style> style = underlyingNotif.getNotificationStyle();

        Bubble.FlyoutMessage bubbleMessage = new Bubble.FlyoutMessage();
        bubbleMessage.isGroupChat = underlyingNotif.extras.getBoolean(
                Notification.EXTRA_IS_GROUP_CONVERSATION);
        try {
            if (Notification.BigTextStyle.class.equals(style)) {
                // Return the big text, it is big so probably important. If it's not there use the
                // normal text.
                CharSequence bigText =
                        underlyingNotif.extras.getCharSequence(Notification.EXTRA_BIG_TEXT);
                bubbleMessage.message = !TextUtils.isEmpty(bigText)
                        ? bigText
                        : underlyingNotif.extras.getCharSequence(Notification.EXTRA_TEXT);
                return bubbleMessage;
            } else if (Notification.MessagingStyle.class.equals(style)) {
                final List<Notification.MessagingStyle.Message> messages =
                        Notification.MessagingStyle.Message.getMessagesFromBundleArray(
                                (Parcelable[]) underlyingNotif.extras.get(
                                        Notification.EXTRA_MESSAGES));

                final Notification.MessagingStyle.Message latestMessage =
                        Notification.MessagingStyle.findLatestIncomingMessage(messages);
                if (latestMessage != null) {
                    bubbleMessage.message = latestMessage.getText();
                    Person sender = latestMessage.getSenderPerson();
                    bubbleMessage.senderName = sender != null ? sender.getName() : null;
                    bubbleMessage.senderAvatar = null;
                    bubbleMessage.senderIcon = sender != null ? sender.getIcon() : null;
                    return bubbleMessage;
                }
            } else if (Notification.InboxStyle.class.equals(style)) {
                CharSequence[] lines =
                        underlyingNotif.extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);

                // Return the last line since it should be the most recent.
                if (lines != null && lines.length > 0) {
                    bubbleMessage.message = lines[lines.length - 1];
                    return bubbleMessage;
                }
            } else if (Notification.MediaStyle.class.equals(style)) {
                // Return nothing, media updates aren't typically useful as a text update.
                return bubbleMessage;
            } else {
                // Default to text extra.
                bubbleMessage.message =
                        underlyingNotif.extras.getCharSequence(Notification.EXTRA_TEXT);
                return bubbleMessage;
            }
        } catch (ClassCastException | NullPointerException | ArrayIndexOutOfBoundsException e) {
            // No use crashing, we'll just return null and the caller will assume there's no update
            // message.
            e.printStackTrace();
        }

        return bubbleMessage;
    }
}
