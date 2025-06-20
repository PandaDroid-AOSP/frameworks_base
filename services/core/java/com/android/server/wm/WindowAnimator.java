/*
 * Copyright (C) 2014 The Android Open Source Project
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

package com.android.server.wm;

import static com.android.internal.protolog.WmProtoLogGroups.WM_SHOW_TRANSACTIONS;
import static com.android.server.wm.SurfaceAnimator.ANIMATION_TYPE_ALL;
import static com.android.server.wm.WindowContainer.AnimationFlags.CHILDREN;
import static com.android.server.wm.WindowManagerDebugConfig.DEBUG_WINDOW_TRACE;
import static com.android.server.wm.WindowManagerDebugConfig.TAG_WITH_CLASS_NAME;
import static com.android.server.wm.WindowManagerDebugConfig.TAG_WM;

import android.annotation.IntDef;
import android.content.Context;
import android.os.HandlerExecutor;
import android.os.Trace;
import android.util.Slog;
import android.util.TimeUtils;
import android.view.Choreographer;
import android.view.SurfaceControl;

import com.android.internal.protolog.ProtoLog;
import com.android.server.policy.WindowManagerPolicy;

import java.io.PrintWriter;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;

/**
 * Singleton class that carries out the animations and Surface operations in a separate task
 * on behalf of WindowManagerService.
 */
public class WindowAnimator {
    private static final String TAG = TAG_WITH_CLASS_NAME ? "WindowAnimator" : TAG_WM;

    final WindowManagerService mService;
    final Context mContext;
    final WindowManagerPolicy mPolicy;

    /** Is any window animating? */
    private boolean mLastRootAnimating;

    final Choreographer.FrameCallback mAnimationFrameCallback;

    /** Time of current animation step. Reset on each iteration */
    long mCurrentTime;

    private boolean mInitialized = false;

    private Choreographer mChoreographer;

    private final HandlerExecutor mExecutor;

    /**
     * Indicates whether we have an animation frame callback scheduled, which will happen at
     * vsync-app and then schedule the animation tick at the right time (vsync-sf).
     */
    private boolean mAnimationFrameCallbackScheduled;
    boolean mNotifyWhenNoAnimation = false;

    /**
     * A list of runnable that need to be run after {@link WindowContainer#prepareSurfaces} is
     * executed and the corresponding transaction is closed and applied.
     */
    private ArrayList<Runnable> mAfterPrepareSurfacesRunnables = new ArrayList<>();

    private final SurfaceControl.Transaction mTransaction;

    /** The pending transaction is applied. */
    static final int PENDING_STATE_NONE = 0;
    /** There are some (significant) operations set to the pending transaction. */
    static final int PENDING_STATE_HAS_CHANGES = 1;
    /** The pending transaction needs to be applied before sending sync transaction to shell. */
    static final int PENDING_STATE_NEED_APPLY = 2;

    @IntDef(prefix = { "PENDING_STATE_" }, value = {
            PENDING_STATE_NONE,
            PENDING_STATE_HAS_CHANGES,
            PENDING_STATE_NEED_APPLY,
    })
    @Retention(RetentionPolicy.SOURCE)
    @interface PendingState {}

    /** The global state of pending transaction. */
    @PendingState
    int mPendingState;

    WindowAnimator(final WindowManagerService service) {
        mService = service;
        mContext = service.mContext;
        mPolicy = service.mPolicy;
        mTransaction = service.mTransactionFactory.get();
        service.mAnimationHandler.runWithScissors(
                () -> mChoreographer = Choreographer.getSfInstance(), 0 /* timeout */);
        mExecutor = new HandlerExecutor(service.mAnimationHandler);

        mAnimationFrameCallback = frameTimeNs -> {
            synchronized (mService.mGlobalLock) {
                mAnimationFrameCallbackScheduled = false;
                animate(frameTimeNs);
                if (mNotifyWhenNoAnimation && !mLastRootAnimating) {
                    mService.mGlobalLock.notifyAll();
                }
            }
        };
    }

    void ready() {
        mInitialized = true;
    }

    private void animate(long frameTimeNs) {
        if (!mInitialized) {
            return;
        }

        // Schedule next frame already such that back-pressure happens continuously.
        scheduleAnimation();

        final RootWindowContainer root = mService.mRoot;
        boolean rootAnimating = false;
        mCurrentTime = frameTimeNs / TimeUtils.NANOS_PER_MS;
        if (DEBUG_WINDOW_TRACE) {
            Slog.i(TAG, "!!! animate: entry time=" + mCurrentTime);
        }

        ProtoLog.i(WM_SHOW_TRANSACTIONS, ">>> OPEN TRANSACTION animate");
        try {
            // Remove all deferred displays, tasks, and activities.
            root.handleCompleteDeferredRemoval();

            final AccessibilityController accessibilityController =
                    mService.mAccessibilityController;
            final int numDisplays = root.getChildCount();
            for (int i = 0; i < numDisplays; i++) {
                final DisplayContent dc = root.getChildAt(i);
                // Update animations of all applications, including those associated with
                // exiting/removed apps.
                dc.updateWindowsForAnimator();
                dc.prepareSurfaces();
            }

            for (int i = 0; i < numDisplays; i++) {
                final DisplayContent dc = root.getChildAt(i);
                if (accessibilityController.hasCallbacks()) {
                    accessibilityController
                            .recomputeMagnifiedRegionAndDrawMagnifiedRegionBorderIfNeeded(
                                    dc.mDisplayId);
                }

                if (dc.isAnimating(CHILDREN, ANIMATION_TYPE_ALL)) {
                    rootAnimating = true;
                    if (!dc.mLastContainsRunningSurfaceAnimator) {
                        dc.mLastContainsRunningSurfaceAnimator = true;
                        dc.enableHighFrameRate(true);
                    }
                } else if (dc.mLastContainsRunningSurfaceAnimator) {
                    dc.mLastContainsRunningSurfaceAnimator = false;
                    dc.enableHighFrameRate(false);
                }
                mTransaction.merge(dc.getPendingTransaction());
            }

            cancelAnimation();

            if (mService.mWatermark != null) {
                mService.mWatermark.drawIfNeeded();
            }

        } catch (RuntimeException e) {
            Slog.wtf(TAG, "Unhandled exception in Window Manager", e);
        }

        final boolean hasPendingLayoutChanges = root.hasPendingLayoutChanges(this);
        if (hasPendingLayoutChanges) {
            mService.mWindowPlacerLocked.requestTraversal();
        }

        if (rootAnimating && !mLastRootAnimating) {
            Trace.asyncTraceBegin(Trace.TRACE_TAG_WINDOW_MANAGER, "animating", 0);
        }
        if (!rootAnimating && mLastRootAnimating) {
            mService.mWindowPlacerLocked.requestTraversal();
            Trace.asyncTraceEnd(Trace.TRACE_TAG_WINDOW_MANAGER, "animating", 0);
        }
        mLastRootAnimating = rootAnimating;

        final ArrayList<Runnable> afterPrepareSurfacesRunnables = mAfterPrepareSurfacesRunnables;
        if (!afterPrepareSurfacesRunnables.isEmpty()) {
            mAfterPrepareSurfacesRunnables = new ArrayList<>();
            mTransaction.addTransactionCommittedListener(mExecutor, () -> {
                synchronized (mService.mGlobalLock) {
                    // Traverse in order they were added.
                    for (int i = 0, size = afterPrepareSurfacesRunnables.size(); i < size; i++) {
                        afterPrepareSurfacesRunnables.get(i).run();
                    }
                    afterPrepareSurfacesRunnables.clear();
                }
            });
        }
        Trace.traceBegin(Trace.TRACE_TAG_WINDOW_MANAGER, "applyTransaction");
        mTransaction.apply();
        Trace.traceEnd(Trace.TRACE_TAG_WINDOW_MANAGER);
        mPendingState = PENDING_STATE_NONE;
        mService.mWindowTracing.logState("WindowAnimator");
        ProtoLog.i(WM_SHOW_TRANSACTIONS, "<<< CLOSE TRANSACTION animate");

        mService.mAtmService.mTaskOrganizerController.dispatchPendingEvents();

        if (DEBUG_WINDOW_TRACE) {
            Slog.i(TAG, "!!! animate: exit"
                    + " hasPendingLayoutChanges=" + hasPendingLayoutChanges);
        }
    }

    public void dumpLocked(PrintWriter pw, String prefix, boolean dumpAll) {
        final String subPrefix = "  " + prefix;

        for (int i = 0; i < mService.mRoot.getChildCount(); i++) {
            final DisplayContent dc = mService.mRoot.getChildAt(i);
            pw.print(prefix); pw.print(dc); pw.println(":");
            dc.dumpWindowAnimators(pw, subPrefix);
            pw.println();
        }

        pw.println();

        if (dumpAll) {
            pw.print(prefix); pw.print("mCurrentTime=");
                    pw.println(TimeUtils.formatUptime(mCurrentTime));
        }
    }

    void scheduleAnimation() {
        if (!mAnimationFrameCallbackScheduled) {
            mAnimationFrameCallbackScheduled = true;
            mChoreographer.postFrameCallback(mAnimationFrameCallback);
        }
    }

    private void cancelAnimation() {
        if (mAnimationFrameCallbackScheduled) {
            mAnimationFrameCallbackScheduled = false;
            mChoreographer.removeFrameCallback(mAnimationFrameCallback);
        }
    }

    boolean isAnimationScheduled() {
        return mAnimationFrameCallbackScheduled;
    }

    void applyPendingTransaction() {
        Trace.traceBegin(Trace.TRACE_TAG_WINDOW_MANAGER, "applyPendingTransaction");
        mPendingState = PENDING_STATE_NONE;
        final int numDisplays = mService.mRoot.getChildCount();
        if (numDisplays == 1) {
            mService.mRoot.getChildAt(0).getPendingTransaction().apply();
        } else {
            for (int i = 0; i < numDisplays; i++) {
                mTransaction.merge(mService.mRoot.getChildAt(i).getPendingTransaction());
            }
            mTransaction.apply();
        }
        Trace.traceEnd(Trace.TRACE_TAG_WINDOW_MANAGER);
    }

    /**
     * Adds a runnable to be executed after {@link WindowContainer#prepareSurfaces} is called and
     * the corresponding transaction is closed, applied, and committed.
     */
    void addAfterPrepareSurfacesRunnable(Runnable r) {
        mAfterPrepareSurfacesRunnables.add(r);
        scheduleAnimation();
    }
}
