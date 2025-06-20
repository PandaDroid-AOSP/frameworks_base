/*
 * Copyright (C) 2015 The Android Open Source Project
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

package android.os.test;

import static org.junit.Assert.assertTrue;

import android.os.Build;
import android.os.Handler;
import android.os.HandlerExecutor;
import android.os.Looper;
import android.os.Message;
import android.os.MessageQueue;
import android.os.SystemClock;
import android.os.TestLooperManager;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.Executor;

/**
 * Creates a looper whose message queue can be manipulated This allows testing code that uses a
 * looper to dispatch messages in a deterministic manner Creating a TestLooper will also install it
 * as the looper for the current thread
 *
 * @deprecated Use {@link android.os.TestLooperManager} or {@link
 *     org.robolectric.shadows.ShadowLooper} instead.
 *     This class is not actively maintained.
 *     Both of the recommended alternatives allow fine control of execution.
 *     The Robolectric class also allows advancing time.
 */
public class TestLooper {
    private final Looper mLooper;
    private final TestLooperManager mTestLooperManager;
    private final Clock mClock;

    private static final Constructor<Looper> LOOPER_CONSTRUCTOR;
    private static final Field THREAD_LOCAL_LOOPER_FIELD;
    private static final Field MESSAGE_QUEUE_MESSAGES_FIELD;
    private static final Field MESSAGE_NEXT_FIELD;
    private static final Field MESSAGE_WHEN_FIELD;
    private static final Method MESSAGE_MARK_IN_USE_METHOD;
    private static final String TAG = "TestLooper";

    private AutoDispatchThread mAutoDispatchThread;

    /**
     * Baklava introduces new {@link TestLooperManager} APIs that we can use instead of reflection.
     */
    private static boolean isAtLeastBaklava() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA;
    }

    static {
        try {
            LOOPER_CONSTRUCTOR = Looper.class.getDeclaredConstructor(Boolean.TYPE);
            LOOPER_CONSTRUCTOR.setAccessible(true);
            THREAD_LOCAL_LOOPER_FIELD = Looper.class.getDeclaredField("sThreadLocal");
            THREAD_LOCAL_LOOPER_FIELD.setAccessible(true);

            if (isAtLeastBaklava()) {
                MESSAGE_QUEUE_MESSAGES_FIELD = null;
                MESSAGE_NEXT_FIELD = null;
                MESSAGE_WHEN_FIELD = null;
                MESSAGE_MARK_IN_USE_METHOD = null;
            } else {
                MESSAGE_QUEUE_MESSAGES_FIELD = MessageQueue.class.getDeclaredField("mMessages");
                MESSAGE_QUEUE_MESSAGES_FIELD.setAccessible(true);
                MESSAGE_NEXT_FIELD = Message.class.getDeclaredField("next");
                MESSAGE_NEXT_FIELD.setAccessible(true);
                MESSAGE_WHEN_FIELD = Message.class.getDeclaredField("when");
                MESSAGE_WHEN_FIELD.setAccessible(true);
                MESSAGE_MARK_IN_USE_METHOD = Message.class.getDeclaredMethod("markInUse");
                MESSAGE_MARK_IN_USE_METHOD.setAccessible(true);
            }
        } catch (NoSuchFieldException | NoSuchMethodException e) {
            throw new RuntimeException("Failed to initialize TestLooper", e);
        }
    }

    /**
     * Creates a TestLooper and installs it as the looper for the current thread.
     */
    public TestLooper() {
        this(SystemClock::uptimeMillis);
    }

    /**
     * Creates a TestLooper with a custom clock and installs it as the looper for the current
     * thread.
     *
     * Messages are dispatched when their {@link Message#when} is before or at {@link
     * Clock#uptimeMillis()}.
     * Use a custom clock with care. When using an offsettable clock like {@link
     * com.android.server.testutils.OffsettableClock} be sure not to double offset messages by
     * offsetting the clock and calling {@link #moveTimeForward(long)}. Instead, offset the clock
     * and call {@link #dispatchAll()}.
     */
    public TestLooper(Clock clock) {
        try {
            mLooper = LOOPER_CONSTRUCTOR.newInstance(false);

            ThreadLocal<Looper> threadLocalLooper =
                    (ThreadLocal<Looper>) THREAD_LOCAL_LOOPER_FIELD.get(null);
            threadLocalLooper.set(mLooper);
        } catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new RuntimeException("Reflection error constructing or accessing looper", e);
        }

        if (isAtLeastBaklava()) {
            mTestLooperManager =
                InstrumentationRegistry.getInstrumentation().acquireLooperManager(mLooper);
        } else {
            mTestLooperManager = null;
        }

        mClock = clock;
    }

    public Looper getLooper() {
        return mLooper;
    }

    public Executor getNewExecutor() {
        return new HandlerExecutor(new Handler(getLooper()));
    }

    private Message getMessageLinkedListLegacy() {
        try {
            MessageQueue queue = mLooper.getQueue();
            return (Message) MESSAGE_QUEUE_MESSAGES_FIELD.get(queue);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Access failed in TestLooper: get - MessageQueue.mMessages",
                e);
        }
    }

    public void moveTimeForward(long milliSeconds) {
        if (isAtLeastBaklava()) {
            moveTimeForwardBaklava(milliSeconds);
        } else {
            moveTimeForwardLegacy(milliSeconds);
        }
    }

    private void moveTimeForwardBaklava(long milliSeconds) {
        // Drain all Messages from the queue.
        Queue<Message> messages = new ArrayDeque<>();
        while (true) {
            Message message = mTestLooperManager.poll();
            if (message == null) {
                break;
            }
            messages.add(message);
        }

        // Repost all Messages back to the queue with a new time.
        while (true) {
            Message message = messages.poll();
            if (message == null) {
                break;
            }

            // Ugly trick to reset the Message's "in use" flag.
            // This is needed because the Message cannot be re-enqueued if it's
            // marked in use.
            message.copyFrom(message);

            // Adjust the Message's delivery time.
            long newWhen = message.getWhen() - milliSeconds;
            if (newWhen < 0) {
                newWhen = 0;
            }

            // Send the Message back to its Handler to be re-enqueued.
            message.getTarget().sendMessageAtTime(message, newWhen);
        }
    }

    private void moveTimeForwardLegacy(long milliSeconds) {
        try {
            Message msg = getMessageLinkedListLegacy();
            while (msg != null) {
                long updatedWhen = msg.getWhen() - milliSeconds;
                if (updatedWhen < 0) {
                    updatedWhen = 0;
                }
                MESSAGE_WHEN_FIELD.set(msg, updatedWhen);
                msg = (Message) MESSAGE_NEXT_FIELD.get(msg);
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Access failed in TestLooper: set - Message.when", e);
        }
    }

    private long currentTime() {
        return mClock.uptimeMillis();
    }

    private Message messageQueueNextLegacy() {
        try {
            long now = currentTime();

            Message prevMsg = null;
            Message msg = getMessageLinkedListLegacy();
            if (msg != null && msg.getTarget() == null) {
                // Stalled by a barrier. Find the next asynchronous message in
                // the queue.
                do {
                    prevMsg = msg;
                    msg = (Message) MESSAGE_NEXT_FIELD.get(msg);
                } while (msg != null && !msg.isAsynchronous());
            }
            if (msg != null) {
                if (now >= msg.getWhen()) {
                    // Got a message.
                    if (prevMsg != null) {
                        MESSAGE_NEXT_FIELD.set(prevMsg, MESSAGE_NEXT_FIELD.get(msg));
                    } else {
                        MESSAGE_QUEUE_MESSAGES_FIELD.set(mLooper.getQueue(),
                                MESSAGE_NEXT_FIELD.get(msg));
                    }
                    MESSAGE_NEXT_FIELD.set(msg, null);
                    MESSAGE_MARK_IN_USE_METHOD.invoke(msg);
                    return msg;
                }
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("Access failed in TestLooper", e);
        }

        return null;
    }

    /**
     * @return true if there are pending messages in the message queue
     */
    public boolean isIdle() {
        if (isAtLeastBaklava()) {
            return isIdleBaklava();
        } else {
            return isIdleLegacy();
        }
    }

    private boolean isIdleBaklava() {
        Long when = mTestLooperManager.peekWhen();
        return when != null && currentTime() >= when;
    }

    private synchronized boolean isIdleLegacy() {
        Message messageList = getMessageLinkedListLegacy();
        return messageList != null && currentTime() >= messageList.getWhen();
    }

    /**
     * @return the next message in the Looper's message queue or null if there is none
     */
    public Message nextMessage() {
        if (isAtLeastBaklava()) {
            return nextMessageBaklava();
        } else {
            return nextMessageLegacy();
        }
    }

    private Message nextMessageBaklava() {
        if (isIdle()) {
            return mTestLooperManager.poll();
        } else {
            return null;
        }
    }

    private synchronized Message nextMessageLegacy() {
        if (isIdle()) {
            return messageQueueNextLegacy();
        } else {
            return null;
        }
    }

    /**
     * Dispatch the next message in the queue
     * Asserts that there is a message in the queue
     */
    public void dispatchNext() {
        if (isAtLeastBaklava()) {
            dispatchNextBaklava();
        } else {
            dispatchNextLegacy();
        }
    }

    private void dispatchNextBaklava() {
        assertTrue(isIdle());
        Message msg = mTestLooperManager.poll();
        if (msg == null) {
            return;
        }
        msg.getTarget().dispatchMessage(msg);
    }

    private synchronized void dispatchNextLegacy() {
        assertTrue(isIdle());
        Message msg = messageQueueNextLegacy();
        if (msg == null) {
            return;
        }
        msg.getTarget().dispatchMessage(msg);
    }

    /**
     * Dispatch all messages currently in the queue
     * Will not fail if there are no messages pending
     *
     * @return the number of messages dispatched
     */
    public synchronized int dispatchAll() {
        int count = 0;
        while (isIdle()) {
            dispatchNext();
            ++count;
        }
        return count;
    }

    public interface Clock {
        long uptimeMillis();
    }

    /**
     * Thread used to dispatch messages when the main thread is blocked waiting for a response.
     */
    private class AutoDispatchThread extends Thread {
        private static final int MAX_LOOPS = 100;
        private static final int LOOP_SLEEP_TIME_MS = 10;

        private RuntimeException mAutoDispatchException = null;

        /**
         * Run method for the auto dispatch thread.
         * The thread loops a maximum of MAX_LOOPS times with a 10ms sleep between loops.
         * The thread continues looping and attempting to dispatch all messages until
         * {@link #stopAutoDispatch()} has been invoked.
         */
        @Override
        public void run() {
            int dispatchCount = 0;
            for (int i = 0; i < MAX_LOOPS; i++) {
                try {
                    dispatchCount += dispatchAll();
                } catch (RuntimeException e) {
                    mAutoDispatchException = e;
                    return;
                }
                Log.d(TAG, "dispatched " + dispatchCount + " messages");
                try {
                    Thread.sleep(LOOP_SLEEP_TIME_MS);
                } catch (InterruptedException e) {
                    if (dispatchCount == 0) {
                        Log.e(TAG, "stopAutoDispatch called before any messages were dispatched.");
                        mAutoDispatchException = new IllegalStateException(
                                "stopAutoDispatch called before any messages were dispatched.");
                    }
                    return;
                }
            }
            if (dispatchCount == 0) {
                Log.e(TAG, "AutoDispatchThread did not dispatch any messages.");
                mAutoDispatchException = new IllegalStateException(
                        "TestLooper did not dispatch any messages before exiting.");
            }
        }

        /**
         * Method allowing the TestLooper to pass any exceptions thrown by the thread to be passed
         * to the main thread.
         *
         * @return RuntimeException Exception created by stopping without dispatching a message
         */
        public RuntimeException getException() {
            return mAutoDispatchException;
        }
    }

    /**
     * Create and start a new AutoDispatchThread if one is not already running.
     */
    public void startAutoDispatch() {
        if (mAutoDispatchThread != null) {
            throw new IllegalStateException(
                    "startAutoDispatch called with the AutoDispatchThread already running.");
        }
        mAutoDispatchThread = new AutoDispatchThread();
        mAutoDispatchThread.start();
    }

    /**
     * If an AutoDispatchThread is currently running, stop and clean up.
     */
    public void stopAutoDispatch() {
        if (mAutoDispatchThread != null) {
            if (mAutoDispatchThread.isAlive()) {
                mAutoDispatchThread.interrupt();
            }
            try {
                mAutoDispatchThread.join();
            } catch (InterruptedException e) {
                // Catch exception from join.
            }

            RuntimeException e = mAutoDispatchThread.getException();
            mAutoDispatchThread = null;
            if (e != null) {
                throw e;
            }
        } else {
            // stopAutoDispatch was called when startAutoDispatch has not created a new thread.
            throw new IllegalStateException(
                    "stopAutoDispatch called without startAutoDispatch.");
        }
    }

    /**
     * If an AutoDispatchThread is currently running, stop and clean up.
     * This method ignores exceptions raised for indicating that no messages were dispatched.
     */
    public void stopAutoDispatchAndIgnoreExceptions() {
        try {
            stopAutoDispatch();
        } catch (IllegalStateException e) {
            Log.e(TAG, "stopAutoDispatch", e);
        }

    }
}
