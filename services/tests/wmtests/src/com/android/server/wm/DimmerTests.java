/*
 * Copyright (C) 2017 The Android Open Source Project
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

import static com.android.dx.mockito.inline.extended.ExtendedMockito.mock;
import static com.android.dx.mockito.inline.extended.ExtendedMockito.never;
import static com.android.dx.mockito.inline.extended.ExtendedMockito.spy;
import static com.android.dx.mockito.inline.extended.ExtendedMockito.times;
import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
import static com.android.server.wm.utils.LastCallVerifier.lastCall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import android.graphics.Rect;
import android.platform.test.annotations.Presubmit;
import android.platform.test.annotations.RequiresFlagsDisabled;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.view.SurfaceControl;
import android.view.SurfaceSession;

import com.android.server.testutils.StubTransaction;
import com.android.server.wm.utils.MockAnimationAdapter;
import com.android.window.flags.Flags;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Build/Install/Run:
 *  atest WmTests:DimmerTests
 */
@Presubmit
@RunWith(WindowTestRunner.class)
public class DimmerTests extends WindowTestsBase {

    private static class MockSurfaceBuildingContainer extends WindowContainer<WindowState> {
        final SurfaceSession mSession = new SurfaceSession();
        final SurfaceControl mHostControl = mock(SurfaceControl.class);
        final SurfaceControl.Transaction mHostTransaction = spy(StubTransaction.class);
        Rect mBounds = new Rect(10, 20, 30, 40);

        MockSurfaceBuildingContainer(WindowManagerService wm) {
            super(wm);
            mVisibleRequested = true;
        }

        class MockSurfaceBuilder extends SurfaceControl.Builder {
            MockSurfaceBuilder(SurfaceSession ss) {
                super(ss);
            }

            @Override
            public SurfaceControl build() {
                SurfaceControl mSc = mock(SurfaceControl.class);
                when(mSc.isValid()).thenReturn(true);
                return mSc;
            }
        }

        @Override
        SurfaceControl.Builder makeChildSurface(WindowContainer child) {
            return new MockSurfaceBuilder(mSession);
        }

        @Override
        public SurfaceControl getSurfaceControl() {
            return mHostControl;
        }

        @Override
        public SurfaceControl.Transaction getSyncTransaction() {
            return mHostTransaction;
        }

        @Override
        public SurfaceControl.Transaction getPendingTransaction() {
            return mHostTransaction;
        }

        @Override
        public Rect getBounds() {
            return mBounds;
        }
    }

    static class MockAnimationAdapterFactory extends DimmerAnimationHelper.AnimationAdapterFactory {
        @Override
        public AnimationAdapter get(LocalAnimationAdapter.AnimationSpec alphaAnimationSpec,
                SurfaceAnimationRunner runner) {
            return sTestAnimation;
        }
    }

    static class TestActivityEmbeddingMock {
        Task mTask = mock(Task.class);
        TaskFragment mLeft = mock(TaskFragment.class);
        TaskFragment mRight = mock(TaskFragment.class);
        Rect mTaskBounds = new Rect(10, 0, 50, 40);
        Rect mLeftBounds = new Rect(10, 0, 30, 40);
        Rect mRightBounds = new Rect(30, 0, 50, 40);

        TestActivityEmbeddingMock() {
            when(mTask.getBounds()).thenReturn(mTaskBounds);
            when(mLeft.getBounds()).thenReturn(mLeftBounds);
            when(mRight.getBounds()).thenReturn(mRightBounds);
            when(mLeft.isEmbedded()).thenReturn(true);
            when(mRight.isEmbedded()).thenReturn(true);
        }

        void pretendParentToTask(WindowState child) {
            when(child.getTaskFragment()).thenReturn(mTask);
            when(child.getTask()).thenReturn(mTask);
        }

        void pretendParentToRight(WindowState child) {
            when(child.getTaskFragment()).thenReturn(mRight);
            when(child.getTask()).thenReturn(mTask);
        }
    }

    WindowState getMockDimmingContainer() {
        WindowState window = mock(WindowState.class);
        SurfaceControl surface = mock(SurfaceControl.class);
        when(window.getSurfaceControl()).thenReturn(surface);
        return window;
    }

    private Dimmer mDimmer;
    private SurfaceControl.Transaction mTransaction;
    MockSurfaceBuildingContainer mHost;
    private WindowState mChild1;
    private WindowState mChild2;
    private static AnimationAdapter sTestAnimation;

    @Before
    public void setUp() throws Exception {
        mHost = new MockSurfaceBuildingContainer(mWm);
        mTransaction = mHost.getSyncTransaction();

        SurfaceAnimator animator = mock(SurfaceAnimator.class);
        when(animator.getAnimation()).thenReturn(null);

        mChild1 = getMockDimmingContainer();
        mChild2 = getMockDimmingContainer();

        mHost.addChild(mChild1, 0);
        mHost.addChild(mChild2, 1);

        sTestAnimation = spy(new MockAnimationAdapter());
        mDimmer = new Dimmer(mHost, new MockAnimationAdapterFactory());
    }

    @Test
    @RequiresFlagsDisabled(Flags.FLAG_USE_TASKS_DIM_ONLY)
    public void testUpdateDimsAppliesCrop() {
        mDimmer.adjustAppearance(mChild1, 1, 1);
        mDimmer.adjustPosition(mChild1, mChild1);

        int width = 100;
        int height = 300;
        mDimmer.getDimBounds().set(0, 0, width, height);
        mDimmer.updateDims(mTransaction);

        verify(mTransaction).setWindowCrop(mDimmer.getDimLayer(), width, height);
        verify(mTransaction).show(mDimmer.getDimLayer());
    }

    @Test
    @RequiresFlagsEnabled(Flags.FLAG_USE_TASKS_DIM_ONLY)
    public void testBoundsInActivityEmbeddingForWholeTask() {
        final WindowState dimmingWindow = getMockDimmingContainer();
        TestActivityEmbeddingMock embedding = new TestActivityEmbeddingMock();
        embedding.pretendParentToRight(dimmingWindow);
        when(embedding.mRight.isDimmingOnParentTask()).thenReturn(true);

        mDimmer.adjustAppearance(dimmingWindow, 1, 1);
        mDimmer.adjustPosition(dimmingWindow, dimmingWindow);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).setWindowCrop(mDimmer.getDimLayer(),
                embedding.mTaskBounds.width(), embedding.mTaskBounds.height());
        verify(mTransaction).setPosition(mDimmer.getDimLayer(), 0, 0);
    }

    @Test
    @RequiresFlagsEnabled(Flags.FLAG_USE_TASKS_DIM_ONLY)
    public void testBoundsInActivityEmbeddingForTaskFragmentOnly() {
        final WindowState dimmingWindow = getMockDimmingContainer();
        TestActivityEmbeddingMock embedding = new TestActivityEmbeddingMock();
        embedding.pretendParentToRight(dimmingWindow);
        when(embedding.mRight.isDimmingOnParentTask()).thenReturn(false);

        mDimmer.adjustAppearance(dimmingWindow, 1, 1);
        mDimmer.adjustPosition(dimmingWindow, dimmingWindow);
        mDimmer.updateDims(mTransaction);
        Rect expectedAbsoluteBounds = embedding.mRightBounds;
        Rect expectedRelativeBounds = new Rect(expectedAbsoluteBounds);
        expectedRelativeBounds.offset(-embedding.mTaskBounds.left, -embedding.mTaskBounds.top);
        verify(mTransaction).setWindowCrop(mDimmer.getDimLayer(),
                embedding.mRightBounds.width(), embedding.mRightBounds.height());
        verify(mTransaction).setPosition(mDimmer.getDimLayer(),
                expectedRelativeBounds.left, expectedRelativeBounds.top);
        assertEquals(expectedAbsoluteBounds, mDimmer.getDimBounds());
    }

    @Test
    @RequiresFlagsEnabled(Flags.FLAG_USE_TASKS_DIM_ONLY)
    public void testDimBoundsAdaptToResizing() {
        // First call with some generic bounds
        mDimmer.adjustAppearance(mChild1, 0.5f, 1);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).setWindowCrop(mDimmer.getDimLayer(),
                mHost.getBounds().width(), mHost.getBounds().height());

        // Change bounds
        mHost.getBounds().left += 5;
        mHost.getBounds().top += 6;
        mDimmer.adjustAppearance(mChild1, 1, 1);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).setWindowCrop(mDimmer.getDimLayer(),
                mHost.getBounds().width(), mHost.getBounds().height());
    }

    @Test
    public void testDimBelowWithChildSurfaceCreatesSurfaceBelowChild() {
        final float alpha = 0.7f;
        final int blur = 50;
        mDimmer.adjustAppearance(mChild1, alpha, blur);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();

        assertNotNull("Dimmer should have created a surface", dimLayer);

        mDimmer.updateDims(mTransaction);
        verify(sTestAnimation).startAnimation(eq(dimLayer), eq(mTransaction),
                anyInt(), any(SurfaceAnimator.OnAnimationFinishedCallback.class));
        verify(mTransaction).setRelativeLayer(dimLayer, mChild1.getSurfaceControl(), -1);
        verify(mTransaction, lastCall()).setAlpha(dimLayer, alpha);
        verify(mTransaction).setBackgroundBlurRadius(dimLayer, blur);
    }

    @Test
    public void testDimBelowWithChildSurfaceDestroyedWhenReset() {
        final float alpha = 0.8f;
        final int blur = 50;
        // Dim once
        mDimmer.adjustAppearance(mChild1, alpha, blur);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);
        // Reset, and don't dim
        mDimmer.resetDimStates();
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).show(dimLayer);
        verify(mTransaction).remove(dimLayer);
    }

    @Test
    public void testDimBelowWithChildSurfaceNotDestroyedWhenPersisted() {
        final float alpha = 0.8f;
        final int blur = 20;
        // Dim once
        mDimmer.adjustAppearance(mChild1, alpha, blur);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);
        // Reset and dim again
        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, alpha, blur);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).show(dimLayer);
        verify(mTransaction, never()).remove(dimLayer);
    }

    @Test
    @RequiresFlagsDisabled(Flags.FLAG_USE_TASKS_DIM_ONLY)
    public void testDimUpdateWhileDimming() {
        final float alpha = 0.8f;
        mDimmer.adjustAppearance(mChild1, alpha, 20);
        mDimmer.adjustPosition(mChild1, mChild1);
        final Rect bounds = mDimmer.getDimBounds();

        SurfaceControl dimLayer = mDimmer.getDimLayer();
        bounds.set(0, 0, 10, 10);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).setWindowCrop(dimLayer, bounds.width(), bounds.height());
        verify(mTransaction, times(1)).show(dimLayer);
        verify(mTransaction).setPosition(dimLayer, 0, 0);

        bounds.set(10, 10, 30, 30);
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).setWindowCrop(dimLayer, bounds.width(), bounds.height());
        verify(mTransaction).setPosition(dimLayer, 10, 10);
    }

    @Test
    public void testRemoveDimImmediately() {
        mDimmer.adjustAppearance(mChild1, 1, 2);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);
        verify(mTransaction, times(1)).show(dimLayer);

        reset(sTestAnimation);
        mDimmer.dontAnimateExit();
        mDimmer.resetDimStates();
        mDimmer.updateDims(mTransaction);
        verify(sTestAnimation, never()).startAnimation(
                any(SurfaceControl.class), any(SurfaceControl.Transaction.class),
                anyInt(), any(SurfaceAnimator.OnAnimationFinishedCallback.class));
        verify(mTransaction).remove(dimLayer);
    }

    /**
     * mChild is requesting the dim values to be set directly. In this case, dim won't play the
     * standard animation, but directly apply mChild's requests to the dim surface
     */
    @Test
    public void testContainerDimsOpeningAnimationByItself() {
        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0.1f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0.2f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0.3f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);

        verify(mTransaction).setAlpha(dimLayer, 0.2f);
        verify(mTransaction).setAlpha(dimLayer, 0.3f);
        verify(sTestAnimation, times(1)).startAnimation(
                any(SurfaceControl.class), any(SurfaceControl.Transaction.class),
                anyInt(), any(SurfaceAnimator.OnAnimationFinishedCallback.class));
    }

    /**
     * Same as testContainerDimsOpeningAnimationByItself, but this is a more specific case in which
     * alpha is animated to 0. This corner case is needed to verify that the layer is removed anyway
     */
    @Test
    public void testContainerDimsClosingAnimationByItself() {
        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0.2f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0.1f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild1, 0f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.updateDims(mTransaction);
        verify(mTransaction).remove(dimLayer);
    }

    /**
     * Check the handover of the dim between two windows and the consequent dim animation in between
     */
    @Test
    public void testMultipleContainersDimmingConsecutively() {
        mDimmer.adjustAppearance(mChild1, 0.5f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.updateDims(mTransaction);

        mDimmer.resetDimStates();
        mDimmer.adjustAppearance(mChild2, 0.9f, 0);
        mDimmer.adjustPosition(mChild1, mChild2);
        mDimmer.updateDims(mTransaction);

        verify(sTestAnimation, times(2)).startAnimation(
                any(SurfaceControl.class), any(SurfaceControl.Transaction.class),
                anyInt(), any(SurfaceAnimator.OnAnimationFinishedCallback.class));
        verify(mTransaction).setAlpha(dimLayer, 0.5f);
        verify(mTransaction).setAlpha(dimLayer, 0.9f);
    }

    /**
     * Two windows are trying to modify the dim at the same time, but only the last request before
     * updateDims will be satisfied
     */
    @Test
    public void testMultipleContainersDimmingAtTheSameTime() {
        mDimmer.adjustAppearance(mChild1, 0.5f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        SurfaceControl dimLayer = mDimmer.getDimLayer();
        mDimmer.adjustAppearance(mChild2, 0.9f, 0);
        mDimmer.adjustPosition(mChild1, mChild2);
        mDimmer.updateDims(mTransaction);

        verify(sTestAnimation, times(1)).startAnimation(
                any(SurfaceControl.class), any(SurfaceControl.Transaction.class),
                anyInt(), any(SurfaceAnimator.OnAnimationFinishedCallback.class));
        verify(mTransaction, never()).setAlpha(dimLayer, 0.5f);
        verify(mTransaction).setAlpha(dimLayer, 0.9f);
    }

    /**
     * A window requesting to dim to 0 and without blur would cause the dim to be created and
     * destroyed continuously.
     * Ensure the dim layer is not created until the window is requesting valid values.
     */
    @Test
    public void testDimNotCreatedIfNoAlphaNoBlur() {
        mDimmer.adjustAppearance(mChild1, 0.0f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        assertNull(mDimmer.getDimLayer());
        mDimmer.updateDims(mTransaction);
        assertNull(mDimmer.getDimLayer());

        mDimmer.adjustAppearance(mChild1, 0.9f, 0);
        mDimmer.adjustPosition(mChild1, mChild1);
        assertNotNull(mDimmer.getDimLayer());
    }

    /**
     * If there is a blur, then the dim layer is created even though alpha is 0
     */
    @Test
    public void testDimCreatedIfNoAlphaButHasBlur() {
        mDimmer.adjustAppearance(mChild1, 0.0f, 10);
        mDimmer.adjustPosition(mChild1, mChild1);
        assertNotNull(mDimmer.getDimLayer());
    }
}
