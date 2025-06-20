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
 * limitations under the License
 */

package com.android.systemui.statusbar.notification.stack;

import static com.android.systemui.Flags.physicalNotificationMovement;
import static com.android.systemui.statusbar.notification.row.ExpandableView.HEIGHT_PROPERTY;
import static com.android.systemui.statusbar.notification.row.ExpandableView.TAG_ANIMATOR_HEIGHT;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.PropertyValuesHolder;
import android.animation.ValueAnimator;
import android.util.FloatProperty;
import android.view.View;

import androidx.annotation.NonNull;

import com.android.app.animation.Interpolators;
import com.android.internal.dynamicanimation.animation.DynamicAnimation;
import com.android.systemui.res.R;
import com.android.systemui.statusbar.notification.PhysicsProperty;
import com.android.systemui.statusbar.notification.PhysicsPropertyAnimator;
import com.android.systemui.statusbar.notification.row.ExpandableNotificationRow;
import com.android.systemui.statusbar.notification.row.ExpandableView;

/**
 * A state of an expandable view
 */
public class ExpandableViewState extends ViewState {

    private static final int TAG_ANIMATOR_TOP_INSET = R.id.top_inset_animator_tag;
    private static final int TAG_ANIMATOR_BOTTOM_INSET = R.id.bottom_inset_animator_tag;
    private static final int TAG_END_HEIGHT = R.id.height_animator_end_value_tag;
    private static final int TAG_END_TOP_INSET = R.id.top_inset_animator_end_value_tag;
    private static final int TAG_END_BOTTOM_INSET = R.id.bottom_inset_animator_end_value_tag;
    private static final int TAG_START_HEIGHT = R.id.height_animator_start_value_tag;
    private static final int TAG_START_TOP_INSET = R.id.top_inset_animator_start_value_tag;
    private static final int TAG_START_BOTTOM_INSET = R.id.bottom_inset_animator_start_value_tag;

    // These are flags such that we can create masks for filtering.

    /**
     * No known location. This is the default and should not be set after an invocation of the
     * algorithm.
     */
    public static final int LOCATION_UNKNOWN = 0x00;

    /**
     * The location is the first heads up notification, so on the very top.
     */
    public static final int LOCATION_FIRST_HUN = 0x01;

    /**
     * The location is hidden / scrolled away on the top.
     */
    public static final int LOCATION_HIDDEN_TOP = 0x02;

    /**
     * The location is in the main area of the screen and visible.
     */
    public static final int LOCATION_MAIN_AREA = 0x04;

    /**
     * The location is in the bottom stack and it's peeking
     */
    public static final int LOCATION_BOTTOM_STACK_PEEKING = 0x08;

    /**
     * The location is in the bottom stack and it's hidden.
     */
    public static final int LOCATION_BOTTOM_STACK_HIDDEN = 0x10;

    /**
     * The view isn't laid out at all.
     */
    public static final int LOCATION_GONE = 0x40;

    /**
     * The visible locations of a view.
     */
    public static final int VISIBLE_LOCATIONS = ExpandableViewState.LOCATION_FIRST_HUN
            | ExpandableViewState.LOCATION_MAIN_AREA;

    public int height;
    public boolean hideSensitive;
    public boolean belowSpeedBump;
    public boolean inShelf;

    /**
     * A state indicating whether a headsup is currently fully visible, even when not scrolled.
     * Only valid if the view is heads upped.
     */
    public boolean headsUpIsVisible;

    /**
     * How much the child overlaps on top with the child above.
     */
    public int clipTopAmount;

    /**
     * How much the child overlaps on bottom with the child above. This is used to
     * show the background properly when the child on top is translating away.
     */
    public int clipBottomAmount;

    /**
     * The index of the view, only accounting for views not equal to GONE
     */
    public int notGoneIndex;

    /**
     * The location this view is currently rendered at.
     *
     * <p>See <code>LOCATION_</code> flags.</p>
     */
    public int location;

    @Override
    public void copyFrom(ViewState viewState) {
        super.copyFrom(viewState);
        if (viewState instanceof ExpandableViewState) {
            ExpandableViewState svs = (ExpandableViewState) viewState;
            height = svs.height;
            hideSensitive = svs.hideSensitive;
            belowSpeedBump = svs.belowSpeedBump;
            clipTopAmount = svs.clipTopAmount;
            notGoneIndex = svs.notGoneIndex;
            location = svs.location;
            headsUpIsVisible = svs.headsUpIsVisible;
        }
    }

    /**
     * Applies a {@link ExpandableViewState} to a {@link ExpandableView}.
     */
    @Override
    public void applyToView(View view) {
        super.applyToView(view);
        if (view instanceof ExpandableView) {
            ExpandableView expandableView = (ExpandableView) view;

            final int height = expandableView.getActualHeight();
            final int newHeight = this.height;

            // apply height
            if (height != newHeight) {
                expandableView.setFinalActualHeight(newHeight);
            }

            // apply hiding sensitive
            expandableView.setHideSensitive(
                    this.hideSensitive, false /* animated */, 0 /* delay */, 0 /* duration */);

            // apply clipping
            final float oldClipTopAmount = expandableView.getClipTopAmount();
            if (oldClipTopAmount != this.clipTopAmount) {
                expandableView.setClipTopAmount(this.clipTopAmount);
            }
            final float oldClipBottomAmount = expandableView.getClipBottomAmount();
            if (oldClipBottomAmount != this.clipBottomAmount) {
                expandableView.setClipBottomAmount(this.clipBottomAmount);
            }

            expandableView.setTransformingInShelf(false);
            expandableView.setInShelf(inShelf);

            if (headsUpIsVisible) {
                expandableView.markHeadsUpSeen();
            }
        }
    }

    @Override
    public void animateTo(View child, AnimationProperties properties) {
        super.animateTo(child, properties);
        if (!(child instanceof ExpandableView)) {
            return;
        }
        ExpandableView expandableView = (ExpandableView) child;
        AnimationFilter animationFilter = properties.getAnimationFilter();

        // start height animation
        if (this.height != expandableView.getActualHeight()) {
            if (mUsePhysicsForMovement) {
                boolean animateHeight = properties.getAnimationFilter().animateHeight;
                if (animateHeight) {
                    expandableView.setActualHeightAnimating(true);
                }
                DynamicAnimation.OnAnimationEndListener endListener = null;
                if (!ViewState.isAnimating(expandableView, HEIGHT_PROPERTY)) {
                    // only Add the end listener if we haven't already
                    endListener = (animation, canceled, value, velocity) -> {
                        expandableView.setActualHeightAnimating(false);
                        if (!canceled && child instanceof ExpandableNotificationRow row) {
                            row.setGroupExpansionChanging(false /* isExpansionChanging */);
                        }
                    };
                }
                PhysicsPropertyAnimator.setProperty(child, HEIGHT_PROPERTY, this.height, properties,
                        animateHeight,
                        endListener);
            } else {
                startHeightAnimationInterpolator(expandableView, properties);
            }
        } else {
            abortAnimation(child, TAG_ANIMATOR_HEIGHT);
        }

        // start clip top animation
        if (this.clipTopAmount != expandableView.getClipTopAmount()) {
            startClipAnimation(expandableView, properties, /* clipTop */true);
        } else {
            abortAnimation(child, TAG_ANIMATOR_TOP_INSET);
        }

        // start clip bottom animation
        if (this.clipBottomAmount != expandableView.getClipBottomAmount()) {
            startClipAnimation(expandableView, properties, /* clipTop */ false);
        } else {
            abortAnimation(child, TAG_ANIMATOR_BOTTOM_INSET);
        }

        // start hiding sensitive animation
        expandableView.setHideSensitive(this.hideSensitive, animationFilter.animateHideSensitive,
                properties.delay, properties.duration);

        if (properties.wasAdded(child) && !hidden) {
            expandableView.performAddAnimation(properties.delay, properties.duration,
                    false /* isHeadsUpAppear */);
        }

        if (!expandableView.isInShelf() && this.inShelf) {
            expandableView.setTransformingInShelf(true);
        }
        expandableView.setInShelf(this.inShelf);

        if (headsUpIsVisible) {
            expandableView.markHeadsUpSeen();
        }
    }

    private void startHeightAnimationInterpolator(final ExpandableView child,
            AnimationProperties properties) {
        Integer previousStartValue = getChildTag(child, TAG_START_HEIGHT);
        Integer previousEndValue = getChildTag(child, TAG_END_HEIGHT);
        int newEndValue = this.height;
        if (previousEndValue != null && previousEndValue == newEndValue) {
            return;
        }
        ValueAnimator previousAnimator = getChildTag(child, TAG_ANIMATOR_HEIGHT);
        AnimationFilter filter = properties.getAnimationFilter();
        if (!filter.animateHeight) {
            // just a local update was performed
            if (previousAnimator != null) {
                // we need to increase all animation keyframes of the previous animator by the
                // relative change to the end value
                PropertyValuesHolder[] values = previousAnimator.getValues();
                int relativeDiff = newEndValue - previousEndValue;
                int newStartValue = previousStartValue + relativeDiff;
                values[0].setIntValues(newStartValue, newEndValue);
                child.setTag(TAG_START_HEIGHT, newStartValue);
                child.setTag(TAG_END_HEIGHT, newEndValue);
                previousAnimator.setCurrentPlayTime(previousAnimator.getCurrentPlayTime());
                return;
            } else {
                // no new animation needed, let's just apply the value
                child.setActualHeight(newEndValue, false);
                return;
            }
        }

        ValueAnimator animator = ValueAnimator.ofInt(child.getActualHeight(), newEndValue);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animation) {
                child.setActualHeight((int) animation.getAnimatedValue(),
                        false /* notifyListeners */);
            }
        });
        animator.setInterpolator(Interpolators.FAST_OUT_SLOW_IN);
        long newDuration = cancelAnimatorAndGetNewDuration(properties.duration, previousAnimator);
        animator.setDuration(newDuration);
        if (properties.delay > 0 && (previousAnimator == null
                || previousAnimator.getAnimatedFraction() == 0)) {
            animator.setStartDelay(properties.delay);
        }
        AnimatorListenerAdapter listener = properties.getAnimationFinishListener(
                null /* no property for this height */);
        if (listener != null) {
            animator.addListener(listener);
        }
        // remove the tag when the animation is finished
        animator.addListener(new AnimatorListenerAdapter() {
            boolean mWasCancelled;

            @Override
            public void onAnimationEnd(Animator animation) {
                child.setTag(TAG_ANIMATOR_HEIGHT, null);
                child.setTag(TAG_START_HEIGHT, null);
                child.setTag(TAG_END_HEIGHT, null);
                child.setActualHeightAnimating(false);
                if (!mWasCancelled && child instanceof ExpandableNotificationRow) {
                    ((ExpandableNotificationRow) child).setGroupExpansionChanging(
                            false /* isExpansionChanging */);
                }
            }

            @Override
            public void onAnimationStart(Animator animation) {
                mWasCancelled = false;
            }

            @Override
            public void onAnimationCancel(Animator animation) {
                mWasCancelled = true;
            }
        });
        startAnimator(animator, listener);
        child.setTag(TAG_ANIMATOR_HEIGHT, animator);
        child.setTag(TAG_START_HEIGHT, child.getActualHeight());
        child.setTag(TAG_END_HEIGHT, newEndValue);
        child.setActualHeightAnimating(true);
    }

    private void startClipAnimation(final ExpandableView child, AnimationProperties properties,
            boolean clipTop) {
        Integer previousStartValue = getChildTag(child,
                clipTop ? TAG_START_TOP_INSET : TAG_START_BOTTOM_INSET);
        Integer previousEndValue = getChildTag(child,
                clipTop ? TAG_END_TOP_INSET : TAG_END_BOTTOM_INSET);
        int newEndValue = clipTop ? this.clipTopAmount : this.clipBottomAmount;
        if (previousEndValue != null && previousEndValue == newEndValue) {
            return;
        }
        ValueAnimator previousAnimator = getChildTag(child,
                clipTop ? TAG_ANIMATOR_TOP_INSET : TAG_ANIMATOR_BOTTOM_INSET);
        AnimationFilter filter = properties.getAnimationFilter();
        if (clipTop && !filter.animateTopInset || !clipTop) {
            // just a local update was performed
            if (previousAnimator != null) {
                // we need to increase all animation keyframes of the previous animator by the
                // relative change to the end value
                PropertyValuesHolder[] values = previousAnimator.getValues();
                int relativeDiff = newEndValue - previousEndValue;
                int newStartValue = previousStartValue + relativeDiff;
                values[0].setIntValues(newStartValue, newEndValue);
                child.setTag(clipTop ? TAG_START_TOP_INSET : TAG_START_BOTTOM_INSET, newStartValue);
                child.setTag(clipTop ? TAG_END_TOP_INSET : TAG_END_BOTTOM_INSET, newEndValue);
                previousAnimator.setCurrentPlayTime(previousAnimator.getCurrentPlayTime());
                return;
            } else {
                // no new animation needed, let's just apply the value
                if (clipTop) {
                    child.setClipTopAmount(newEndValue);
                } else {
                    child.setClipBottomAmount(newEndValue);
                }
                return;
            }
        }

        ValueAnimator animator = ValueAnimator.ofInt(
                clipTop ? child.getClipTopAmount() : child.getClipBottomAmount(), newEndValue);
        animator.addUpdateListener(animation -> {
            if (clipTop) {
                child.setClipTopAmount((int) animation.getAnimatedValue());
            } else {
                child.setClipBottomAmount((int) animation.getAnimatedValue());
            }
        });
        animator.setInterpolator(Interpolators.FAST_OUT_SLOW_IN);
        long newDuration = cancelAnimatorAndGetNewDuration(properties.duration, previousAnimator);
        animator.setDuration(newDuration);
        if (properties.delay > 0 && (previousAnimator == null
                || previousAnimator.getAnimatedFraction() == 0)) {
            animator.setStartDelay(properties.delay);
        }
        AnimatorListenerAdapter listener = properties.getAnimationFinishListener(
                null /* no property for top inset */);
        if (listener != null) {
            animator.addListener(listener);
        }
        // remove the tag when the animation is finished
        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                child.setTag(clipTop ? TAG_ANIMATOR_TOP_INSET : TAG_ANIMATOR_BOTTOM_INSET, null);
                child.setTag(clipTop ? TAG_START_TOP_INSET : TAG_START_BOTTOM_INSET, null);
                child.setTag(clipTop ? TAG_END_TOP_INSET : TAG_END_BOTTOM_INSET, null);
            }
        });
        startAnimator(animator, listener);
        child.setTag(clipTop ? TAG_ANIMATOR_TOP_INSET : TAG_ANIMATOR_BOTTOM_INSET, animator);
        child.setTag(clipTop ? TAG_START_TOP_INSET : TAG_START_BOTTOM_INSET,
                clipTop ? child.getClipTopAmount() : child.getClipBottomAmount());
        child.setTag(clipTop ? TAG_END_TOP_INSET : TAG_END_BOTTOM_INSET, newEndValue);
    }

    @Override
    public void cancelAnimations(View view) {
        super.cancelAnimations(view);
        abortAnimation(view, TAG_ANIMATOR_HEIGHT);
        abortAnimation(view, TAG_ANIMATOR_TOP_INSET);
    }
}
