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

package com.android.settingslib.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;

import androidx.annotation.GravityInt;
import androidx.annotation.IntDef;
import androidx.preference.Preference;
import androidx.preference.PreferenceViewHolder;

import com.android.settingslib.widget.preference.button.R;

import com.google.android.material.button.MaterialButton;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * A preference handled a button
 */
public class ButtonPreference extends Preference implements GroupSectionDividerMixin {

    public static final int TYPE_FILLED = 0;
    public static final int TYPE_TONAL = 1;
    public static final int TYPE_OUTLINE = 2;

    @IntDef({TYPE_FILLED, TYPE_TONAL, TYPE_OUTLINE})
    @Retention(RetentionPolicy.SOURCE)
    public @interface Type {
    }

    public static final int SIZE_NORMAL = 0;
    public static final int SIZE_LARGE = 1;
    public static final int SIZE_EXTRA_LARGE = 2;

    @IntDef({SIZE_NORMAL, SIZE_LARGE, SIZE_EXTRA_LARGE})
    @Retention(RetentionPolicy.SOURCE)
    public @interface Size {
    }

    enum ButtonStyle {
        FILLED_NORMAL(TYPE_FILLED, SIZE_NORMAL, R.layout.settingslib_expressive_button_filled),
        FILLED_LARGE(TYPE_FILLED, SIZE_LARGE, R.layout.settingslib_expressive_button_filled_large),
        FILLED_EXTRA(TYPE_FILLED, SIZE_EXTRA_LARGE,
                R.layout.settingslib_expressive_button_filled_extra),
        TONAL_NORMAL(TYPE_TONAL, SIZE_NORMAL, R.layout.settingslib_expressive_button_tonal),
        TONAL_LARGE(TYPE_TONAL, SIZE_LARGE, R.layout.settingslib_expressive_button_tonal_large),
        TONAL_EXTRA(TYPE_TONAL, SIZE_EXTRA_LARGE,
                R.layout.settingslib_expressive_button_tonal_extra),
        OUTLINE_NORMAL(TYPE_OUTLINE, SIZE_NORMAL, R.layout.settingslib_expressive_button_outline),
        OUTLINE_LARGE(TYPE_OUTLINE, SIZE_LARGE,
                R.layout.settingslib_expressive_button_outline_large),
        OUTLINE_EXTRA(TYPE_OUTLINE, SIZE_EXTRA_LARGE,
                R.layout.settingslib_expressive_button_outline_extra);

        private final int mType;
        private final int mSize;
        private final int mLayoutId;

        ButtonStyle(int type, int size, int layoutId) {
            this.mType = type;
            this.mSize = size;
            this.mLayoutId = layoutId;
        }

        static int getLayoutId(@Type int type, @Size int size) {
            for (ButtonStyle style : values()) {
                if (style.mType == type && style.mSize == size) {
                    return style.mLayoutId;
                }
            }
            throw new IllegalArgumentException();
        }
    }

    private static final int ICON_SIZE = 24;

    private View.OnClickListener mClickListener;
    private Button mButton;
    private CharSequence mTitle;
    private Drawable mIcon;
    @GravityInt
    private int mGravity;

    /**
     * Constructs a new LayoutPreference with the given context's theme, the supplied
     * attribute set, and default style attribute.
     *
     * @param context      The Context the view is running in, through which it can
     *                     access the current theme, resources, etc.
     * @param attrs        The attributes of the XML tag that is inflating the view.
     * @param defStyleAttr An attribute in the current theme that contains a
     *                     reference to a style resource that supplies default
     *                     values for the view. Can be 0 to not look for
     *                     defaults.
     */
    public ButtonPreference(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context, attrs, defStyleAttr);
    }

    /**
     * Constructs a new LayoutPreference with the given context's theme and the supplied
     * attribute set.
     *
     * @param context The Context the view is running in, through which it can
     *                access the current theme, resources, etc.
     * @param attrs   The attributes of the XML tag that is inflating the view.
     */
    public ButtonPreference(Context context, AttributeSet attrs) {
        this(context, attrs, 0 /* defStyleAttr */);
    }

    /**
     * Constructs a new LayoutPreference with the given context's theme and a customized view.
     *
     * @param context The Context the view is running in, through which it can
     *                access the current theme, resources, etc.
     */
    public ButtonPreference(Context context) {
        this(context, null);
    }

    private void init(Context context, AttributeSet attrs, int defStyleAttr) {
        int resId = R.layout.settingslib_button_layout;

        if (attrs != null) {
            TypedArray a = context.obtainStyledAttributes(attrs,
                    androidx.preference.R.styleable.Preference, defStyleAttr,
                    0 /*defStyleRes*/);
            mTitle = a.getText(
                    androidx.preference.R.styleable.Preference_android_title);
            mIcon = a.getDrawable(
                    androidx.preference.R.styleable.Preference_android_icon);
            a.recycle();

            a = context.obtainStyledAttributes(attrs,
                    R.styleable.ButtonPreference, defStyleAttr,
                    0 /*defStyleRes*/);
            mGravity = a.getInt(R.styleable.ButtonPreference_android_gravity, Gravity.START);

            if (SettingsThemeHelper.isExpressiveTheme(context)) {
                int type = a.getInt(R.styleable.ButtonPreference_buttonPreferenceType, 0);
                int size = a.getInt(R.styleable.ButtonPreference_buttonPreferenceSize, 0);
                resId = ButtonStyle.getLayoutId(type, size);
            }
            a.recycle();
        }

        setLayoutResource(resId);
    }

    @Override
    public void onBindViewHolder(PreferenceViewHolder holder) {
        mButton = (Button) holder.findViewById(R.id.settingslib_button);
        setTitle(mTitle);
        setIcon(mIcon);
        setGravity(mGravity);
        setOnClickListener(mClickListener);

        if (mButton != null) {
            final boolean selectable = isSelectable();
            mButton.setFocusable(selectable);
            mButton.setClickable(selectable);

            mButton.setEnabled(isEnabled());
        }

        holder.setDividerAllowedAbove(false);
        holder.setDividerAllowedBelow(false);
    }

    @Override
    public void setTitle(CharSequence title) {
        mTitle = title;
        if (mButton != null) {
            mButton.setText(title);
        }
    }

    @Override public CharSequence getTitle() {
        return mTitle;
    }

    @Override
    public void setIcon(Drawable icon) {
        mIcon = icon;
        if (mButton == null || icon == null) {
            return;
        }

        if (mButton instanceof MaterialButton) {
            ((MaterialButton) mButton).setIcon(icon);
        } else {
            //get pixel from dp
            int size = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, ICON_SIZE,
                    getContext().getResources().getDisplayMetrics());
            icon.setBounds(0, 0, size, size);

            //set drawableStart
            mButton.setCompoundDrawablesRelativeWithIntrinsicBounds(icon, null/* top */,
                    null/* end */,
                    null/* bottom */);
        }
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        if (mButton != null) {
            mButton.setEnabled(enabled);
        }
    }

    /**
     * Return Button
     */
    public Button getButton() {
        return mButton;
    }


    /**
     * Set a listener for button click
     */
    public void setOnClickListener(View.OnClickListener listener) {
        mClickListener = listener;
        if (mButton != null) {
            mButton.setOnClickListener(listener);
        }
    }

    /**
     * Set the gravity of button
     *
     * @param gravity The {@link Gravity} supported CENTER_HORIZONTAL
     *                and the default value is START
     */
    public void setGravity(@GravityInt int gravity) {
        if (gravity == Gravity.CENTER_HORIZONTAL || gravity == Gravity.CENTER_VERTICAL
                || gravity == Gravity.CENTER) {
            mGravity = Gravity.CENTER_HORIZONTAL;
        } else {
            mGravity = Gravity.START;
        }

        if (mButton != null) {
            LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) mButton.getLayoutParams();
            lp.gravity = mGravity;
            mButton.setLayoutParams(lp);
        }
    }

    /**
     * Sets the style of the button.
     *
     * @param type Specifies the button's type, which sets the attribute `buttonPreferenceType`.
     *             Possible values are:
     *             <ul>
     *                 <li>0: filled</li>
     *                 <li>1: tonal</li>
     *                 <li>2: outline</li>
     *             </ul>
     * @param size Specifies the button's size, which sets the attribute `buttonPreferenceSize`.
     *             Possible values are:
     *             <ul>
     *                 <li>0: normal</li>
     *                 <li>1: large</li>
     *                 <li>2: extra large</li>
     *             </ul>
     */
    public void setButtonStyle(@Type int type, @Size int size) {
        int layoutId = ButtonStyle.getLayoutId(type, size);
        setLayoutResource(layoutId);
        notifyChanged();
    }
}
