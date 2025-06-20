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

package com.android.systemui.statusbar;

import static android.view.View.IMPORTANT_FOR_ACCESSIBILITY_YES;
import static android.view.WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG;

import static com.android.systemui.Flags.fetchBookmarksXmlKeyboardShortcuts;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.AppGlobals;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import android.content.res.Configuration;
import android.graphics.Matrix;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;
import android.hardware.input.InputManagerGlobal;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.RemoteException;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.util.Pair;
import android.util.SparseArray;
import android.view.ContextThemeWrapper;
import android.view.Display;
import android.view.Gravity;
import android.view.InputDevice;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.KeyboardShortcutGroup;
import android.view.KeyboardShortcutInfo;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.AccessibilityDelegate;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.app.AssistUtils;
import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.nano.MetricsProto;
import com.android.systemui.res.R;
import com.android.systemui.statusbar.phone.CentralSurfaces;
import com.android.systemui.utils.windowmanager.WindowManagerProvider;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Contains functionality for handling keyboard shortcuts.
 */
public final class KeyboardShortcutListSearch {
    private static final String TAG = KeyboardShortcutListSearch.class.getSimpleName();
    private static final Object sLock = new Object();
    @VisibleForTesting public static KeyboardShortcutListSearch sInstance;

    private static int SHORTCUT_SYSTEM_INDEX = 0;
    private static int SHORTCUT_INPUT_INDEX = 1;
    private static int SHORTCUT_OPENAPPS_INDEX = 2;
    private static int SHORTCUT_SPECIFICAPP_INDEX = 3;

    private WindowManager mWindowManager;
    private EditText mSearchEditText;
    private ImageButton mEditTextCancel;
    private String mQueryString;
    private int mCurrentCategoryIndex = 0;
    private Map<Integer, Boolean> mKeySearchResultMap = new HashMap<>();

    private List<List<KeyboardShortcutMultiMappingGroup>> mFullShortsGroup = new ArrayList<>();
    private List<KeyboardShortcutMultiMappingGroup> mSpecificAppGroup = new ArrayList<>();
    private List<KeyboardShortcutMultiMappingGroup> mSystemGroup = new ArrayList<>();
    private List<KeyboardShortcutMultiMappingGroup> mInputGroup = new ArrayList<>();
    private List<KeyboardShortcutMultiMappingGroup> mOpenAppsGroup = new ArrayList<>();

    private ArrayList<Button> mFullButtonList = new ArrayList<>();
    private Button mButtonSystem;
    private Button mButtonInput;
    private Button mButtonOpenApps;
    private Button mButtonSpecificApp;
    private CharSequence mCurrentAppPackageName;
    private TextView mNoSearchResults;

    private final SparseArray<String> mSpecialCharacterNames = new SparseArray<>();
    private final SparseArray<String> mModifierNames = new SparseArray<>();
    private final SparseArray<Drawable> mModifierDrawables = new SparseArray<>();
    // Ordered list of modifiers that are supported. All values in this array must exist in
    // mModifierNames.
    private final int[] mModifierList = new int[] {
            KeyEvent.META_META_ON, KeyEvent.META_CTRL_ON, KeyEvent.META_ALT_ON,
            KeyEvent.META_SHIFT_ON, KeyEvent.META_SYM_ON, KeyEvent.META_FUNCTION_ON
    };

    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final HandlerThread mHandlerThread = new HandlerThread("KeyboardShortcutHelper");
    @VisibleForTesting Handler mBackgroundHandler;
    @VisibleForTesting public Context mContext;
    private final IPackageManager mPackageManager;

    @VisibleForTesting BottomSheetDialog mKeyboardShortcutsBottomSheetDialog;
    private KeyCharacterMap mKeyCharacterMap;
    private KeyCharacterMap mBackupKeyCharacterMap;

    @VisibleForTesting
    KeyboardShortcutListSearch(Context context, @NonNull WindowManager windowManager,
            int deviceId) {
        this.mContext = new ContextThemeWrapper(
                context, R.style.KeyboardShortcutHelper);
        this.mPackageManager = AppGlobals.getPackageManager();
        this.mWindowManager = windowManager;
        loadResources(this.mContext);
        createHardcodedShortcuts(deviceId);
    }

    private static KeyboardShortcutListSearch getInstance(Context context, int deviceId,
            WindowManagerProvider windowManagerProvider) {
        if (sInstance == null) {
            WindowManager windowManager = windowManagerProvider.getWindowManager(context);
            sInstance = new KeyboardShortcutListSearch(context, windowManager, deviceId);
        }
        return sInstance;
    }

    public static void show(Context context, int deviceId,
            WindowManagerProvider windowManagerProvider) {
        MetricsLogger.visible(context,
                MetricsProto.MetricsEvent.KEYBOARD_SHORTCUTS_HELPER);
        synchronized (sLock) {
            if (sInstance != null && !sInstance.mContext.equals(context)) {
                dismiss();
            }
            getInstance(context, deviceId, windowManagerProvider).showKeyboardShortcuts(deviceId);
        }
    }

    public static void toggle(Context context, int deviceId,
            WindowManagerProvider windowManagerProvider) {
        synchronized (sLock) {
            if (isShowing()) {
                dismiss();
            } else {
                show(context, deviceId, windowManagerProvider);
            }
        }
    }

    public static void dismiss() {
        synchronized (sLock) {
            if (sInstance != null) {
                MetricsLogger.hidden(sInstance.mContext,
                        MetricsProto.MetricsEvent.KEYBOARD_SHORTCUTS_HELPER);
                sInstance.dismissKeyboardShortcuts();
                sInstance = null;
            }
        }
    }

    private static boolean isShowing() {
        return sInstance != null && sInstance.mKeyboardShortcutsBottomSheetDialog != null
                && sInstance.mKeyboardShortcutsBottomSheetDialog.isShowing();
    }

    private void loadResources(Context context) {
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_HOME, context.getString(R.string.keyboard_key_home));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_BACK, context.getString(R.string.keyboard_key_back));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DPAD_UP, context.getString(R.string.keyboard_key_dpad_up));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DPAD_DOWN, context.getString(R.string.keyboard_key_dpad_down));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DPAD_LEFT, context.getString(R.string.keyboard_key_dpad_left));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DPAD_RIGHT, context.getString(R.string.keyboard_key_dpad_right));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DPAD_CENTER, context.getString(R.string.keyboard_key_dpad_center));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_PERIOD, ".");
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_TAB, context.getString(R.string.keyboard_key_tab));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_SPACE, context.getString(R.string.keyboard_key_space));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_ENTER, context.getString(R.string.keyboard_key_enter));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_DEL, context.getString(R.string.keyboard_key_backspace));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE,
                context.getString(R.string.keyboard_key_media_play_pause));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_MEDIA_STOP, context.getString(R.string.keyboard_key_media_stop));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_MEDIA_NEXT, context.getString(R.string.keyboard_key_media_next));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MEDIA_PREVIOUS,
                context.getString(R.string.keyboard_key_media_previous));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MEDIA_REWIND,
                context.getString(R.string.keyboard_key_media_rewind));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MEDIA_FAST_FORWARD,
                context.getString(R.string.keyboard_key_media_fast_forward));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_PAGE_UP, context.getString(R.string.keyboard_key_page_up));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_PAGE_DOWN, context.getString(R.string.keyboard_key_page_down));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_A,
                context.getString(R.string.keyboard_key_button_template, "A"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_B,
                context.getString(R.string.keyboard_key_button_template, "B"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_C,
                context.getString(R.string.keyboard_key_button_template, "C"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_X,
                context.getString(R.string.keyboard_key_button_template, "X"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_Y,
                context.getString(R.string.keyboard_key_button_template, "Y"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_Z,
                context.getString(R.string.keyboard_key_button_template, "Z"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_L1,
                context.getString(R.string.keyboard_key_button_template, "L1"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_R1,
                context.getString(R.string.keyboard_key_button_template, "R1"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_L2,
                context.getString(R.string.keyboard_key_button_template, "L2"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_R2,
                context.getString(R.string.keyboard_key_button_template, "R2"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_START,
                context.getString(R.string.keyboard_key_button_template, "Start"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_SELECT,
                context.getString(R.string.keyboard_key_button_template, "Select"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BUTTON_MODE,
                context.getString(R.string.keyboard_key_button_template, "Mode"));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_FORWARD_DEL, context.getString(R.string.keyboard_key_forward_del));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_ESCAPE, context.getString(R.string.keyboard_key_esc));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_SYSRQ, "SysRq");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_BREAK, "Break");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_SCROLL_LOCK, "Scroll Lock");
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_MOVE_HOME, context.getString(R.string.keyboard_key_move_home));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_MOVE_END, context.getString(R.string.keyboard_key_move_end));
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_INSERT, context.getString(R.string.keyboard_key_insert));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F1, "F1");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F2, "F2");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F3, "F3");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F4, "F4");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F5, "F5");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F6, "F6");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F7, "F7");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F8, "F8");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F9, "F9");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F10, "F10");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F11, "F11");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_F12, "F12");
        mSpecialCharacterNames.put(
                KeyEvent.KEYCODE_NUM_LOCK, context.getString(R.string.keyboard_key_num_lock));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MINUS, "-");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_GRAVE, "`");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_EQUALS, "=");

        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_0,
                context.getString(R.string.keyboard_key_numpad_template, "0"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_1,
                context.getString(R.string.keyboard_key_numpad_template, "1"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_2,
                context.getString(R.string.keyboard_key_numpad_template, "2"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_3,
                context.getString(R.string.keyboard_key_numpad_template, "3"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_4,
                context.getString(R.string.keyboard_key_numpad_template, "4"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_5,
                context.getString(R.string.keyboard_key_numpad_template, "5"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_6,
                context.getString(R.string.keyboard_key_numpad_template, "6"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_7,
                context.getString(R.string.keyboard_key_numpad_template, "7"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_8,
                context.getString(R.string.keyboard_key_numpad_template, "8"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_9,
                context.getString(R.string.keyboard_key_numpad_template, "9"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_DIVIDE,
                context.getString(R.string.keyboard_key_numpad_template, "/"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_MULTIPLY,
                context.getString(R.string.keyboard_key_numpad_template, "*"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_SUBTRACT,
                context.getString(R.string.keyboard_key_numpad_template, "-"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_ADD,
                context.getString(R.string.keyboard_key_numpad_template, "+"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_DOT,
                context.getString(R.string.keyboard_key_numpad_template, "."));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_COMMA,
                context.getString(R.string.keyboard_key_numpad_template, ","));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_ENTER,
                context.getString(R.string.keyboard_key_numpad_template,
                        context.getString(R.string.keyboard_key_enter)));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_EQUALS,
                context.getString(R.string.keyboard_key_numpad_template, "="));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_LEFT_PAREN,
                context.getString(R.string.keyboard_key_numpad_template, "("));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_NUMPAD_RIGHT_PAREN,
                context.getString(R.string.keyboard_key_numpad_template, ")"));
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_ZENKAKU_HANKAKU, "半角/全角");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_EISU, "英数");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_MUHENKAN, "無変換");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_HENKAN, "変換");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_KATAKANA_HIRAGANA, "かな");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_ALT_LEFT, "Alt");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_ALT_RIGHT, "Alt");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_CTRL_LEFT, "Ctrl");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_CTRL_RIGHT, "Ctrl");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_SHIFT_LEFT, "Shift");
        mSpecialCharacterNames.put(KeyEvent.KEYCODE_SHIFT_RIGHT, "Shift");

        mModifierNames.put(KeyEvent.META_META_ON, "Meta");
        mModifierNames.put(KeyEvent.META_CTRL_ON, "Ctrl");
        mModifierNames.put(KeyEvent.META_ALT_ON, "Alt");
        mModifierNames.put(KeyEvent.META_SHIFT_ON, "Shift");
        mModifierNames.put(KeyEvent.META_SYM_ON, "Sym");
        mModifierNames.put(KeyEvent.META_FUNCTION_ON, "Fn");

        mModifierDrawables.put(
                KeyEvent.META_META_ON, context.getDrawable(R.drawable.ic_ksh_key_meta));
    }

    private void createHardcodedShortcuts(int deviceId) {
        // Add system shortcuts
        mKeySearchResultMap.put(SHORTCUT_SYSTEM_INDEX, true);
        mSystemGroup.add(getMultiMappingSystemShortcuts(mContext));
        mSystemGroup.add(getSystemMultitaskingShortcuts(mContext));
        // Add input shortcuts
        mKeySearchResultMap.put(SHORTCUT_INPUT_INDEX, true);
        mInputGroup.add(getMultiMappingInputShortcuts(mContext));
        // Add open apps shortcuts
        final List<KeyboardShortcutMultiMappingGroup> appShortcuts =
                Arrays.asList(getDefaultMultiMappingApplicationShortcuts(deviceId));
        if (appShortcuts != null && !appShortcuts.isEmpty()) {
            mOpenAppsGroup = appShortcuts;
            mKeySearchResultMap.put(SHORTCUT_OPENAPPS_INDEX, true);
        } else {
            mKeySearchResultMap.put(SHORTCUT_OPENAPPS_INDEX, false);
        }
    }

    /**
     * Retrieves a {@link KeyCharacterMap} and assigns it to mKeyCharacterMap. If the given id is an
     * existing device, that device's map is used. Otherwise, it checks first all available devices
     * and if there is a full keyboard it uses that map, otherwise falls back to the Virtual
     * Keyboard with its default map.
     */
    private void retrieveKeyCharacterMap(int deviceId) {
        final InputManagerGlobal inputManager = InputManagerGlobal.getInstance();
        mBackupKeyCharacterMap = inputManager.getInputDevice(-1).getKeyCharacterMap();
        if (deviceId != -1) {
            final InputDevice inputDevice = inputManager.getInputDevice(deviceId);
            if (inputDevice != null) {
                mKeyCharacterMap = inputDevice.getKeyCharacterMap();
                return;
            }
        }
        final int[] deviceIds = inputManager.getInputDeviceIds();
        for (int id : deviceIds) {
            final InputDevice inputDevice = inputManager.getInputDevice(id);
            // -1 is the Virtual Keyboard, with the default key map. Use that one only as last
            // resort.
            if (inputDevice.getId() != -1 && inputDevice.isFullKeyboard()) {
                mKeyCharacterMap = inputDevice.getKeyCharacterMap();
                return;
            }
        }
        // Fall back to -1, the virtual keyboard.
        mKeyCharacterMap = mBackupKeyCharacterMap;
    }

    private boolean mAppShortcutsReceived;
    private boolean mImeShortcutsReceived;

    private void onAppSpecificShortcutsReceived(List<KeyboardShortcutGroup> result) {
        // Add specific app shortcuts
        if (result != null) {
            if (result.isEmpty()) {
                mCurrentAppPackageName = null;
                mKeySearchResultMap.put(SHORTCUT_SPECIFICAPP_INDEX, false);
            } else {
                mCurrentAppPackageName = result.get(0).getPackageName();
                KeyboardShortcuts.sanitiseShortcuts(result);
                mSpecificAppGroup.addAll(
                        reMapToKeyboardShortcutMultiMappingGroup(result));
                mKeySearchResultMap.put(SHORTCUT_SPECIFICAPP_INDEX, true);
            }
        }
        mAppShortcutsReceived = true;
        if (mImeShortcutsReceived) {
            mergeAndShowKeyboardShortcutsGroups();
        }
    }

    private void onImeSpecificShortcutsReceived(List<KeyboardShortcutGroup> result) {
        // Add specific Ime shortcuts
        if (result != null) {
            if (!result.isEmpty()) {
                KeyboardShortcuts.sanitiseShortcuts(result);
                mInputGroup.addAll(
                        reMapToKeyboardShortcutMultiMappingGroup(result));
            }
        }
        mImeShortcutsReceived = true;
        if (mAppShortcutsReceived) {
            mergeAndShowKeyboardShortcutsGroups();
        }
    }

    @VisibleForTesting
    public void showKeyboardShortcuts(int deviceId) {
        if (mBackgroundHandler == null) {
            mHandlerThread.start();
            mBackgroundHandler = new Handler(mHandlerThread.getLooper());
        }

        retrieveKeyCharacterMap(deviceId);
        mAppShortcutsReceived = false;
        mImeShortcutsReceived = false;
        mWindowManager.requestAppKeyboardShortcuts(
                result -> {
                    mBackgroundHandler.post(() -> {
                        onAppSpecificShortcutsReceived(result);
                    });
                }, deviceId);
        mWindowManager.requestImeKeyboardShortcuts(
                result -> {
                    mBackgroundHandler.post(() -> {
                        onImeSpecificShortcutsReceived(result);
                    });
                }, deviceId);
    }

    private void mergeAndShowKeyboardShortcutsGroups() {
        mFullShortsGroup.add(SHORTCUT_SYSTEM_INDEX, mSystemGroup);
        mFullShortsGroup.add(SHORTCUT_INPUT_INDEX, mInputGroup);
        mFullShortsGroup.add(SHORTCUT_OPENAPPS_INDEX, mOpenAppsGroup);
        mFullShortsGroup.add(SHORTCUT_SPECIFICAPP_INDEX, mSpecificAppGroup);
        showKeyboardShortcutSearchList(mFullShortsGroup);
    }

    // The original data structure is only for 1-to-1 shortcut mapping, so remap the old
    // data structure to the new data structure for handling the N-to-1 key mapping and other
    // complex case.
    private List<KeyboardShortcutMultiMappingGroup> reMapToKeyboardShortcutMultiMappingGroup(
            List<KeyboardShortcutGroup> keyboardShortcutGroups) {
        List<KeyboardShortcutMultiMappingGroup> keyboardShortcutMultiMappingGroups =
                new ArrayList<>();
        for (KeyboardShortcutGroup group : keyboardShortcutGroups) {
            KeyboardShortcutMultiMappingGroup mappedGroup =
                    new KeyboardShortcutMultiMappingGroup(
                            group.getLabel(),
                            new ArrayList<>());
            Map<String, List<ShortcutMultiMappingInfo>> shortcutMap = new LinkedHashMap<>();
            for (KeyboardShortcutInfo info : group.getItems()) {
                String label = info.getLabel().toString();
                Icon icon = info.getIcon();
                if (shortcutMap.containsKey(label)) {
                    List<ShortcutMultiMappingInfo> shortcuts = shortcutMap.get(label);
                    boolean foundSameIcon = false;
                    for (ShortcutMultiMappingInfo shortcut : shortcuts) {
                        Icon shortcutIcon = shortcut.getIcon();
                        if ((shortcutIcon != null
                                && icon != null
                                && shortcutIcon.sameAs(icon))
                                || (shortcutIcon == null && icon == null)) {
                            foundSameIcon = true;
                            shortcut.addShortcutKeyGroup(new ShortcutKeyGroup(info, null));
                            break;
                        }
                    }
                    if (!foundSameIcon) {
                        shortcuts.add(new ShortcutMultiMappingInfo(info));
                    }
                } else {
                    List<ShortcutMultiMappingInfo> shortcuts = new ArrayList<>();
                    shortcuts.add(new ShortcutMultiMappingInfo(info));
                    shortcutMap.put(label, shortcuts);
                }
            }
            for (List<ShortcutMultiMappingInfo> shortcutInfos : shortcutMap.values()) {
                for (ShortcutMultiMappingInfo shortcutInfo : shortcutInfos) {
                    mappedGroup.addItem(shortcutInfo);
                }
            }
            keyboardShortcutMultiMappingGroups.add(mappedGroup);
        }
        return keyboardShortcutMultiMappingGroups;
    }

    @VisibleForTesting
    public void dismissKeyboardShortcuts() {
        if (mKeyboardShortcutsBottomSheetDialog != null) {
            mKeyboardShortcutsBottomSheetDialog.dismiss();
            mKeyboardShortcutsBottomSheetDialog = null;
        }
        mHandlerThread.quit();
    }

    private KeyboardShortcutMultiMappingGroup getMultiMappingSystemShortcuts(Context context) {
        KeyboardShortcutMultiMappingGroup systemGroup =
                new KeyboardShortcutMultiMappingGroup(
                        context.getString(R.string.keyboard_shortcut_group_system),
                        new ArrayList<>());
        List<ShortcutKeyGroupMultiMappingInfo> infoList = Arrays.asList(
                /* Access list of all apps and search (i.e. Search/Launcher): Meta */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_all_apps_search),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_UNKNOWN, KeyEvent.META_META_ON))),
                /* Access home screen: Meta + H, Meta + Enter */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_home_screen),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_H, KeyEvent.META_META_ON),
                                Pair.create(KeyEvent.KEYCODE_ENTER, KeyEvent.META_META_ON))),
                /* Overview of open apps: Meta + Tab */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_overview_open_apps),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_TAB, KeyEvent.META_META_ON))),
                /* Back: go back to previous state (back button) */
                /* Meta + Escape, Meta + left arrow */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_go_back),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_ESCAPE, KeyEvent.META_META_ON),
                                Pair.create(KeyEvent.KEYCODE_DPAD_LEFT, KeyEvent.META_META_ON))),
                /* Take a full screenshot: Meta + S */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_full_screenshot),
                        Arrays.asList(
                                Pair.create(
                                        KeyEvent.KEYCODE_S,
                                        KeyEvent.META_META_ON))),
                /* Access list of system / apps shortcuts: Meta + / */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_system_app_shortcuts),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_SLASH, KeyEvent.META_META_ON))),
                /* Cycle through recent apps (forward): Alt + Tab */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_cycle_forward),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_TAB, KeyEvent.META_ALT_ON))),
                /* Cycle through recent apps (back): Shift + Alt + Tab */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_cycle_back),
                        Arrays.asList(
                                Pair.create(
                                        KeyEvent.KEYCODE_TAB,
                                        KeyEvent.META_SHIFT_ON | KeyEvent.META_ALT_ON))),
                /* Access notification shade: Meta + N */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_notification_shade),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_N, KeyEvent.META_META_ON))),
                /*  Lock screen: Meta + L */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_lock_screen),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_L, KeyEvent.META_META_ON))),
                /* Access system settings: Meta + I */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_system_settings),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_I, KeyEvent.META_META_ON))),
                /* Access Google Assistant: Meta + A */
                new ShortcutKeyGroupMultiMappingInfo(
                        context.getString(R.string.group_system_access_google_assistant),
                        Arrays.asList(
                                Pair.create(KeyEvent.KEYCODE_A, KeyEvent.META_META_ON)))
        );
        for (ShortcutKeyGroupMultiMappingInfo info : infoList) {
            systemGroup.addItem(info.getShortcutMultiMappingInfo());
        }
        return systemGroup;
    }

    private static class ShortcutKeyGroupMultiMappingInfo {
        private String mLabel;
        private List<Pair<Integer, Integer>> mKeycodeGroupList;

        ShortcutKeyGroupMultiMappingInfo(
                String label, List<Pair<Integer, Integer>> keycodeGroupList) {
            mLabel = label;
            mKeycodeGroupList = keycodeGroupList;
        }

        ShortcutMultiMappingInfo getShortcutMultiMappingInfo() {
            List<ShortcutKeyGroup> shortcutKeyGroups = new ArrayList<>();
            for (Pair<Integer, Integer> keycodeGroup : mKeycodeGroupList) {
                shortcutKeyGroups.add(new ShortcutKeyGroup(
                        new KeyboardShortcutInfo(
                                mLabel,
                                keycodeGroup.first /* keycode */,
                                keycodeGroup.second /* modifiers*/),
                        null));
            }
            ShortcutMultiMappingInfo shortcutMultiMappingInfo =
                    new ShortcutMultiMappingInfo(mLabel, null, shortcutKeyGroups);
            return shortcutMultiMappingInfo;
        }
    }

    private static KeyboardShortcutMultiMappingGroup getSystemMultitaskingShortcuts(
            Context context) {
        KeyboardShortcutMultiMappingGroup systemMultitaskingGroup =
                new KeyboardShortcutMultiMappingGroup(
                        context.getString(R.string.keyboard_shortcut_group_system_multitasking),
                        new ArrayList<>());

        // System multitasking shortcuts:
        //    Enter Split screen with current app to RHS: Meta + Ctrl + Right arrow
        //    Enter Split screen with current app to LHS: Meta + Ctrl + Left arrow
        //    Switch from Split screen to full screen: Meta + Ctrl + Up arrow
        //    Change split screen focus to RHS: Meta + Alt + Right arrow
        //    Change split screen focus to LHS: Meta + Alt + Left arrow
        systemMultitaskingGroup.addItem(
                getMultitaskingShortcut(context.getString(R.string.system_multitasking_rhs),
                        KeyEvent.KEYCODE_DPAD_RIGHT,
                        KeyEvent.META_META_ON | KeyEvent.META_CTRL_ON));
        systemMultitaskingGroup.addItem(
                getMultitaskingShortcut(context.getString(R.string.system_multitasking_lhs),
                        KeyEvent.KEYCODE_DPAD_LEFT,
                        KeyEvent.META_META_ON | KeyEvent.META_CTRL_ON));
        systemMultitaskingGroup.addItem(
                getMultitaskingShortcut(context.getString(R.string.system_multitasking_full_screen),
                        KeyEvent.KEYCODE_DPAD_UP,
                        KeyEvent.META_META_ON | KeyEvent.META_CTRL_ON));
        systemMultitaskingGroup.addItem(
                getMultitaskingShortcut(
                        context.getString(R.string.system_multitasking_splitscreen_focus_rhs),
                        KeyEvent.KEYCODE_DPAD_RIGHT,
                        KeyEvent.META_META_ON | KeyEvent.META_ALT_ON));
        systemMultitaskingGroup.addItem(
                getMultitaskingShortcut(
                        context.getString(R.string.system_multitasking_splitscreen_focus_lhs),
                        KeyEvent.KEYCODE_DPAD_LEFT,
                        KeyEvent.META_META_ON | KeyEvent.META_ALT_ON));
        return systemMultitaskingGroup;
    }

    private static ShortcutMultiMappingInfo getMultitaskingShortcut(String shortcutLabel,
            int keycode, int modifiers) {
        List<ShortcutKeyGroup> shortcutKeyGroups = Arrays.asList(
                new ShortcutKeyGroup(new KeyboardShortcutInfo(shortcutLabel, keycode, modifiers),
                        null));
        return new ShortcutMultiMappingInfo(shortcutLabel, null, shortcutKeyGroups);
    }

    private static KeyboardShortcutMultiMappingGroup getMultiMappingInputShortcuts(
            Context context) {
        List<ShortcutMultiMappingInfo> shortcutMultiMappingInfoList = Arrays.asList(
                /* Switch input language (next language): Ctrl + Space */
                new ShortcutMultiMappingInfo(
                        context.getString(R.string.input_switch_input_language_next),
                        null,
                        Arrays.asList(
                                new ShortcutKeyGroup(new KeyboardShortcutInfo(
                                        context.getString(
                                                R.string.input_switch_input_language_next),
                                        KeyEvent.KEYCODE_SPACE, KeyEvent.META_CTRL_ON),
                                        null))),
                /* Switch input language (previous language): */
                /* Ctrl + Shift + Space */
                new ShortcutMultiMappingInfo(
                        context.getString(R.string.input_switch_input_language_previous),
                        null,
                        Arrays.asList(
                                new ShortcutKeyGroup(new KeyboardShortcutInfo(
                                        context.getString(
                                                R.string.input_switch_input_language_previous),
                                        KeyEvent.KEYCODE_SPACE,
                                        KeyEvent.META_CTRL_ON | KeyEvent.META_SHIFT_ON),
                                        null)))
        );
        return new KeyboardShortcutMultiMappingGroup(
                context.getString(R.string.keyboard_shortcut_group_input),
                shortcutMultiMappingInfoList);
    }

    private KeyboardShortcutMultiMappingGroup getDefaultMultiMappingApplicationShortcuts(
            int deviceId) {
        List<ShortcutMultiMappingInfo> shortcutMultiMappingInfos = new ArrayList<>();
        CharSequence categoryTitle;
        if (fetchBookmarksXmlKeyboardShortcuts()) {
            KeyboardShortcutGroup apps =
                    mWindowManager.getApplicationLaunchKeyboardShortcuts(deviceId);
            List<KeyboardShortcutMultiMappingGroup> shortcuts =
                    reMapToKeyboardShortcutMultiMappingGroup(Arrays.asList(apps));
            for (KeyboardShortcutMultiMappingGroup group : shortcuts) {
                for (ShortcutMultiMappingInfo keyboardShortcutInfo : group.getItems()) {
                    shortcutMultiMappingInfos.add(keyboardShortcutInfo);
                }
            }
            categoryTitle = apps.getLabel();
        } else {
            // Show shortcuts based on AOSP bookmarks.xml
            categoryTitle = mContext.getString(R.string.keyboard_shortcut_group_applications);
            final int userId = mContext.getUserId();
            PackageInfo assistPackageInfo =
                    getAssistPackageInfo(mContext, mPackageManager, userId);

            String[] intentCategories = {
                    Intent.CATEGORY_APP_BROWSER,
                    Intent.CATEGORY_APP_CONTACTS,
                    Intent.CATEGORY_APP_EMAIL,
                    Intent.CATEGORY_APP_CALENDAR,
                    Intent.CATEGORY_APP_MAPS,
                    Intent.CATEGORY_APP_CALCULATOR,
            };
            String[] shortcutLabels = {
                    mContext.getString(R.string.keyboard_shortcut_group_applications_browser),
                    mContext.getString(R.string.keyboard_shortcut_group_applications_contacts),
                    mContext.getString(R.string.keyboard_shortcut_group_applications_email),
                    mContext.getString(R.string.keyboard_shortcut_group_applications_calendar),
                    mContext.getString(R.string.keyboard_shortcut_group_applications_maps),
                    mContext.getString(R.string.keyboard_shortcut_group_applications_calculator)
            };

            int[] keyCodes = {
                KeyEvent.KEYCODE_B,
                KeyEvent.KEYCODE_P,
                KeyEvent.KEYCODE_E,
                KeyEvent.KEYCODE_C,
                KeyEvent.KEYCODE_M,
                KeyEvent.KEYCODE_U,
            };

            // Assist.
            if (assistPackageInfo != null) {
                if (assistPackageInfo != null) {
                    final Icon assistIcon = Icon.createWithResource(
                            assistPackageInfo.applicationInfo.packageName,
                            assistPackageInfo.applicationInfo.icon);
                    CharSequence assistLabel = mContext.getString(
                            R.string.keyboard_shortcut_group_applications_assist);
                    KeyboardShortcutInfo assistShortcutInfo = new KeyboardShortcutInfo(
                            assistLabel,
                            assistIcon,
                            KeyEvent.KEYCODE_A,
                            KeyEvent.META_META_ON);
                    shortcutMultiMappingInfos.add(
                            new ShortcutMultiMappingInfo(
                                    assistLabel,
                                    assistIcon,
                                    Arrays.asList(new ShortcutKeyGroup(assistShortcutInfo, null))));
                }
            }

            for (int i = 0; i < shortcutLabels.length; i++) {
                final Icon icon = getIconForIntentCategory(intentCategories[i], userId);
                if (icon != null) {
                    CharSequence label =
                            shortcutLabels[i];
                    KeyboardShortcutInfo keyboardShortcutInfo = new KeyboardShortcutInfo(
                            label,
                            icon,
                            keyCodes[i],
                            KeyEvent.META_META_ON);
                    List<ShortcutKeyGroup> shortcutKeyGroups =
                            Arrays.asList(new ShortcutKeyGroup(keyboardShortcutInfo, null));
                    shortcutMultiMappingInfos.add(
                            new ShortcutMultiMappingInfo(label, icon, shortcutKeyGroups));
                }
            }
        }

        Comparator<ShortcutMultiMappingInfo> applicationItemsComparator =
                new Comparator<ShortcutMultiMappingInfo>() {
                    @Override
                    public int compare(
                            ShortcutMultiMappingInfo ksh1, ShortcutMultiMappingInfo ksh2) {
                        boolean ksh1ShouldBeLast = ksh1.getLabel() == null
                                || ksh1.getLabel().toString().isEmpty();
                        boolean ksh2ShouldBeLast = ksh2.getLabel() == null
                                || ksh2.getLabel().toString().isEmpty();
                        if (ksh1ShouldBeLast && ksh2ShouldBeLast) {
                            return 0;
                        }
                        if (ksh1ShouldBeLast) {
                            return 1;
                        }
                        if (ksh2ShouldBeLast) {
                            return -1;
                        }
                        return (ksh1.getLabel().toString()).compareToIgnoreCase(
                                ksh2.getLabel().toString());
                    }
                };
        // Sorts by label, case insensitive with nulls and/or empty labels last.
        Collections.sort(shortcutMultiMappingInfos, applicationItemsComparator);
        return new KeyboardShortcutMultiMappingGroup(categoryTitle, shortcutMultiMappingInfos);
    }

    private Icon getIconForIntentCategory(String intentCategory, int userId) {
        final Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.addCategory(intentCategory);

        final PackageInfo packageInfo = getPackageInfoForIntent(intent, userId);
        if (packageInfo != null && packageInfo.applicationInfo.icon != 0) {
            return Icon.createWithResource(
                    packageInfo.applicationInfo.packageName,
                    packageInfo.applicationInfo.icon);
        }
        return null;
    }

    private PackageInfo getPackageInfoForIntent(Intent intent, int userId) {
        try {
            ResolveInfo handler;
            handler = mPackageManager.resolveIntent(
                    intent, intent.resolveTypeIfNeeded(mContext.getContentResolver()), 0, userId);
            if (handler == null || handler.activityInfo == null) {
                return null;
            }
            return mPackageManager.getPackageInfo(handler.activityInfo.packageName, 0, userId);
        } catch (RemoteException e) {
            Log.e(TAG, "PackageManagerService is dead", e);
            return null;
        }
    }

    private void showKeyboardShortcutSearchList(
            List<List<KeyboardShortcutMultiMappingGroup>> keyboardShortcutMultiMappingGroupList) {
        // Need to post on the main thread.
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                handleShowKeyboardShortcutSearchList(keyboardShortcutMultiMappingGroupList);
            }
        });
    }

    private void handleShowKeyboardShortcutSearchList(
            List<List<KeyboardShortcutMultiMappingGroup>> keyboardShortcutMultiMappingGroupList) {
        mQueryString = null;
        LayoutInflater inflater = mContext.getSystemService(LayoutInflater.class);
        mKeyboardShortcutsBottomSheetDialog  = new BottomSheetDialog(mContext);
        final View keyboardShortcutsView = inflater.inflate(
                R.layout.keyboard_shortcuts_search_view, null);
        LinearLayout shortcutsContainer = keyboardShortcutsView.findViewById(
                R.id.keyboard_shortcuts_container);
        mNoSearchResults = keyboardShortcutsView.findViewById(R.id.shortcut_search_no_result);
        Window keyboardShortcutsWindow = mKeyboardShortcutsBottomSheetDialog.getWindow();
        setWindowProperties(keyboardShortcutsWindow);
        mKeyboardShortcutsBottomSheetDialog.setContentView(keyboardShortcutsView);
        setButtonsDefaultStatus(keyboardShortcutsView);
        populateCurrentAppButton();
        populateKeyboardShortcutSearchList(shortcutsContainer);

        // Workaround for solve issue about dialog not full expanded when landscape.
        FrameLayout bottomSheet = (FrameLayout)
                mKeyboardShortcutsBottomSheetDialog.findViewById(
                        com.google.android.material.R.id.design_bottom_sheet);
        if (bottomSheet != null) {
            bottomSheet.setBackgroundResource(android.R.color.transparent);
        }

        BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
        behavior.setDraggable(true);
        behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
        behavior.setSkipCollapsed(true);


        synchronized (sLock) {
            // show KeyboardShortcutsBottomSheetDialog only if it has not been dismissed already
            if (sInstance != null) {
                mKeyboardShortcutsBottomSheetDialog.show();
                setDialogScreenSize();
                keyboardShortcutsView.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
                    @Override
                    public void onLayoutChange(View v, int left, int top, int right,
                            int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                        setDialogScreenSize();
                    }
                });
            }
        }
        mSearchEditText = keyboardShortcutsView.findViewById(R.id.keyboard_shortcuts_search);
        mEditTextCancel = keyboardShortcutsView.findViewById(
                R.id.keyboard_shortcuts_search_cancel);
        mSearchEditText.addTextChangedListener(
                new TextWatcher() {
                    @Override
                    public void afterTextChanged(Editable s) {
                        mQueryString = s.toString();
                        populateKeyboardShortcutSearchList(shortcutsContainer);
                        if (mNoSearchResults.getVisibility() == View.VISIBLE) {
                            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                                    R.string.keyboard_shortcut_search_list_no_result));
                        } else if (mSearchEditText.getText().length() > 0) {
                            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                                    R.string.keyboard_shortcut_a11y_show_search_results));
                        }
                        mEditTextCancel.setVisibility(
                                TextUtils.isEmpty(mQueryString) ? View.GONE : View.VISIBLE);
                    }

                    @Override
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                        // Do nothing.
                    }

                    @Override
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                        // Do nothing.
                    }
                });

        mEditTextCancel.setOnClickListener(v -> mSearchEditText.setText(null));
    }

    private static void setWindowProperties(Window keyboardShortcutsWindow) {
        keyboardShortcutsWindow.setType(TYPE_SYSTEM_DIALOG);
        WindowManager.LayoutParams params = new WindowManager.LayoutParams();
        params.copyFrom(keyboardShortcutsWindow.getAttributes());
        // Allows the bottom sheet dialog to render all the way to the bottom of the screen,
        // behind the gesture navigation bar.
        params.flags |= WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS;
        params.setFitInsetsTypes(WindowInsets.Type.statusBars());
        keyboardShortcutsWindow.setAttributes(params);
        keyboardShortcutsWindow.getDecorView().setOnApplyWindowInsetsListener((v, insets) -> {
            int bottom = insets.getInsets(WindowInsets.Type.navigationBars()).bottom;
            View container = v.findViewById(R.id.keyboard_shortcuts_container);
            container.setPadding(container.getPaddingLeft(), container.getPaddingTop(),
                    container.getPaddingRight(), bottom);
            return WindowInsets.CONSUMED;
        });
        keyboardShortcutsWindow.setWindowAnimations(
                R.style.KeyboardShortcutHelper_BottomSheetDialogAnimation);
    }

    private void populateKeyboardShortcutSearchList(LinearLayout keyboardShortcutsLayout) {
        LayoutInflater inflater = LayoutInflater.from(mContext);
        TextView shortcutsKeyView = (TextView) inflater.inflate(
                R.layout.keyboard_shortcuts_key_view, keyboardShortcutsLayout, false);
        shortcutsKeyView.measure(
                View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
        final int shortcutKeyTextItemMinWidth = shortcutsKeyView.getMeasuredHeight();
        // Needed to be able to scale the image items to the same height as the text items.
        final int shortcutKeyIconItemHeightWidth = shortcutsKeyView.getMeasuredHeight()
                - shortcutsKeyView.getPaddingTop()
                - shortcutsKeyView.getPaddingBottom();
        keyboardShortcutsLayout.removeAllViews();

        // Search if user's input is contained in any shortcut groups.
        if (mQueryString != null) {
            for (int i = 0; i < mFullShortsGroup.size(); i++) {
                mKeySearchResultMap.put(i, false);
                for (KeyboardShortcutMultiMappingGroup group : mFullShortsGroup.get(i)) {
                    for (ShortcutMultiMappingInfo info : group.getItems()) {
                        String itemLabel = info.getLabel().toString();
                        if (itemLabel.toUpperCase(Locale.getDefault()).contains(
                                mQueryString.toUpperCase(Locale.getDefault()))) {
                            mKeySearchResultMap.put(i, true);
                            break;
                        }
                    }
                }
            }
        }

        // Set default color for the non-focus categories.
        for (int i = 0; i < mKeySearchResultMap.size(); i++) {
            if (mKeySearchResultMap.get(i)) {
                mFullButtonList.get(i).setVisibility(View.VISIBLE);
                setButtonFocusColor(i, false);
            } else {
                mFullButtonList.get(i).setVisibility(View.GONE);
            }
        }

        // Move the focus to the suitable category.
        if (mFullButtonList.get(mCurrentCategoryIndex).getVisibility() == View.GONE) {
            for (int i = 0; i < mKeySearchResultMap.size(); i++) {
                if (mKeySearchResultMap.get(i)) {
                    setCurrentCategoryIndex(i);
                    break;
                }
            }
        }

        // Set color for the current focus category
        setButtonFocusColor(mCurrentCategoryIndex, true);

        // Load shortcuts for current focus category.
        List<KeyboardShortcutMultiMappingGroup> keyboardShortcutMultiMappingGroups =
                mFullShortsGroup.get(mCurrentCategoryIndex);

        int keyboardShortcutGroupsSize = keyboardShortcutMultiMappingGroups.size();
        List<Boolean> groupSearchResult = new ArrayList<>();
        for (int i = 0; i < keyboardShortcutGroupsSize; i++) {
            View separator = inflater.inflate(
                    R.layout.keyboard_shortcuts_category_short_separator,
                    keyboardShortcutsLayout,
                    false);

            // If there are more than one category, add separators among categories.
            if (i > 0) {
                keyboardShortcutsLayout.addView(separator);
            }

            List<Boolean> itemSearchResult = new ArrayList<>();
            KeyboardShortcutMultiMappingGroup categoryGroup =
                    keyboardShortcutMultiMappingGroups.get(i);
            TextView categoryTitle = (TextView) inflater.inflate(
                    R.layout.keyboard_shortcuts_category_title, keyboardShortcutsLayout, false);
            categoryTitle.setText(categoryGroup.getCategory());
            keyboardShortcutsLayout.addView(categoryTitle);
            LinearLayout shortcutContainer = (LinearLayout) inflater.inflate(
                    R.layout.keyboard_shortcuts_container, keyboardShortcutsLayout, false);
            final int itemsSize = categoryGroup.getItems().size();
            for (int j = 0; j < itemsSize; j++) {
                ShortcutMultiMappingInfo keyGroupInfo = categoryGroup.getItems().get(j);

                if (mQueryString != null) {
                    String shortcutLabel =
                            keyGroupInfo.getLabel().toString().toUpperCase(Locale.getDefault());
                    String queryString = mQueryString.toUpperCase(Locale.getDefault());
                    if (!shortcutLabel.contains(queryString)) {
                        itemSearchResult.add(j, false);
                        continue;
                    } else {
                        itemSearchResult.add(j, true);
                    }
                }

                View shortcutView = inflater.inflate(R.layout.keyboard_shortcut_app_item,
                        shortcutContainer, false);
                TextView shortcutKeyword =
                        shortcutView.findViewById(R.id.keyboard_shortcuts_keyword);
                shortcutKeyword.setText(keyGroupInfo.getLabel());

                if (keyGroupInfo.getIcon() != null) {
                    ImageView shortcutIcon =
                            shortcutView.findViewById(R.id.keyboard_shortcuts_icon);
                    shortcutIcon.setImageIcon(keyGroupInfo.getIcon());
                    shortcutIcon.setVisibility(View.VISIBLE);
                    RelativeLayout.LayoutParams lp =
                            (RelativeLayout.LayoutParams) shortcutKeyword.getLayoutParams();
                    lp.removeRule(RelativeLayout.ALIGN_PARENT_START);
                    shortcutKeyword.setLayoutParams(lp);
                }

                ViewGroup shortcutItemsContainer =
                        shortcutView.findViewById(R.id.keyboard_shortcuts_item_container);
                final int keyGroupItemsSize = keyGroupInfo.getShortcutKeyGroups().size();
                for (int p = 0; p < keyGroupItemsSize; p++) {
                    KeyboardShortcutInfo keyboardShortcutInfo =
                            keyGroupInfo.getShortcutKeyGroups().get(p).getKeyboardShortcutInfo();
                    String complexCommand =
                            keyGroupInfo.getShortcutKeyGroups().get(p).getComplexCommand();

                    if (complexCommand == null) {
                        List<StringDrawableContainer> shortcutKeys =
                                getHumanReadableShortcutKeys(keyboardShortcutInfo);
                        if (shortcutKeys == null) {
                            // Ignore shortcuts we can't display keys for.
                            Log.w(TAG, "Keyboard Shortcut contains unsupported keys, skipping.");
                            continue;
                        }
                        final int shortcutKeysSize = shortcutKeys.size();
                        for (int k = 0; k < shortcutKeysSize; k++) {
                            StringDrawableContainer shortcutRepresentation = shortcutKeys.get(k);
                            if (shortcutRepresentation.mDrawable != null) {
                                ImageView shortcutKeyIconView = (ImageView) inflater.inflate(
                                        R.layout.keyboard_shortcuts_key_icon_view,
                                        shortcutItemsContainer,
                                        false);
                                shortcutKeyIconView.setImageDrawable(
                                        shortcutRepresentation.mDrawable);
                                // Once the view has been measured, scale and position the icon in
                                // the center.
                                shortcutKeyIconView.post(() -> {
                                    Drawable d = shortcutKeyIconView.getDrawable();

                                    float newSize = mContext.getResources().getDimensionPixelSize(
                                            R.dimen.ksh_icon_scaled_size);
                                    int viewWidth = shortcutKeyIconView.getWidth();
                                    int viewHeight = shortcutKeyIconView.getHeight();
                                    float scaleFactor = newSize / d.getIntrinsicWidth();
                                    // Assumes that top/bottom and left/right padding are equal.
                                    int paddingHorizontal =  shortcutKeyIconView.getPaddingLeft();
                                    int paddingVertical =  shortcutKeyIconView.getPaddingTop();

                                    Matrix m = new Matrix();
                                    m.postScale(scaleFactor, scaleFactor);
                                    m.postTranslate(
                                            (viewWidth - newSize) / 2 - paddingHorizontal,
                                            (viewHeight - newSize) / 2 - paddingVertical);
                                    shortcutKeyIconView.setImageMatrix(m);
                                });
                                shortcutKeyIconView.setImportantForAccessibility(
                                        IMPORTANT_FOR_ACCESSIBILITY_YES);
                                shortcutKeyIconView.setAccessibilityDelegate(
                                        new ShortcutKeyAccessibilityDelegate(
                                                shortcutRepresentation.mString));
                                shortcutItemsContainer.addView(shortcutKeyIconView);
                            } else if (shortcutRepresentation.mString != null) {
                                TextView shortcutKeyTextView = (TextView) inflater.inflate(
                                        R.layout.keyboard_shortcuts_key_view,
                                        shortcutItemsContainer,
                                        false);
                                shortcutKeyTextView.setMinimumWidth(shortcutKeyTextItemMinWidth);
                                shortcutKeyTextView.setText(shortcutRepresentation.mString);
                                shortcutKeyTextView.setAccessibilityDelegate(
                                        new ShortcutKeyAccessibilityDelegate(
                                                shortcutRepresentation.mString));
                                shortcutItemsContainer.addView(shortcutKeyTextView);
                            }
                        }
                    } else {
                        TextView shortcutKeyTextView = (TextView) inflater.inflate(
                                R.layout.keyboard_shortcuts_key_view,
                                shortcutItemsContainer,
                                false);
                        shortcutKeyTextView.setMinimumWidth(shortcutKeyTextItemMinWidth);
                        shortcutKeyTextView.setText(complexCommand);
                        shortcutKeyTextView.setAccessibilityDelegate(
                                new ShortcutKeyAccessibilityDelegate(complexCommand));
                        shortcutItemsContainer.addView(shortcutKeyTextView);
                    }

                    if (p < keyGroupItemsSize - 1) {
                        TextView shortcutKeyTextView = (TextView) inflater.inflate(
                                R.layout.keyboard_shortcuts_key_separator_view,
                                shortcutItemsContainer,
                                false);
                        shortcutItemsContainer.addView(shortcutKeyTextView);
                    }
                }
                shortcutContainer.addView(shortcutView);
            }

            if (!groupSearchResult.isEmpty() && !groupSearchResult.get(i - 1)) {
                keyboardShortcutsLayout.removeView(separator);
            }

            if (!itemSearchResult.isEmpty() && !itemSearchResult.contains(true)) {
                // No results, so remove the category title and separator
                keyboardShortcutsLayout.removeView(categoryTitle);
                keyboardShortcutsLayout.removeView(separator);
                groupSearchResult.add(false);
                if (i == keyboardShortcutGroupsSize - 1 && !groupSearchResult.contains(true)) {
                    // show "No shortcut found"
                    mNoSearchResults.setVisibility(View.VISIBLE);
                }
                continue;
            }
            groupSearchResult.add(true);
            mNoSearchResults.setVisibility(View.GONE);
            keyboardShortcutsLayout.addView(shortcutContainer);
        }
    }

    private List<StringDrawableContainer> getHumanReadableShortcutKeys(KeyboardShortcutInfo info) {
        List<StringDrawableContainer> shortcutKeys = getHumanReadableModifiers(info);
        if (shortcutKeys == null) {
            return null;
        }
        String shortcutKeyString = null;
        Drawable shortcutKeyDrawable = null;
        if (info.getBaseCharacter() > Character.MIN_VALUE) {
            shortcutKeyString = String.valueOf(info.getBaseCharacter())
                    .toUpperCase(Locale.getDefault());
        } else if (mSpecialCharacterNames.get(info.getKeycode()) != null) {
            shortcutKeyString = mSpecialCharacterNames.get(info.getKeycode());
        } else {
            // Special case for shortcuts with no base key or keycode.
            if (info.getKeycode() == KeyEvent.KEYCODE_UNKNOWN) {
                return shortcutKeys;
            }
            char displayLabel = mKeyCharacterMap.getDisplayLabel(info.getKeycode());
            if (displayLabel != 0) {
                shortcutKeyString = String.valueOf(displayLabel);
            } else {
                displayLabel = mBackupKeyCharacterMap.getDisplayLabel(info.getKeycode());
                if (displayLabel != 0) {
                    shortcutKeyString = String.valueOf(displayLabel);
                } else {
                    return null;
                }
            }
        }

        if (shortcutKeyString != null) {
            shortcutKeys.add(new StringDrawableContainer(shortcutKeyString, shortcutKeyDrawable));
        } else {
            Log.w(TAG, "Keyboard Shortcut does not have a text representation, skipping.");
        }

        return shortcutKeys;
    }

    private List<StringDrawableContainer> getHumanReadableModifiers(KeyboardShortcutInfo info) {
        final List<StringDrawableContainer> shortcutKeys = new ArrayList<>();
        int modifiers = info.getModifiers();
        if (modifiers == 0) {
            return shortcutKeys;
        }
        for (int supportedModifier : mModifierList) {
            if ((modifiers & supportedModifier) != 0) {
                shortcutKeys.add(new StringDrawableContainer(
                        mModifierNames.get(supportedModifier),
                        mModifierDrawables.get(supportedModifier)));
                modifiers &= ~supportedModifier;
            }
        }
        if (modifiers != 0) {
            // Remaining unsupported modifiers, don't show anything.
            return null;
        }
        return shortcutKeys;
    }

    private final class ShortcutKeyAccessibilityDelegate extends AccessibilityDelegate {
        private String mContentDescription;

        ShortcutKeyAccessibilityDelegate(String contentDescription) {
            mContentDescription = contentDescription;
        }

        @Override
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            if (mContentDescription != null) {
                info.setContentDescription(mContentDescription.toLowerCase(Locale.getDefault()));
            }
        }
    }

    private static final class StringDrawableContainer {
        @NonNull
        public String mString;
        @Nullable
        public Drawable mDrawable;

        StringDrawableContainer(String string, Drawable drawable) {
            mString = string;
            mDrawable = drawable;
        }
    }

    private void setDialogScreenSize() {
        Window window = mKeyboardShortcutsBottomSheetDialog.getWindow();
        Display display = mWindowManager.getDefaultDisplay();
        WindowManager.LayoutParams lp =
                mKeyboardShortcutsBottomSheetDialog.getWindow().getAttributes();
        if (mContext.getResources().getConfiguration().orientation
                == Configuration.ORIENTATION_PORTRAIT) {
            lp.width = (int) (display.getWidth() * 0.8);
            lp.height = (int) (display.getHeight() * 0.8);
        } else {
            lp.width = (int) (display.getWidth() * 0.7);
            lp.height = (int) (display.getHeight() * 0.95);
        }
        window.setGravity(Gravity.BOTTOM);
        window.setAttributes(lp);
    }

    private void setCurrentCategoryIndex(int index) {
        mCurrentCategoryIndex = index;
    }

    private void setButtonsDefaultStatus(View keyboardShortcutsView) {
        mButtonSystem = keyboardShortcutsView.findViewById(R.id.shortcut_system);
        mButtonInput = keyboardShortcutsView.findViewById(R.id.shortcut_input);
        mButtonOpenApps = keyboardShortcutsView.findViewById(R.id.shortcut_open_apps);
        mButtonSpecificApp = keyboardShortcutsView.findViewById(R.id.shortcut_specific_app);

        LinearLayout shortcutsContainer = keyboardShortcutsView.findViewById(
                R.id.keyboard_shortcuts_container);

        mButtonSystem.setOnClickListener(v -> {
            setCurrentCategoryIndex(SHORTCUT_SYSTEM_INDEX);
            populateKeyboardShortcutSearchList(shortcutsContainer);
            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                    R.string.keyboard_shortcut_a11y_filter_system));
        });

        mButtonInput.setOnClickListener(v -> {
            setCurrentCategoryIndex(SHORTCUT_INPUT_INDEX);
            populateKeyboardShortcutSearchList(shortcutsContainer);
            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                    R.string.keyboard_shortcut_a11y_filter_input));
        });

        mButtonOpenApps.setOnClickListener(v -> {
            setCurrentCategoryIndex(SHORTCUT_OPENAPPS_INDEX);
            populateKeyboardShortcutSearchList(shortcutsContainer);
            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                    R.string.keyboard_shortcut_a11y_filter_open_apps));
        });

        mButtonSpecificApp.setOnClickListener(v -> {
            setCurrentCategoryIndex(SHORTCUT_SPECIFICAPP_INDEX);
            populateKeyboardShortcutSearchList(shortcutsContainer);
            shortcutsContainer.setAccessibilityPaneTitle(mContext.getString(
                    R.string.keyboard_shortcut_a11y_filter_current_app));
        });

        mFullButtonList.add(mButtonSystem);
        mFullButtonList.add(mButtonInput);
        mFullButtonList.add(mButtonOpenApps);
        mFullButtonList.add(mButtonSpecificApp);
    }

    private void resetCurrentAppButton() {
        if (mButtonSpecificApp == null) {
            return;
        }
        mButtonSpecificApp.setText(
                mContext.getString(R.string.keyboard_shortcut_search_category_current_app));
        // TODO(b/325252986): Reset icon once the icon is implemented
    }

    private void populateCurrentAppButton() {
        if (mButtonSpecificApp == null) {
            return;
        }
        if (mCurrentAppPackageName != null) {
            final int userId = mContext.getUserId();
            try {
                PackageManager pmUser = CentralSurfaces.getPackageManagerForUser(
                        mContext,
                        userId);
                ApplicationInfo appInfo = pmUser.getApplicationInfoAsUser(
                        mCurrentAppPackageName.toString(),
                        0,
                        userId);
                // According to the API, we will always get a label
                mButtonSpecificApp.setText(pmUser.getApplicationLabel(appInfo));
                // TODO(b/325252986): Show icon once it has been defined
            } catch (NameNotFoundException e) {
                Log.e(TAG, "Package name not found", e);
                resetCurrentAppButton();
            }
        } else {
            resetCurrentAppButton();
        }
    }

    private void setButtonFocusColor(int i, boolean isFocused) {
        if (isFocused) {
            mFullButtonList.get(i).setTextColor(getColorOfTextColorOnAccent());
            mFullButtonList.get(i).setBackground(
                    mContext.getDrawable(R.drawable.shortcut_button_focus_colored));
        } else {
            // Default color
            mFullButtonList.get(i).setTextColor(getColorOfTextColorSecondary());
            mFullButtonList.get(i).setBackground(
                    mContext.getDrawable(R.drawable.shortcut_button_colored));
        }
    }

    private int getColorOfTextColorOnAccent() {
        return mContext.getColor(com.android.internal.R.color.materialColorOnPrimary);
    }

    private int getColorOfTextColorSecondary() {
        return mContext.getColor(com.android.internal.R.color.materialColorOnSurface);
    }

    // Create the new data structure for handling the N-to-1 key mapping and other complex case.
    private static class KeyboardShortcutMultiMappingGroup {
        private final CharSequence mCategory;
        private List<ShortcutMultiMappingInfo> mItems;

        KeyboardShortcutMultiMappingGroup(
                CharSequence category, List<ShortcutMultiMappingInfo> items) {
            mCategory = category;
            mItems = items;
        }

        void addItem(ShortcutMultiMappingInfo item) {
            mItems.add(item);
        }

        CharSequence getCategory() {
            return mCategory;
        }

        List<ShortcutMultiMappingInfo> getItems() {
            return mItems;
        }
    }

    private static class ShortcutMultiMappingInfo {
        private final CharSequence mLabel;
        private final Icon mIcon;
        private List<ShortcutKeyGroup> mShortcutKeyGroups;

        ShortcutMultiMappingInfo(
                CharSequence label, Icon icon, List<ShortcutKeyGroup> shortcutKeyGroups) {
            mLabel = label;
            mIcon = icon;
            mShortcutKeyGroups = shortcutKeyGroups;
        }

        ShortcutMultiMappingInfo(KeyboardShortcutInfo info) {
            mLabel = info.getLabel();
            mIcon = info.getIcon();
            mShortcutKeyGroups = new ArrayList<>(
                Arrays.asList(new ShortcutKeyGroup(info, null))
            );
        }

        CharSequence getLabel() {
            return mLabel;
        }

        Icon getIcon() {
            return mIcon;
        }

        void addShortcutKeyGroup(ShortcutKeyGroup group) {
            mShortcutKeyGroups.add(group);
        }

        List<ShortcutKeyGroup> getShortcutKeyGroups() {
            return mShortcutKeyGroups;
        }
    }

    private static class ShortcutKeyGroup {
        private final KeyboardShortcutInfo mKeyboardShortcutInfo;
        private final String mComplexCommand;

        ShortcutKeyGroup(KeyboardShortcutInfo keyboardShortcutInfo, String complexCommand) {
            mKeyboardShortcutInfo = keyboardShortcutInfo;
            mComplexCommand = complexCommand;
        }

        // To be compatible with the original functions, keep KeyboardShortcutInfo in here.
        KeyboardShortcutInfo getKeyboardShortcutInfo() {
            return mKeyboardShortcutInfo;
        }

        // In some case, the shortcut is a complex description not a N-to-1 key mapping.
        String getComplexCommand() {
            return mComplexCommand;
        }
    }

    private static PackageInfo getAssistPackageInfo(
            Context context, IPackageManager packageManager, int userId) {
        AssistUtils assistUtils = new AssistUtils(context);
        ComponentName assistComponent = assistUtils.getAssistComponentForUser(userId);
        // Not all devices have an assist component.
        PackageInfo assistPackageInfo = null;
        if (assistComponent != null) {
            try {
                assistPackageInfo = packageManager.getPackageInfo(
                        assistComponent.getPackageName(), 0, userId);
            } catch (RemoteException e) {
                Log.e(TAG, "PackageManagerService is dead");
            }
        }
        return assistPackageInfo;
    }
}
