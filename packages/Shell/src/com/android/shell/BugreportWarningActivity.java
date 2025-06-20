/*
 * Copyright (C) 2013 The Android Open Source Project
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

package com.android.shell;

import static com.android.shell.BugreportPrefs.getWarningState;
import static com.android.shell.BugreportPrefs.setWarningState;
import static com.android.shell.BugreportProgressService.sendShareIntent;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.WindowManager;
import android.widget.CheckBox;

import com.android.internal.app.AlertActivity;
import com.android.internal.app.AlertController;

/**
 * Dialog that warns about contents of a bugreport.
 */
public class BugreportWarningActivity extends AlertActivity
        implements DialogInterface.OnClickListener {

    private Intent mSendIntent;
    private CheckBox mConfirmRepeat;

    @Override
    public void onCreate(Bundle icicle) {
        super.onCreate(icicle);

        // Don't allow overlay windows.
        getWindow().addSystemFlags(
                WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);

        mSendIntent = getIntent().getParcelableExtra(Intent.EXTRA_INTENT);

        if (mSendIntent != null) {
            // We need to touch the extras to unpack them so they get migrated to
            // ClipData correctly.
            mSendIntent.hasExtra(Intent.EXTRA_STREAM);
        }

        final AlertController.AlertParams ap = mAlertParams;
        ap.mView = LayoutInflater.from(this).inflate(R.layout.confirm_repeat, null);
        ap.mPositiveButtonText = getString(android.R.string.ok);
        ap.mNegativeButtonText = getString(android.R.string.cancel);
        ap.mPositiveButtonListener = this;
        ap.mNegativeButtonListener = this;

        mConfirmRepeat = (CheckBox) ap.mView.findViewById(android.R.id.checkbox);

        int bugreportStateUnknown = getResources().getInteger(
                com.android.internal.R.integer.bugreport_state_unknown);
        int bugreportStateHide = getResources().getInteger(
                com.android.internal.R.integer.bugreport_state_hide);
        int bugreportStateShow = getResources().getInteger(
                com.android.internal.R.integer.bugreport_state_show);

        final int state = getWarningState(this, bugreportStateUnknown);
        final boolean checked;
        if (Build.IS_USER) {
            checked = state == bugreportStateHide; // Only checks if specifically set to.
        } else {
            checked = state != bugreportStateShow; // Checks by default.
        }
        mConfirmRepeat.setChecked(checked);

        setupAlert();
    }

    @Override
    public void onClick(DialogInterface dialog, int which) {
        int bugreportStateHide = getResources().getInteger(
                com.android.internal.R.integer.bugreport_state_hide);
        int bugreportStateShow = getResources().getInteger(
                com.android.internal.R.integer.bugreport_state_show);
        if (which == AlertDialog.BUTTON_POSITIVE) {
            // Remember confirm state, and launch target
            setWarningState(this, mConfirmRepeat.isChecked() ? bugreportStateHide
                    : bugreportStateShow);
            if (mSendIntent != null) {
                sendShareIntent(this, mSendIntent);
            }
        }

        finish();
    }
}
