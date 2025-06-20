/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.systemui.media;

import android.annotation.Nullable;
import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.database.Cursor;
import android.media.AudioAttributes;
import android.media.IAudioService;
import android.media.IRingtonePlayer;
import android.media.Ringtone;
import android.media.VolumeShaper;
import android.net.Uri;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.provider.MediaStore;
import android.util.Log;

import com.android.systemui.CoreStartable;
import com.android.systemui.dagger.SysUISingleton;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

import javax.inject.Inject;

/**
 * Service that offers to play ringtones by {@link Uri}, since our process has
 * {@link android.Manifest.permission#READ_EXTERNAL_STORAGE}.
 */
@SysUISingleton
public class RingtonePlayer implements CoreStartable {
    private static final String TAG = "RingtonePlayer";
    private static final boolean LOGD = true;
    private final Context mContext;

    // TODO: support Uri switching under same IBinder

    private IAudioService mAudioService;

    private final NotificationPlayer mAsyncPlayer = new NotificationPlayer(TAG);
    private final HashMap<IBinder, Client> mClients = new HashMap<IBinder, Client>();

    @Inject
    public RingtonePlayer(Context context) {
        mContext = context;
    }

    @Override
    public void start() {
        mAsyncPlayer.setUsesWakeLock(mContext);

        mAudioService = IAudioService.Stub.asInterface(
                ServiceManager.getService(Context.AUDIO_SERVICE));
        try {
            mAudioService.setRingtonePlayer(mCallback);
        } catch (RemoteException e) {
            Log.e(TAG, "Problem registering RingtonePlayer: " + e);
        }
    }

    /**
     * Represents an active remote {@link Ringtone} client.
     */
    private class Client implements IBinder.DeathRecipient {
        private final IBinder mToken;
        private final Ringtone mRingtone;

        public Client(IBinder token, Uri uri, UserHandle user, AudioAttributes aa) {
            this(token, uri, user, aa, null);
        }

        Client(IBinder token, Uri uri, UserHandle user, AudioAttributes aa,
                @Nullable VolumeShaper.Configuration volumeShaperConfig) {
            mToken = token;

            mRingtone = new Ringtone(getContextForUser(user), false);
            mRingtone.setAudioAttributesField(aa);
            mRingtone.setUri(uri, volumeShaperConfig);
            mRingtone.createLocalMediaPlayer();
        }

        @Override
        public void binderDied() {
            if (LOGD) Log.d(TAG, "binderDied() token=" + mToken);
            synchronized (mClients) {
                mClients.remove(mToken);
            }
            mRingtone.stop();
        }
    }

    private IRingtonePlayer mCallback = new IRingtonePlayer.Stub() {
        @Override
        public void play(IBinder token, Uri uri, AudioAttributes aa, float volume, boolean looping)
                throws RemoteException {
            playWithVolumeShaping(token, uri, aa, volume, looping, null);
        }
        @Override
        public void playWithVolumeShaping(IBinder token, Uri uri, AudioAttributes aa, float volume,
                boolean looping, @Nullable VolumeShaper.Configuration volumeShaperConfig)
                throws RemoteException {
            if (LOGD) {
                Log.d(TAG, "play(token=" + token + ", uri=" + uri + ", uid="
                        + Binder.getCallingUid() + ")");
            }
            enforceUriUserId(uri);

            Client client;
            synchronized (mClients) {
                client = mClients.get(token);
                if (client == null) {
                    final UserHandle user = Binder.getCallingUserHandle();
                    client = new Client(token, uri, user, aa, volumeShaperConfig);
                    token.linkToDeath(client, 0);
                    mClients.put(token, client);
                }
            }
            client.mRingtone.setLooping(looping);
            client.mRingtone.setVolume(volume);
            client.mRingtone.play();
        }

        @Override
        public void stop(IBinder token) {
            if (LOGD) Log.d(TAG, "stop(token=" + token + ")");
            Client client;
            synchronized (mClients) {
                client = mClients.remove(token);
            }
            if (client != null) {
                client.mToken.unlinkToDeath(client, 0);
                client.mRingtone.stop();
            }
        }

        @Override
        public boolean isPlaying(IBinder token) {
            if (LOGD) Log.d(TAG, "isPlaying(token=" + token + ")");
            Client client;
            synchronized (mClients) {
                client = mClients.get(token);
            }
            if (client != null) {
                return client.mRingtone.isPlaying();
            } else {
                return false;
            }
        }

        @Override
        public void setPlaybackProperties(IBinder token, float volume, boolean looping,
                boolean hapticGeneratorEnabled) {
            Client client;
            synchronized (mClients) {
                client = mClients.get(token);
            }
            if (client != null) {
                client.mRingtone.setVolume(volume);
                client.mRingtone.setLooping(looping);
                client.mRingtone.setHapticGeneratorEnabled(hapticGeneratorEnabled);
            }
            // else no client for token when setting playback properties but will be set at play()
        }

        @Override
        public void playAsync(Uri uri, UserHandle user, boolean looping, AudioAttributes aa,
                float volume) {
            if (LOGD) Log.d(TAG, "playAsync(uri=" + uri + ", user=" + user + ")");
            if (Binder.getCallingUid() != Process.SYSTEM_UID) {
                throw new SecurityException("Async playback only available from system UID.");
            }
            if (UserHandle.ALL.equals(user)) {
                user = UserHandle.SYSTEM;
            }
            mAsyncPlayer.play(getContextForUser(user), uri, looping, aa, volume);
        }

        @Override
        public void stopAsync() {
            if (LOGD) Log.d(TAG, "stopAsync()");
            if (Binder.getCallingUid() != Process.SYSTEM_UID) {
                throw new SecurityException("Async playback only available from system UID.");
            }
            mAsyncPlayer.stop();
        }

        @Override
        public String getTitle(Uri uri) {
            enforceUriUserId(uri);
            final UserHandle user = Binder.getCallingUserHandle();
            return Ringtone.getTitle(getContextForUser(user), uri,
                    false /*followSettingsUri*/, false /*allowRemote*/);
        }

        @Override
        public ParcelFileDescriptor openRingtone(Uri uri) {
            enforceUriUserId(uri);
            final UserHandle user = Binder.getCallingUserHandle();
            final ContentResolver resolver = getContextForUser(user).getContentResolver();

            // Only open the requested Uri if it's a well-known ringtone or
            // other sound from the platform media store, otherwise this opens
            // up arbitrary access to any file on external storage.
            if (uri.toString().startsWith(MediaStore.Audio.Media.EXTERNAL_CONTENT_URI.toString())) {
                try (Cursor c = resolver.query(uri, new String[] {
                        MediaStore.Audio.AudioColumns.IS_RINGTONE,
                        MediaStore.Audio.AudioColumns.IS_ALARM,
                        MediaStore.Audio.AudioColumns.IS_NOTIFICATION
                }, null, null, null)) {
                    if (c.moveToFirst()) {
                        if (c.getInt(0) != 0 || c.getInt(1) != 0 || c.getInt(2) != 0) {
                            try {
                                return resolver.openFileDescriptor(uri, "r");
                            } catch (IOException e) {
                                throw new SecurityException(e);
                            }
                        }
                    }
                }
            }
            throw new SecurityException("Uri is not ringtone, alarm, or notification: " + uri);
        }
    };

    /**
     * Must be called from the Binder calling thread.
     * Ensures caller is from the same userId as the content they're trying to access.
     * @param uri the URI to check
     * @throws SecurityException when in a non-system call and userId in uri differs from the
     *                           caller's userId
     */
    private void enforceUriUserId(Uri uri) throws SecurityException {
        final int uriUserId = ContentProvider.getUserIdFromUri(uri, UserHandle.myUserId());
        // for a non-system call, verify the URI to play belongs to the same user as the caller
        if (UserHandle.isApp(Binder.getCallingUid()) && (UserHandle.myUserId() != uriUserId)) {
            final String errorMessage = "Illegal access to uri=" + uri
                    + " content associated with user=" + uriUserId
                    + ", current userID: " + UserHandle.myUserId();
            if (android.media.audio.Flags.ringtoneUserUriCheck()) {
                throw new SecurityException(errorMessage);
            } else {
                Log.e(TAG, errorMessage, new Exception());
            }
        }
    }

    private Context getContextForUser(UserHandle user) {
        try {
            return mContext.createPackageContextAsUser(mContext.getPackageName(), 0, user);
        } catch (NameNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void dump(PrintWriter pw, String[] args) {
        pw.println("Clients:");
        synchronized (mClients) {
            for (Client client : mClients.values()) {
                pw.print("  mToken=");
                pw.print(client.mToken);
                pw.print(" mUri=");
                pw.println(client.mRingtone.getUri());
            }
        }
    }
}
