package com.freevpn.coreloader

import android.util.Log

interface CoreEventListener {
    fun onCoreEvent(eventType: Int, payload: String)
}

object NativeCoreBridge {
    private const val TAG = "NativeCoreBridge"

    init {
        try {
            System.loadLibrary("core_loader")
            Log.i(TAG, "Native library 'core_loader' loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load 'core_loader' native library", e)
        }
    }

    external fun setCoreEventListener(listener: CoreEventListener?)
    external fun checkNeedsTunNative(corePath: String, configJson: String): Boolean
    external fun startProxyWithCore(corePath: String, configJson: String, tunFd: Int): Boolean
    external fun stopCoreNative(): Boolean
    external fun isProxyRunningNative(): Boolean
    external fun getLastCoreErrorNative(): String
}
