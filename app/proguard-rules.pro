# ProGuard / R8 optimization rules for TravonetWG

# Keep JNI / GoBackend entry points
-keepclassmembers class * {
    native <methods>;
}

-keep class org.travonet.backend.** { *; }
-keep class com.wireguard.android.backend.** { *; }
-keep class org.amnezia.vpn.protocol.amneziawg.** { *; }

# Keep data models used in JSON serialization (SharedPreferences & UAPI)
-keep class com.travonet.wireguard.model.** { *; }
-keep class com.travonet.wireguard.parser.** { *; }
-keep class com.travonet.wireguard.core.** { *; }
-keep class com.freevpn.** { *; }
-keep interface com.freevpn.** { *; }

# Compose rules
-keepattributes *Annotation*,InnerClasses,EnclosingMethod
-dontwarn java.lang.ClassValue
