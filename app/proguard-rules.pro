# Keep native method names — exp.c binds to them via JNI.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the app package: exp.c does FindClass("com/worldmargin/dfroot/IReporter") and
# view binding generates com.worldmargin.dfroot.databinding.* referenced reflectively.
-keep class com.worldmargin.dfroot.** { *; }
-keep class com.worldmargin.dfroot.databinding.** { *; }

# Vendored Termux terminal: com.termux.view.TerminalView is inflated from XML by
# class name and com.termux.terminal.JNI binds native methods.
-keep class com.termux.** { *; }

# Keep click-handler wiring used by Material components.
-keepclassmembers class * {
    void *Click(...);
}

-dontwarn com.worldmargin.dfroot.**