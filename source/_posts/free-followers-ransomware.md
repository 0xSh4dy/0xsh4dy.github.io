---
title: Reversing Free Followers (Ransomware)
date: 2023-05-30
subtitle: 
tags: [android,ransomware,malware,mobile]
comments: true
---

In this post, I will provide an in-depth technical analysis of the malicious Android application known as "Free Followers," specifically focusing on its ransomware functionality.

## APK Metadata
---
`Malware sample`: [Malware bazaar](https://bazaar.abuse.ch/download/5251a356421340a45c8dc6d431ef8a8cbca4078a0305a87f4fbd552e9fc0793e/)
<br>
`MD5`: 2ddbc785cd696041c5b0c3bd1a8af552
<br>
`SHA256`: 5251a356421340a45c8dc6d431ef8a8cbca4078a0305a87f4fbd552e9fc0793e
<br>
`SHA1`: 1269636a5197ee7a1402e406c91177bf6a149652
<br>
`File Size`: 2.7 MB
<br>
`CRC32`: 7cd1fa65
<br>
`Package Name`: com.XPhantom.id

---

## Android Manifest
We can recover the manifest by extracting and decoding the contents of the apk using [apktool](https://github.com/iBotPeaches/Apktool).
```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="23" android:compileSdkVersionCodename="6.0-2438415" android:installLocation="internalOnly" package="com.XPhantom.id" platformBuildVersionCode="23" platformBuildVersionName="6.0-2438415">
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.SET_WALLPAPER"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGE"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <activity android:label="@string/app_name" android:name="com.XPhantom.id.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.INFO"/>
            </intent-filter>
        </activity>
        <service android:enabled="true" android:name="com.XPhantom.id.MyService"/>
        <receiver android:enabled="true" android:name="com.XPhantom.id.BootReceiver" android:permission="android.permission.RECEIVE_BOOT_COMPLETED">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.QUICKBOOT_POWERON"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```
The manifest says that there's one activity, one service and one receiver. Apart from that, the required permissions seem to be too much for a `free followers` application. Let's decompile the apk using [JADX](https://github.com/skylot/jadx).

![](/images/rev/ff/ff-01.png)

It starts a service using `startService()` as soon as the application is run. A service that is started using the `startService()` method continues to run even if the component that started it is destroyed. Apart from that, there's one more way in which the application starts `MyService` which is via the one and only broadcast receiver `com.XPhantom.id.BootReceiver` present in this application.
![](/images/rev/ff/ff-02.png)

`android.intent.action.BOOT_COMPLETED` is a broadcast action that is sent by the system when the device completes the booting process and becomes fully operational. It starts the service `MainService` when the device completes the booting process. Now, let's proceed with analyzing the service.

![](/images/rev/ff/ff-03.png)

It renders a new view on the screen that looks like
![](/images/rev/ff/ff-04.png)
This view will also be shown after rebooting the device because the service `MainService` is also started at system startup. The password to remove this view is `Abdullah@` which is checked right here.
```java
public void onClick(View view) {
    if (this.this$0.e1.getText().toString().equals("Abdullah@")) {
        this.this$0.windowManager.removeView(this.this$0.myView);
        try {
            this.this$0.context.startService(new Intent(this.this$0.context, Class.forName("com.XPhantom.id.MyService")));
            return;
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
    }
    this.this$0.e1.setText("");
}
```
Entering this password into the prompt removes the overlapping view.
