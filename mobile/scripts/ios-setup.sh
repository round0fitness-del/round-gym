#!/usr/bin/env bash
# Runs inside mobile/ after "npx cap add ios". Edit this file (not the workflow) to change iPhone settings.
P=ios/App/App/Info.plist
add(){ /usr/libexec/PlistBuddy -c "Delete :$1" "$P" 2>/dev/null; /usr/libexec/PlistBuddy -c "Add :$1 string $2" "$P"; }
add NSCameraUsageDescription 'لمسح رمز QR عند الدخول'
add NSPhotoLibraryUsageDescription 'لاختيار صورة'
add NSPhotoLibraryAddUsageDescription 'لحفظ الفواتير والملفات'
add NSLocationWhenInUseUsageDescription 'لتسجيل حضور وانصراف الموظفين من داخل النادي'
echo "iOS Info.plist updated"
