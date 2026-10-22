#!/usr/bin/env bash
# Runs inside mobile/ after "npx cap add android". Edit this file (not the workflow) to change Android settings.
set -e
M=android/app/src/main/AndroidManifest.xml
for perm in CAMERA ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION; do
  grep -q "android.permission.$perm\"" "$M" || sed -i "s#</manifest>#    <uses-permission android:name=\"android.permission.$perm\" />\n</manifest>#" "$M"
done
grep -q 'android.hardware.location.gps' "$M" || sed -i 's#</manifest>#    <uses-feature android:name="android.hardware.location.gps" android:required="false" />\n</manifest>#' "$M"
sed -i "s/versionCode 1$/versionCode ${GITHUB_RUN_NUMBER:-1}/; s/versionName \"1.0\"/versionName \"1.0.${GITHUB_RUN_NUMBER:-1}\"/" android/app/build.gradle
echo "Android permissions:"; grep uses-permission "$M"
