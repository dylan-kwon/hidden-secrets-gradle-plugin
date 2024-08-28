#include "secrets.hpp"

#include <jni.h>

/* Copyright (c) 2024-present Dylan Kwon
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use,
* copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following
* conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
*/

jobject getApplication(JNIEnv *pEnv) {
    jclass appGlobalsClass = pEnv->FindClass("android/app/AppGlobals");
    jmethodID jGetInitialApplication = pEnv->GetStaticMethodID(appGlobalsClass,"getInitialApplication","()Landroid/app/Application;");
    return pEnv->CallStaticObjectMethod(appGlobalsClass, jGetInitialApplication);
}

jstring getPackageName(JNIEnv *pEnv) {
    jobject applicationObject = getApplication(pEnv);
    jclass contextClass = pEnv->FindClass("android/content/Context");
    jmethodID getPackageNameMethodId = pEnv->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    return static_cast<jstring>(pEnv->CallObjectMethod(applicationObject, getPackageNameMethodId));
}

jstring getKeyHash(JNIEnv *pEnv) {
    // Application
    jobject applicationObject = getApplication(pEnv);

    // PackageName
    jstring packageNameString = getPackageName(pEnv);

    // Context
    jclass contextClass = pEnv->FindClass("android/content/Context");

    // PackageManager
    jmethodID getPackageManagerMethodId = pEnv->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManagerObject = pEnv->CallObjectMethod(applicationObject, getPackageManagerMethodId);
    jclass packageManagerClass = pEnv->GetObjectClass(packageManagerObject);

    // PackageInfo
    jmethodID getPackageInfoMethodId = pEnv->GetMethodID(packageManagerClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject packageInfoObject = pEnv->CallObjectMethod(packageManagerObject, getPackageInfoMethodId, packageNameString, 0x08000000);
    jclass packageInfoClass = pEnv->GetObjectClass(packageInfoObject);

    // SDK Version
    jclass buildClass = pEnv->FindClass("android/os/Build$VERSION");
    jfieldID versionCodeFieldId = pEnv->GetStaticFieldID(buildClass, "SDK_INT", "I");
    jint versionCode = pEnv->GetStaticIntField(buildClass, versionCodeFieldId);

    // Signatures
    jobjectArray signatures;

    if (versionCode >= 28) {
        // SigningInfo
        jfieldID signingInfoFieldId = pEnv->GetFieldID(packageInfoClass, "signingInfo", "Landroid/content/pm/SigningInfo;");
        jobject signingInfoObject = pEnv->GetObjectField(packageInfoObject, signingInfoFieldId);
        jclass signingInfoClass = pEnv->GetObjectClass(signingInfoObject);

        // SigningInfo.hasMultipleSignersBoolean
        jmethodID hasMultipleSignersMethodId = pEnv->GetMethodID(signingInfoClass, "hasMultipleSigners", "()Z");
        jboolean hasMultipleSignersBoolean = pEnv->CallBooleanMethod(signingInfoObject, hasMultipleSignersMethodId);

        if (hasMultipleSignersBoolean) {
            jmethodID getApkContentsSignersMethodId = pEnv->GetMethodID(signingInfoClass, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            signatures = reinterpret_cast<jobjectArray>(pEnv->CallObjectMethod(signingInfoObject, getApkContentsSignersMethodId));
        } else {
            jmethodID getSigningCertificateHistoryMethodId = pEnv->GetMethodID(signingInfoClass, "getSigningCertificateHistory", "()[Landroid/content/pm/Signature;");
            signatures = reinterpret_cast<jobjectArray>(pEnv->CallObjectMethod(signingInfoObject, getSigningCertificateHistoryMethodId));
        }
    } else {
        jfieldID signaturesFieldId = pEnv->GetFieldID(packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");
        signatures = reinterpret_cast<jobjectArray>(pEnv->GetObjectField(packageInfoObject, signaturesFieldId));
    }

    // First Signature
    jobject signatureObject = pEnv->GetObjectArrayElement(signatures, 0);
    jclass signatureClass = pEnv->GetObjectClass(signatureObject);

    // First Signature ByteArray
    jmethodID toByteArrayMethodId = pEnv->GetMethodID(signatureClass, "toByteArray", "()[B");
    jbyteArray signatureByteArray = reinterpret_cast<jbyteArray>(pEnv->CallObjectMethod(signatureObject, toByteArrayMethodId));

    // MessageDigest
    jclass messageDigestClass = pEnv->FindClass("java/security/MessageDigest");
    jmethodID getInstanceMethodId = pEnv->GetStaticMethodID(messageDigestClass,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jobject messageDigestObject = pEnv->CallStaticObjectMethod(messageDigestClass,getInstanceMethodId, pEnv->NewStringUTF("SHA"));

    // MessageDigest Update
    jmethodID updateMethodId = pEnv->GetMethodID(messageDigestClass,"update","([B)V");
    pEnv->CallVoidMethod(messageDigestObject, updateMethodId, signatureByteArray);

    // MessageDigest Digest
    jmethodID digestMethodId = pEnv->GetMethodID(messageDigestClass,"digest","()[B");
    jbyteArray digestByteArray = reinterpret_cast<jbyteArray>(pEnv->CallObjectMethod(messageDigestObject, digestMethodId));

    // Base64
    jclass base64Class = pEnv->FindClass("android/util/Base64");
    jmethodID encodeMethodId = pEnv->GetStaticMethodID(base64Class,"encodeToString","([BI)Ljava/lang/String;");
    jstring base64String = static_cast<jstring>(pEnv->CallStaticObjectMethod(base64Class, encodeMethodId, digestByteArray, 2));

    return base64String;
}

jstring getSignature(JNIEnv* pEnv, jstring packageName) {
    jstring keyHash = getKeyHash(pEnv);

    jclass signatureClass = pEnv->GetObjectClass(keyHash);
    jmethodID concatMethodId = pEnv->GetMethodID(signatureClass, "concat", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring concat = reinterpret_cast<jstring>(pEnv->CallObjectMethod(keyHash, concatMethodId, packageName));

    return concat;
}