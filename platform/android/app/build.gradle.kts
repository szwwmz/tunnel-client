// Android 外壳构建脚本（最小可用）
//
// 说明：
//  - 核心库与 JNI 桥都由根目录 CMakeLists.txt 编译（ANDROID 分支产出 libvpncore_jni.so）；
//  - OpenSSL 需自行交叉编译后放入 src/main/jniLibs/<abi>/，并在 CMake 中提供 include/lib 路径，
//    或改用 mbedTLS 后端（vpn_tls.h 已抽象）。
plugins {
    id("com.android.application")
}

android {
    compileSdk = 34
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "com.example.vpnclient"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf("-DVPN_BUILD_TESTS=OFF", "-DCMAKE_BUILD_TYPE=Release")
                // 若 OpenSSL 为自行编译，取消注释并改成实际路径：
                // arguments += listOf("-DOPENSSL_ROOT_DIR=$projectDir/../../../../third_party/openssl-android/arm64-v8a")
            }
        }
    }

    externalNativeBuild {
        cmake {
            // 直接复用仓库根目录的 CMakeLists.txt（ANDROID 分支构建 vpncore_jni）
            path = file("../../../../CMakeLists.txt")
            version = "3.22.1+"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")
}

dependencies {
    // 骨架只用系统 API 与纯代码 UI，无需 androidx 依赖
}
