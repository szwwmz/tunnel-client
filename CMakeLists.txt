cmake_minimum_required(VERSION 3.16)
project(tunnel-client LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# ---------------------------------------------------------------------------
# 共享核心层：PPP / SSTP / L2TP / PPTP + 加密 + 生命周期编排
# Android 与 Windows 都链接同一个核心库，保证协议与证书策略完全一致
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(VPNCORE_SOURCES
  core/src/vpn_buf.c
  core/src/vpn_capi.c
  core/src/vpn_client.c
  core/src/vpn_config.c
  core/src/vpn_crypto.c
  core/src/vpn_des.c
  core/src/vpn_ike.c
  core/src/vpn_l2tp.c
  core/src/vpn_log.c
  core/src/vpn_md4.c
  core/src/vpn_net.c
  core/src/vpn_platform.c
  core/src/vpn_ppp.c
  core/src/vpn_ppp_auth.c
  core/src/vpn_ppp_frame.c
  core/src/vpn_pptp.c
  core/src/vpn_sstp.c
  core/src/vpn_tls.c
  core/src/vpn_tun.c
)

add_library(vpncore STATIC ${VPNCORE_SOURCES})
target_include_directories(vpncore PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/core/include
  ${CMAKE_CURRENT_SOURCE_DIR}/core/include/vpncore)
target_link_libraries(vpncore PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(vpncore PRIVATE _GNU_SOURCE)
endif()

# 共享库版本（Windows 侧作为 vpncore.dll 使用，Android 侧为 libvpncore.so）
add_library(vpncore_shared SHARED ${VPNCORE_SOURCES})
target_include_directories(vpncore_shared PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/core/include
  ${CMAKE_CURRENT_SOURCE_DIR}/core/include/vpncore)
target_link_libraries(vpncore_shared PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
set_target_properties(vpncore_shared PROPERTIES OUTPUT_NAME vpncore)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(vpncore_shared PRIVATE _GNU_SOURCE)
endif()

# ---------------------------------------------------------------------------
# Linux 桌面 CLI（同时充当跨平台核心的联调工具）
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(vpn-cli cli/main.c)
  target_link_libraries(vpn-cli PRIVATE vpncore)
  install(TARGETS vpn-cli RUNTIME DESTINATION bin)
endif()

# ---------------------------------------------------------------------------
# Android JNI 桥（仅在 NDK 工具链下构建；由 app/build.gradle.kts 调用）
# ---------------------------------------------------------------------------
if(ANDROID)
  add_library(vpncore_jni SHARED platform/android/app/src/main/cpp/vpn_jni.c)
  target_link_libraries(vpncore_jni PRIVATE vpncore log)
  target_compile_options(vpncore_jni PRIVATE -Wno-unused-parameter)
endif()

# ---------------------------------------------------------------------------
# 单元测试
# ---------------------------------------------------------------------------
option(VPN_BUILD_TESTS "Build unit tests" ON)
if(VPN_BUILD_TESTS)
  enable_testing()
  file(GLOB TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.c)
  foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src} ${CMAKE_CURRENT_SOURCE_DIR}/tests/framework.c)
    target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(${test_name} PRIVATE vpncore)
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()

install(TARGETS vpncore_shared LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
