if(NOT ANDROID_NDK_TOOLCHAIN_INCLUDED)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DTARGET_OS_LINUX -std=c++11")
  set(LIB_THREAD "pthread" "dl" "rt" "m")
else()
  set(LIB_THREAD "stdc++" "z" "log")
endif()
