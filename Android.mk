LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)

LOCAL_MODULE := libELFKit_static

LOCAL_SRC_FILES := \
                src/elfkit_common.cc \
                src/elfkit_blinker.cc \
                src/elfkit_mapped_fragment.cc \
                src/elfkit_soinfo.cc \
                src/elfkit_soimage.cc \
                src/elfkit_sofile.cc 

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := -std=c++11

#LOCAL_STATIC_LIBRARIES :=
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -std=c++11 \
                -Werror

include $(BUILD_STATIC_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ELFKit
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cc

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := -std=c++11

LOCAL_STATIC_LIBRARIES := ELFKit_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -std=c++11 \
                -DELFKIT_STANDALONE=0
include $(BUILD_SHARED_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ELFKit.out
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cc

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := -fPIC -pie -std=c++11

LOCAL_STATIC_LIBRARIES := ELFKit_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -std=c++11 \
                -DELFKIT_STANDALONE=1

include $(BUILD_EXECUTABLE)
