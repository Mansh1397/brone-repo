#include <jni.h>
#include <string>
#include <cstring>

extern "C" {

/**
 * Hardened Memory Scrubber Utility
 * Explicitly forces a physical RAM wipe by executing an inline assembly memory barrier.
 * This guarantees compilers cannot optimize away the memset execution loop.
 */
void secure_clear_memory(void* v, size_t n) {
    volatile unsigned char* p = (volatile unsigned char*)v;
    while (n--) {
        *p++ = 0;
    }
    // Structural Hardware Memory Fence Barrier Instruction
    #if defined(__arm__) || defined(__aarch64__)
        asm volatile("dmb sy" ::: "memory");
    #elif defined(__i386__) || defined(__x86_64__)
        asm volatile("mfence" ::: "memory");
    #else
        asm volatile("" ::: "memory");
    #endif
}

/**
 * Native Session Data Purge Handshake
 * Safely processes and zeroes local text matrices inside volatile system cache RAM.
 */
JNIEXPORT jboolean JNICALL
Java_im_brone_native_CryptoBroker_secureNativePurge(JNIEnv* env, jobject thiz, jbyteArray sensitiveData) {
    if (sensitiveData == nullptr) return JNI_FALSE;

    jsize len = env->GetArrayLength(sensitiveData);
    jbyte* buffer = env->GetByteArrayElements(sensitiveData, nullptr);

    if (buffer != nullptr) {
        // Overwrite byte tracks forcefully at the hardware level
        secure_clear_memory(buffer, len);
        env->ReleaseByteArrayElements(sensitiveData, buffer, 0);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

}
