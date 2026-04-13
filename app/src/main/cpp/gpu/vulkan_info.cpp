#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <link.h>
#include <string.h>

// Vulkan headers are available in Android NDK
#include <vulkan/vulkan.h>

#define LOG_TAG "VulkanNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static bool g_target_found = false;
static const char* g_target_lib = nullptr;

static int dl_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (g_target_lib == nullptr) return 0;

    const char* name = info->dlpi_name;
    if (name == nullptr || name[0] == '\0') return 0;

    if (strstr(name, g_target_lib) != nullptr) {
        g_target_found = true;
        return 1; // stop iteration
    }
    return 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_qpdb_env_check_utils_GpuNativeUtil_nativeIsSoLoaded(
        JNIEnv* env,
        jclass clazz,
        jstring soName) {
    const char* target = env->GetStringUTFChars(soName, nullptr);
    if (!target) return JNI_FALSE;

    g_target_lib = target;
    g_target_found = false;

    dl_iterate_phdr(dl_callback, nullptr);

    env->ReleaseStringUTFChars(soName, target);
    return g_target_found ? JNI_TRUE : JNI_FALSE;
}

static bool loadVulkanFunctions(void* libvulkan,
                                PFN_vkEnumerateInstanceVersion* outVkEnumerateInstanceVersion,
                                PFN_vkCreateInstance* outVkCreateInstance,
                                PFN_vkDestroyInstance* outVkDestroyInstance,
                                PFN_vkEnumeratePhysicalDevices* outVkEnumeratePhysicalDevices,
                                PFN_vkGetPhysicalDeviceProperties* outVkGetPhysicalDeviceProperties,
                                PFN_vkEnumerateDeviceExtensionProperties* outVkEnumerateDeviceExtensionProperties) {
    *outVkEnumerateInstanceVersion = reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
            dlsym(libvulkan, "vkEnumerateInstanceVersion"));
    *outVkCreateInstance = reinterpret_cast<PFN_vkCreateInstance>(
            dlsym(libvulkan, "vkCreateInstance"));
    *outVkDestroyInstance = reinterpret_cast<PFN_vkDestroyInstance>(
            dlsym(libvulkan, "vkDestroyInstance"));
    *outVkEnumeratePhysicalDevices = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(
            dlsym(libvulkan, "vkEnumeratePhysicalDevices"));
    *outVkGetPhysicalDeviceProperties = reinterpret_cast<PFN_vkGetPhysicalDeviceProperties>(
            dlsym(libvulkan, "vkGetPhysicalDeviceProperties"));
    *outVkEnumerateDeviceExtensionProperties = reinterpret_cast<PFN_vkEnumerateDeviceExtensionProperties>(
            dlsym(libvulkan, "vkEnumerateDeviceExtensionProperties"));

    return *outVkCreateInstance && *outVkDestroyInstance && *outVkEnumeratePhysicalDevices
           && *outVkGetPhysicalDeviceProperties && *outVkEnumerateDeviceExtensionProperties;
}

static VkInstance createVulkanInstance(PFN_vkCreateInstance vkCreateInstance, uint32_t apiVersion) {
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "EnvCheck";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "No Engine";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = apiVersion;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance;
    VkResult result = vkCreateInstance(&createInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        return VK_NULL_HANDLE;
    }
    return instance;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_GpuNativeUtil_nativeGetVulkanInfo(
        JNIEnv* env,
        jclass clazz) {

    void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
    if (!libvulkan) {
        LOGD("libvulkan.so not found");
        return env->NewStringUTF("");
    }

    PFN_vkEnumerateInstanceVersion vkEnumerateInstanceVersion = nullptr;
    PFN_vkCreateInstance vkCreateInstance = nullptr;
    PFN_vkDestroyInstance vkDestroyInstance = nullptr;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = nullptr;
    PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = nullptr;
    PFN_vkEnumerateDeviceExtensionProperties vkEnumerateDeviceExtensionProperties = nullptr;

    if (!loadVulkanFunctions(libvulkan, &vkEnumerateInstanceVersion, &vkCreateInstance, &vkDestroyInstance,
                             &vkEnumeratePhysicalDevices, &vkGetPhysicalDeviceProperties,
                             &vkEnumerateDeviceExtensionProperties)) {
        LOGE("Failed to load required Vulkan functions");
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    uint32_t apiVersion = VK_API_VERSION_1_0;
    if (vkEnumerateInstanceVersion) {
        vkEnumerateInstanceVersion(&apiVersion);
    }

    VkInstance instance = createVulkanInstance(vkCreateInstance, apiVersion);
    if (instance == VK_NULL_HANDLE) {
        LOGE("vkCreateInstance failed");
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        LOGD("No Vulkan physical devices found");
        vkDestroyInstance(instance, nullptr);
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    std::string resultStr;
    for (uint32_t i = 0; i < deviceCount; i++) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(devices[i], &props);

        // Format pipelineCacheUUID (16 bytes)
        char uuidBuf[64];
        snprintf(uuidBuf, sizeof(uuidBuf),
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 props.pipelineCacheUUID[0], props.pipelineCacheUUID[1],
                 props.pipelineCacheUUID[2], props.pipelineCacheUUID[3],
                 props.pipelineCacheUUID[4], props.pipelineCacheUUID[5],
                 props.pipelineCacheUUID[6], props.pipelineCacheUUID[7],
                 props.pipelineCacheUUID[8], props.pipelineCacheUUID[9],
                 props.pipelineCacheUUID[10], props.pipelineCacheUUID[11],
                 props.pipelineCacheUUID[12], props.pipelineCacheUUID[13],
                 props.pipelineCacheUUID[14], props.pipelineCacheUUID[15]);

        char buf[512];
        snprintf(buf, sizeof(buf),
                 "[%u] name=%s; vendorID=0x%x; deviceID=0x%x; driverVersion=0x%x; type=%u; apiVersion=%u.%u.%u; pipelineCacheUUID=%s",
                 i,
                 props.deviceName,
                 props.vendorID,
                 props.deviceID,
                 props.driverVersion,
                 props.deviceType,
                 VK_VERSION_MAJOR(props.apiVersion),
                 VK_VERSION_MINOR(props.apiVersion),
                 VK_VERSION_PATCH(props.apiVersion),
                 uuidBuf);

        if (!resultStr.empty()) {
            resultStr += " | ";
        }
        resultStr += buf;

        LOGI("Vulkan GPU[%u]: %s, UUID=%s", i, props.deviceName, uuidBuf);
    }

    vkDestroyInstance(instance, nullptr);
    dlclose(libvulkan);

    return env->NewStringUTF(resultStr.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_GpuNativeUtil_nativeGetVulkanExtensions(
        JNIEnv* env,
        jclass clazz) {

    void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
    if (!libvulkan) {
        LOGD("libvulkan.so not found");
        return env->NewStringUTF("");
    }

    PFN_vkEnumerateInstanceVersion vkEnumerateInstanceVersion = nullptr;
    PFN_vkCreateInstance vkCreateInstance = nullptr;
    PFN_vkDestroyInstance vkDestroyInstance = nullptr;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = nullptr;
    PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = nullptr;
    PFN_vkEnumerateDeviceExtensionProperties vkEnumerateDeviceExtensionProperties = nullptr;

    if (!loadVulkanFunctions(libvulkan, &vkEnumerateInstanceVersion, &vkCreateInstance, &vkDestroyInstance,
                             &vkEnumeratePhysicalDevices, &vkGetPhysicalDeviceProperties,
                             &vkEnumerateDeviceExtensionProperties)) {
        LOGE("Failed to load required Vulkan functions");
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    uint32_t apiVersion = VK_API_VERSION_1_0;
    if (vkEnumerateInstanceVersion) {
        vkEnumerateInstanceVersion(&apiVersion);
    }

    VkInstance instance = createVulkanInstance(vkCreateInstance, apiVersion);
    if (instance == VK_NULL_HANDLE) {
        LOGE("vkCreateInstance failed");
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        LOGD("No Vulkan physical devices found");
        vkDestroyInstance(instance, nullptr);
        dlclose(libvulkan);
        return env->NewStringUTF("");
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    std::string resultStr;
    for (uint32_t i = 0; i < deviceCount; i++) {
        uint32_t extCount = 0;
        vkEnumerateDeviceExtensionProperties(devices[i], nullptr, &extCount, nullptr);

        if (extCount > 0) {
            std::vector<VkExtensionProperties> extensions(extCount);
            vkEnumerateDeviceExtensionProperties(devices[i], nullptr, &extCount, extensions.data());

            if (!resultStr.empty()) {
                resultStr += " | ";
            }
            resultStr += "[GPU";
            resultStr += std::to_string(i);
            resultStr += "] ";

            for (uint32_t j = 0; j < extCount; j++) {
                if (j > 0) resultStr += " ";
                resultStr += extensions[j].extensionName;
            }
        }
    }

    vkDestroyInstance(instance, nullptr);
    dlclose(libvulkan);

    if (resultStr.empty()) {
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(resultStr.c_str());
}
