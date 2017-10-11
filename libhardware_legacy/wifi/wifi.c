/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#ifdef CONFIG_MEDIATEK_WIFI_BEAM
//by Haman
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>
#include <cutils/sockets.h>
//End 
#endif

#include "hardware_legacy/wifi.h"
#ifdef LIBWPA_CLIENT_EXISTS
#include "libwpa_client/wpa_ctrl.h"
#endif

#define LOG_TAG "WifiHW"
#include "cutils/log.h"
#include "cutils/memory.h"
#include "cutils/misc.h"
#include "cutils/properties.h"
#include "private/android_filesystem_config.h"
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>
#endif

extern int do_dhcp();
extern int ifc_init();
extern void ifc_close();
extern char *dhcp_lasterror();
extern void get_dhcp_info();
extern int init_module(void *, unsigned long, const char *);
extern int delete_module(const char *, unsigned int);
void wifi_close_sockets();

#ifndef LIBWPA_CLIENT_EXISTS
#define WPA_EVENT_TERMINATING "CTRL-EVENT-TERMINATING "
struct wpa_ctrl {};
void wpa_ctrl_cleanup(void) {}
struct wpa_ctrl *wpa_ctrl_open(const char *ctrl_path) { return NULL; }
void wpa_ctrl_close(struct wpa_ctrl *ctrl) {}
int wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
	char *reply, size_t *reply_len, void (*msg_cb)(char *msg, size_t len))
	{ return 0; }
int wpa_ctrl_attach(struct wpa_ctrl *ctrl) { return 0; }
int wpa_ctrl_detach(struct wpa_ctrl *ctrl) { return 0; }
int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len)
	{ return 0; }
int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl) { return 0; }
#endif

static struct wpa_ctrl *ctrl_conn;
static struct wpa_ctrl *monitor_conn;

/* socket pair used to exit from a blocking read */
static int exit_sockets[2];

static char primary_iface[PROPERTY_VALUE_MAX];
// TODO: use new ANDROID_SOCKET mechanism, once support for multiple
// sockets is in

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
#define HOSTAPD_CTRL_PATH "/data/misc/wifi/hostapd"
#define HOSTAPD_NIC_IFACE "ap0"
static char current_fw_path[PROPERTY_VALUE_MAX] = {'\0'};
static const char FW_PATH_PROP_NAME[]="mtk_wifi.fwpath";
#endif

#ifndef WIFI_DRIVER_MODULE_ARG
#define WIFI_DRIVER_MODULE_ARG          ""
#endif
#ifndef WIFI_FIRMWARE_LOADER
#define WIFI_FIRMWARE_LOADER		""
#endif
#define WIFI_TEST_INTERFACE		"sta"

#ifndef WIFI_DRIVER_FW_PATH_STA
#define WIFI_DRIVER_FW_PATH_STA		NULL
#endif
#ifndef WIFI_DRIVER_FW_PATH_AP
#define WIFI_DRIVER_FW_PATH_AP		NULL
#endif
#ifndef WIFI_DRIVER_FW_PATH_P2P
#define WIFI_DRIVER_FW_PATH_P2P		NULL
#endif

#ifndef WIFI_DRIVER_FW_PATH_PARAM
#define WIFI_DRIVER_FW_PATH_PARAM	"/sys/module/wlan/parameters/fwpath"
#endif

#define WIFI_DRIVER_LOADER_DELAY	1000000

#ifdef CONFIG_MEDIATEK_WIFI_BEAM
#ifndef WIFI_INTERFACE
#define WIFI_INTERFACE "wlan0"
#endif

#ifndef P2P_WILDCARD_SSID
#define P2P_WILDCARD_SSID "DIRECT-"
#define P2P_WILDCARD_SSID_LEN 7
#endif
#endif
static const char IFACE_DIR[]           = "/data/system/wpa_supplicant";
#ifdef WIFI_DRIVER_MODULE_PATH
static const char DRIVER_MODULE_NAME[]  = WIFI_DRIVER_MODULE_NAME;
static const char DRIVER_MODULE_TAG[]   = WIFI_DRIVER_MODULE_NAME " ";
static const char DRIVER_MODULE_PATH[]  = WIFI_DRIVER_MODULE_PATH;
static const char DRIVER_MODULE_ARG[]   = WIFI_DRIVER_MODULE_ARG;
#endif
static const char FIRMWARE_LOADER[]     = WIFI_FIRMWARE_LOADER;
static const char DRIVER_PROP_NAME[]    = "wlan.driver.status";
static const char SUPPLICANT_NAME[]     = "wpa_supplicant";
static const char SUPP_PROP_NAME[]      = "init.svc.wpa_supplicant";
static const char P2P_SUPPLICANT_NAME[] = "p2p_supplicant";
static const char P2P_PROP_NAME[]       = "init.svc.p2p_supplicant";
static const char SUPP_CONFIG_TEMPLATE[]= "/system/etc/wifi/wpa_supplicant.conf";
static const char SUPP_CONFIG_FILE[]    = "/data/misc/wifi/wpa_supplicant.conf";
static const char P2P_CONFIG_FILE[]     = "/data/misc/wifi/p2p_supplicant.conf";
static const char CONTROL_IFACE_PATH[]  = "/data/misc/wifi/sockets";
static const char MODULE_FILE[]         = "/proc/modules";

static const char IFNAME[]              = "IFNAME=";
#define IFNAMELEN			(sizeof(IFNAME) - 1)
static const char WPA_EVENT_IGNORE[]    = "CTRL-EVENT-IGNORE ";

static const char SUPP_ENTROPY_FILE[]   = WIFI_ENTROPY_FILE;
static unsigned char dummy_key[21] = { 0x02, 0x11, 0xbe, 0x33, 0x43, 0x35,
                                       0x68, 0x47, 0x84, 0x99, 0xa9, 0x2b,
                                       0x1c, 0xd3, 0xee, 0xff, 0xf1, 0xe2,
                                       0xf3, 0xf4, 0xf5 };
#ifdef CONFIG_MEDIATEK_WIFI_BEAM
/*
 * mtk fix thread sync bug in wifi_send_command
 * */
#include <pthread.h>

struct wifi_sync_t {
	pthread_mutex_t conn_lock;
	int conn_count;
};
struct wifi_sync_t wifi_sync;

void wifi_init_sync(struct wifi_sync_t *psync)
{
	pthread_mutex_init(&psync->conn_lock, NULL);
	psync->conn_count = 1;
	ALOGD("init mutex done\n");
}
void wifi_hold_sync(struct wifi_sync_t *psync)
{
	pthread_mutex_lock(&psync->conn_lock);
	psync->conn_count ++;
	pthread_mutex_unlock(&psync->conn_lock);
		
}
void wifi_rele_sync(struct wifi_sync_t *psync)
{
	pthread_mutex_lock(&psync->conn_lock);
	psync->conn_count --;
	if (psync->conn_count == 0) {
		pthread_mutex_unlock(&psync->conn_lock);
		ALOGD("deinit mutex done\n");
		pthread_mutex_destroy(&psync->conn_lock);
	} else {
		pthread_mutex_unlock(&psync->conn_lock);
	}
	ALOGD("release mutex done\n");
}
/**********************************************/
#endif

/* Is either SUPPLICANT_NAME or P2P_SUPPLICANT_NAME */
static char supplicant_name[PROPERTY_VALUE_MAX];
/* Is either SUPP_PROP_NAME or P2P_PROP_NAME */
static char supplicant_prop_name[PROPERTY_KEY_MAX];

static int insmod(const char *filename, const char *args)
{
    void *module;
    unsigned int size;
    int ret;

    module = load_file(filename, &size);
    if (!module)
        return -1;

    ret = init_module(module, size, args);

    free(module);

    return ret;
}

static int rmmod(const char *modname)
{
    int ret = -1;
    int maxtry = 10;

    while (maxtry-- > 0) {
        ret = delete_module(modname, O_NONBLOCK | O_EXCL);
        if (ret < 0 && errno == EAGAIN)
            usleep(500000);
        else
            break;
    }

    if (ret != 0)
        ALOGD("Unable to unload driver module \"%s\": %s\n",
             modname, strerror(errno));
    return ret;
}

int do_dhcp_request(int *ipaddr, int *gateway, int *mask,
                    int *dns1, int *dns2, int *server, int *lease) {
    /* For test driver, always report success */
    if (strcmp(primary_iface, WIFI_TEST_INTERFACE) == 0)
        return 0;

    if (ifc_init() < 0)
        return -1;

    if (do_dhcp(primary_iface) < 0) {
        ifc_close();
        return -1;
    }
    ifc_close();
    get_dhcp_info(ipaddr, gateway, mask, dns1, dns2, server, lease);
    return 0;
}

const char *get_dhcp_error_string() {
    return dhcp_lasterror();
}

int is_wifi_driver_loaded() {
    char driver_status[PROPERTY_VALUE_MAX];
#ifdef WIFI_DRIVER_MODULE_PATH
    FILE *proc;
    char line[sizeof(DRIVER_MODULE_TAG)+10];
#endif

    if (!property_get(DRIVER_PROP_NAME, driver_status, NULL)
            || strcmp(driver_status, "ok") != 0) {
        return 0;  /* driver not loaded */
    }
#ifdef WIFI_DRIVER_MODULE_PATH
    /*
     * If the property says the driver is loaded, check to
     * make sure that the property setting isn't just left
     * over from a previous manual shutdown or a runtime
     * crash.
     */
    if ((proc = fopen(MODULE_FILE, "r")) == NULL) {
        ALOGW("Could not open %s: %s", MODULE_FILE, strerror(errno));
        property_set(DRIVER_PROP_NAME, "unloaded");
        return 0;
    }
    while ((fgets(line, sizeof(line), proc)) != NULL) {
        if (strncmp(line, DRIVER_MODULE_TAG, strlen(DRIVER_MODULE_TAG)) == 0) {
            fclose(proc);
            return 1;
        }
    }
    fclose(proc);
    property_set(DRIVER_PROP_NAME, "unloaded");
    return 0;
#else
    return 1;
#endif
}

int wifi_load_driver()
{
#ifdef WIFI_DRIVER_MODULE_PATH
    char driver_status[PROPERTY_VALUE_MAX];
    int count = 100; /* wait at most 20 seconds for completion */

    if (is_wifi_driver_loaded()) {
        return 0;
    }

    if (insmod(DRIVER_MODULE_PATH, DRIVER_MODULE_ARG) < 0)
        return -1;

    if (strcmp(FIRMWARE_LOADER,"") == 0) {
        /* usleep(WIFI_DRIVER_LOADER_DELAY); */
        property_set(DRIVER_PROP_NAME, "ok");
    }
    else {
        property_set("ctl.start", FIRMWARE_LOADER);
    }
    sched_yield();
    while (count-- > 0) {
        if (property_get(DRIVER_PROP_NAME, driver_status, NULL)) {
            if (strcmp(driver_status, "ok") == 0)
                return 0;
            else if (strcmp(DRIVER_PROP_NAME, "failed") == 0) {
                wifi_unload_driver();
                return -1;
            }
        }
        usleep(200000);
    }
    property_set(DRIVER_PROP_NAME, "timeout");
    wifi_unload_driver();
    return -1;
#else
    ALOGD("enter -->%s\n", __func__);

#ifdef CONFIG_MEDIATEK_DEBUG
    char encrypt_status[PROPERTY_VALUE_MAX];
    char decrypt_status[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.state", encrypt_status, NULL);
    property_get("vold.decrypt", decrypt_status, NULL);
    ALOGD("ro.crypto.state=%s decrypt_status=%s\n", encrypt_status, decrypt_status);

    /*need set property: encrypt, decrypt=[unencrypted][], [encrypted][trigger_restart_framework];
       ALPS01935804: don't need set property: [encrypted][trigger_restart_min_framework], [] */
    if(!((strcmp(encrypt_status, "") == 0)
        || (strcmp(encrypt_status, "encrypted") == 0 && strcmp(decrypt_status, "trigger_restart_min_framework") == 0)))
        property_set(DRIVER_PROP_NAME, "ok");
#else
    property_set(DRIVER_PROP_NAME, "ok");
#endif

#ifdef CONFIG_MEDIATEK_WIFI_BEAM
    ALOGD("enter -->%s\n, uid=%d, gid=%d", __func__, getuid(), getgid());
	wifi_init_sync(&wifi_sync);
#endif
    return 0;
#endif
}

int wifi_unload_driver()
{
    usleep(200000); /* allow to finish interface down */
#ifdef WIFI_DRIVER_MODULE_PATH
    if (rmmod(DRIVER_MODULE_NAME) == 0) {
        int count = 20; /* wait at most 10 seconds for completion */
        while (count-- > 0) {
            if (!is_wifi_driver_loaded())
                break;
            usleep(500000);
        }
        usleep(500000); /* allow card removal */
        if (count) {
            return 0;
        }
        return -1;
    } else
        return -1;
#else
    ALOGD("enter -->%s\n", __func__);

#ifdef CONFIG_MEDIATEK_DEBUG
    char encrypt_status[PROPERTY_VALUE_MAX];
    char decrypt_status[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.state", encrypt_status, NULL);
    property_get("vold.decrypt", decrypt_status, NULL);
    ALOGD("ro.crypto.state=%s decrypt_status=%s\n", encrypt_status, decrypt_status);

    /*need set property: encrypt, decrypt=[unencrypted][], [encrypted][trigger_restart_framework];
       ALPS01935804: don't need set property: [encrypted][trigger_restart_min_framework], [] */
    if(!((strcmp(encrypt_status, "") == 0)
        || (strcmp(encrypt_status, "encrypted") == 0 && strcmp(decrypt_status, "trigger_restart_min_framework") == 0)))
        property_set(DRIVER_PROP_NAME, "unloaded");
#else
    property_set(DRIVER_PROP_NAME, "unloaded");
#endif

#ifdef CONFIG_MEDIATEK_WIFI_BEAM
	/*fix wifi_send_command bug*/
	wifi_rele_sync(&wifi_sync);
#endif	
    return 0;
#endif
}

int ensure_entropy_file_exists()
{
    int ret;
    int destfd;

    ret = access(SUPP_ENTROPY_FILE, R_OK|W_OK);
    if ((ret == 0) || (errno == EACCES)) {
        if ((ret != 0) &&
            (chmod(SUPP_ENTROPY_FILE, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) != 0)) {
            ALOGE("Cannot set RW to \"%s\": %s", SUPP_ENTROPY_FILE, strerror(errno));
            return -1;
        }
        return 0;
    }
    destfd = TEMP_FAILURE_RETRY(open(SUPP_ENTROPY_FILE, O_CREAT|O_RDWR, 0660));
    if (destfd < 0) {
        ALOGE("Cannot create \"%s\": %s", SUPP_ENTROPY_FILE, strerror(errno));
        return -1;
    }

    if (TEMP_FAILURE_RETRY(write(destfd, dummy_key, sizeof(dummy_key))) != sizeof(dummy_key)) {
        ALOGE("Error writing \"%s\": %s", SUPP_ENTROPY_FILE, strerror(errno));
        close(destfd);
        return -1;
    }
    close(destfd);

    /* chmod is needed because open() didn't set permisions properly */
    if (chmod(SUPP_ENTROPY_FILE, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
             SUPP_ENTROPY_FILE, strerror(errno));
        unlink(SUPP_ENTROPY_FILE);
        return -1;
    }

    if (chown(SUPP_ENTROPY_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
             SUPP_ENTROPY_FILE, AID_WIFI, strerror(errno));
        unlink(SUPP_ENTROPY_FILE);
        return -1;
    }
    return 0;
}

int ensure_config_file_exists(const char *config_file)
{
    char buf[2048];
    int srcfd, destfd;
    struct stat sb;
    int nread;
    int ret;
#ifdef CONFIG_MEDIATEK_DEBUG /* debug file permission */
	struct stat s;
	if (lstat(config_file, &s) < 0)
		ALOGE("%s, Get file info fail, %s", config_file, strerror(errno));
	else {
		ALOGD("%s\npermission:%d, owner:%d, group:%d, process uid:%d",
				config_file, s.st_mode, s.st_uid, s.st_gid, getuid());
	}
#endif

    ret = access(config_file, R_OK|W_OK);
    if ((ret == 0) || (errno == EACCES)) {
        if ((ret != 0) &&
            (chmod(config_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) != 0)) {
            ALOGE("Cannot set RW to \"%s\": %s", config_file, strerror(errno));
            return -1;
        }
        return 0;
    } else if (errno != ENOENT) {
        ALOGE("Cannot access \"%s\": %s", config_file, strerror(errno));
        return -1;
    }

    srcfd = TEMP_FAILURE_RETRY(open(SUPP_CONFIG_TEMPLATE, O_RDONLY));
    if (srcfd < 0) {
        ALOGE("Cannot open \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = TEMP_FAILURE_RETRY(open(config_file, O_CREAT|O_RDWR, 0660));
    if (destfd < 0) {
        close(srcfd);
        ALOGE("Cannot create \"%s\": %s", config_file, strerror(errno));
        return -1;
    }

    while ((nread = TEMP_FAILURE_RETRY(read(srcfd, buf, sizeof(buf)))) != 0) {
        if (nread < 0) {
            ALOGE("Error reading \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(config_file);
            return -1;
        }
        TEMP_FAILURE_RETRY(write(destfd, buf, nread));
    }

    close(destfd);
    close(srcfd);

    /* chmod is needed because open() didn't set permisions properly */
    if (chmod(config_file, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
             config_file, strerror(errno));
        unlink(config_file);
        return -1;
    }

    if (chown(config_file, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
             config_file, AID_WIFI, strerror(errno));
        unlink(config_file);
        return -1;
    }
    return 0;
}

int wifi_start_supplicant(int p2p_supported)
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 200; /* wait at most 20 seconds for completion */
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    const prop_info *pi;
    unsigned serial = 0, i;
#endif

    ALOGD("enter -->%s p2p_supported=%d\n", __func__, p2p_supported);
    if (p2p_supported) {
        strcpy(supplicant_name, P2P_SUPPLICANT_NAME);
        strcpy(supplicant_prop_name, P2P_PROP_NAME);

        /* Ensure p2p config file is created */
        if (ensure_config_file_exists(P2P_CONFIG_FILE) < 0) {
            ALOGE("Failed to create a p2p config file");
            return -1;
        }

    } else {
        strcpy(supplicant_name, SUPPLICANT_NAME);
        strcpy(supplicant_prop_name, SUPP_PROP_NAME);
    }

    /* Check whether already running */
    if (property_get(supplicant_prop_name, supp_status, NULL)
            && strcmp(supp_status, "running") == 0) {
        return 0;
    }

    /* Before starting the daemon, make sure its config file exists */
    if (ensure_config_file_exists(SUPP_CONFIG_FILE) < 0) {
        ALOGE("Wi-Fi will not be enabled");
        return -1;
    }

    if (ensure_entropy_file_exists() < 0) {
        ALOGE("Wi-Fi entropy file was not created");
    }

    /* Clear out any stale socket files that might be left over. */
    wpa_ctrl_cleanup();

    /* Reset sockets used for exiting from hung state */
    exit_sockets[0] = exit_sockets[1] = -1;

#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    /*
     * Get a reference to the status property, so we can distinguish
     * the case where it goes stopped => running => stopped (i.e.,
     * it start up, but fails right away) from the case in which
     * it starts in the stopped state and never manages to start
     * running at all.
     */
    pi = __system_property_find(supplicant_prop_name);
    if (pi != NULL) {
        serial = __system_property_serial(pi);
    }
#endif
    property_get("wifi.interface", primary_iface, WIFI_TEST_INTERFACE);

    property_set("ctl.start", supplicant_name);
    sched_yield();

    while (count-- > 0) {
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
        if (pi == NULL) {
            pi = __system_property_find(supplicant_prop_name);
        }
        if (pi != NULL) {
            /*
             * property serial updated means that init process is scheduled
             * after we sched_yield, further property status checking is based on this */
            if (__system_property_serial(pi) != serial) {
                __system_property_read(pi, NULL, supp_status);
                if (strcmp(supp_status, "running") == 0) {
                    return 0;
                } else if (strcmp(supp_status, "stopped") == 0) {
                    return -1;
                }
            }
        }
#else
        if (property_get(supplicant_prop_name, supp_status, NULL)) {
            if (strcmp(supp_status, "running") == 0)
                return 0;
        }
#endif
        usleep(100000);
    }
    return -1;
}

int wifi_stop_supplicant(int p2p_supported)
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; /* wait at most 5 seconds for completion */

    ALOGD("enter -->%s p2p_supported=%d\n", __func__, p2p_supported);
    if (p2p_supported) {
        strcpy(supplicant_name, P2P_SUPPLICANT_NAME);
        strcpy(supplicant_prop_name, P2P_PROP_NAME);
    } else {
        strcpy(supplicant_name, SUPPLICANT_NAME);
        strcpy(supplicant_prop_name, SUPP_PROP_NAME);
    }

    /* Check whether supplicant already stopped */
    if (property_get(supplicant_prop_name, supp_status, NULL)
        && strcmp(supp_status, "stopped") == 0) {
        return 0;
    }

    property_set("ctl.stop", supplicant_name);
    sched_yield();

    while (count-- > 0) {
        if (property_get(supplicant_prop_name, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0)
                return 0;
        }
        usleep(100000);
    }
    ALOGE("Failed to stop supplicant");
    return -1;
}

int wifi_connect_on_socket_path(const char *path)
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};

    ALOGD("enter -->%s path=%s\n", __func__, path);

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0){
        /* wifi tries connecting to hostapd */
    } else {
        /* wifi tries connecting to supplicant */
#endif
    /* Make sure supplicant is running */
    if (!property_get(supplicant_prop_name, supp_status, NULL)
            || strcmp(supp_status, "running") != 0) {
        ALOGE("Supplicant not running, cannot connect");
        return -1;
    }
#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    }
#endif

    ctrl_conn = wpa_ctrl_open(path);
    if (ctrl_conn == NULL) {
        ALOGE("Unable to open connection to supplicant on \"%s\": %s",
             path, strerror(errno));
        return -1;
    }
    monitor_conn = wpa_ctrl_open(path);
    if (monitor_conn == NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        return -1;
    }
    if (wpa_ctrl_attach(monitor_conn) != 0) {
        wpa_ctrl_close(monitor_conn);
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = monitor_conn = NULL;
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, exit_sockets) == -1) {
        wpa_ctrl_close(monitor_conn);
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = monitor_conn = NULL;
        return -1;
    }

    return 0;
}

/* Establishes the control and monitor socket connections on the interface */
int wifi_connect_to_supplicant()
{
    static char path[PATH_MAX];

    ALOGD("enter -->%s\n", __func__);

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    if (!property_get(FW_PATH_PROP_NAME, current_fw_path, NULL)){
        ALOGE("Fail to get current fw path\n");
        return -1;
    }
    ALOGD("current fw path: %s\n", current_fw_path);

    if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0){
        /* wifi connect to hostapd */
        strcpy(primary_iface, HOSTAPD_NIC_IFACE);
        snprintf(path, sizeof(path), "%s/%s", HOSTAPD_CTRL_PATH, primary_iface);
    } else {
        /* wifi connect to supplicant */
#endif
    if (access(IFACE_DIR, F_OK) == 0) {
        snprintf(path, sizeof(path), "%s/%s", IFACE_DIR, primary_iface);
    } else {
        snprintf(path, sizeof(path), "@android:wpa_%s", primary_iface);
    }
#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    }
#endif
    return wifi_connect_on_socket_path(path);
}

int wifi_send_command(const char *cmd, char *reply, size_t *reply_len)
{
    int ret;

    ALOGD("enter -->%s cmd=%s\n", __func__, cmd);

    if (ctrl_conn == NULL) {
        ALOGV("Not connected to wpa_supplicant - \"%s\" command dropped.\n", cmd);
        return -1;
    }

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    /*
     * Command strings are in the format
     *
     *     IFNAME=iface XXX (legacy:wlan0; hotspot:ap0)
     *        or
     *     XXX (p2p)
     *
     * the prefix "IFNAME=ap0 " is added to distinguish hotspot, and not 
     * reconganized by hostapd defaultly, so strip it off before send to 
     * hostapd.
     */
    {
        size_t nwrite = strlen(cmd);
        char *match;
        
        if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0) {
            if (strncmp(cmd, IFNAME, IFNAMELEN) == 0) {
                match = strchr(cmd, ' ');
                if (match != NULL) {
                    nwrite -= (match + 1 - cmd);
                    memmove(cmd, match + 1, nwrite + 1);
                } else {
                    ALOGE("Invalid command format\n");
                    return -1;
                }
            }
            ALOGD("hostapd command without interface - %s\n", cmd);
        }
    }
#endif
#ifdef CONFIG_MEDIATEK_WIFI_BEAM
	/*fix wifi_send_command bug*/
	pthread_mutex_lock(&wifi_sync.conn_lock);
#endif
    ret = wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), reply, reply_len, NULL);
#ifdef CONFIG_MEDIATEK_WIFI_BEAM
	pthread_mutex_unlock(&wifi_sync.conn_lock);
#endif
    if (ret == -2) {
        ALOGD("'%s' command timed out.\n", cmd);
        /* unblocks the monitor receive socket for termination */
        TEMP_FAILURE_RETRY(write(exit_sockets[0], "T", 1));
        return -2;
    } else if (ret < 0 || strncmp(reply, "FAIL", 4) == 0) {
        return -1;
    }
    if (strncmp(cmd, "PING", 4) == 0) {
        reply[*reply_len] = '\0';
    }
    ALOGD("leave --> reply=%s\n", reply);
    return 0;
}

int wifi_supplicant_connection_active()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};

    if (property_get(supplicant_prop_name, supp_status, NULL)) {
        if (strcmp(supp_status, "stopped") == 0)
            return -1;
    }

    return 0;
}

int wifi_ctrl_recv(char *reply, size_t *reply_len)
{
    int res;
    int ctrlfd = wpa_ctrl_get_fd(monitor_conn);
    struct pollfd rfds[2];

    ALOGD("enter -->%s\n", __func__);

    memset(rfds, 0, 2 * sizeof(struct pollfd));
    rfds[0].fd = ctrlfd;
    rfds[0].events |= POLLIN;
    rfds[1].fd = exit_sockets[1];
    rfds[1].events |= POLLIN;
    do {
        res = TEMP_FAILURE_RETRY(poll(rfds, 2, 30000));
        if (res < 0) {
            ALOGE("Error poll = %d", res);
            return res;
        } else if (res == 0) {
        #ifdef CONFIG_HOTSPOT_MGR_SUPPORT
            if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0){
            /* How to check if hostapd is active or not ?
             */
            } else {
        #endif
            /* timed out, check if supplicant is active
             * or not ..
             */
            res = wifi_supplicant_connection_active();
            if (res < 0)
                return -2;
        #ifdef CONFIG_HOTSPOT_MGR_SUPPORT
            }
        #endif
        }
    } while (res == 0);

    if (rfds[0].revents & POLLIN) {
        return wpa_ctrl_recv(monitor_conn, reply, reply_len);
    }

    /* it is not rfds[0], then it must be rfts[1] (i.e. the exit socket)
     * or we timed out. In either case, this call has failed ..
     */
    return -2;
}

int wifi_wait_on_socket(char *buf, size_t buflen)
{
    size_t nread = buflen - 1;
    int result;
    char *match, *match2;

    ALOGD("enter -->%s buflen=%d\n", __func__, buflen);

    if (monitor_conn == NULL) {
        return snprintf(buf, buflen, "IFNAME=%s %s - connection closed",
                        primary_iface, WPA_EVENT_TERMINATING);
    }

    result = wifi_ctrl_recv(buf, &nread);

    /* Terminate reception on exit socket */
    if (result == -2) {
        return snprintf(buf, buflen, "IFNAME=%s %s - connection closed",
                        primary_iface, WPA_EVENT_TERMINATING);
    }

    if (result < 0) {
        ALOGD("wifi_ctrl_recv failed: %s\n", strerror(errno));
        return snprintf(buf, buflen, "IFNAME=%s %s - recv error",
                        primary_iface, WPA_EVENT_TERMINATING);
    }
    buf[nread] = '\0';
    /* Check for EOF on the socket */
    if (result == 0 && nread == 0) {
        /* Fabricate an event to pass up */
        ALOGD("Received EOF on supplicant socket\n");
        return snprintf(buf, buflen, "IFNAME=%s %s - signal 0 received",
                        primary_iface, WPA_EVENT_TERMINATING);
    }
    ALOGD("[1] get event: %s", buf);
    /*
     * Events strings are in the format
     *
     *     IFNAME=iface <N>CTRL-EVENT-XXX 
     *        or
     *     <N>CTRL-EVENT-XXX 
     *
     * where N is the message level in numerical form (0=VERBOSE, 1=DEBUG,
     * etc.) and XXX is the event name. The level information is not useful
     * to us, so strip it off.
     */

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    {
        char *tempbuf;
        size_t templen;
        
        /* If running in AP mode and connected to hostapd,
         * add prefix "IFNAME=ap0 " to the received event.
         */
        if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0) {
            templen = IFNAMELEN + 4 + nread + 1;
            if (templen > buflen){
                ALOGE("Cannot add prefix \"IFNAME=ap0 \" for hostapd event\n");
            }
            else{
                tempbuf = malloc(templen);
                snprintf(tempbuf, templen, "%s%s %s", IFNAME, primary_iface, buf);
                strcpy(buf, tempbuf);
                nread += IFNAMELEN + 4;
                free(tempbuf);
            }
        }
    }
#endif

    if (strncmp(buf, IFNAME, IFNAMELEN) == 0) {
        match = strchr(buf, ' ');
        if (match != NULL) {
            if (match[1] == '<') {
                match2 = strchr(match + 2, '>');
                if (match2 != NULL) {
                    nread -= (match2 - match);
                    memmove(match + 1, match2 + 1, nread - (match - buf) + 1);
                }
            }
        } else {
            return snprintf(buf, buflen, "%s", WPA_EVENT_IGNORE);
        }
    } else if (buf[0] == '<') {
        match = strchr(buf, '>');
        if (match != NULL) {
            nread -= (match + 1 - buf);
            memmove(buf, match + 1, nread + 1);
            ALOGV("supplicant generated event without interface - %s\n", buf);
        }
    } else {
        /* let the event go as is! */
        ALOGW("supplicant generated event without interface and without message level - %s\n", buf);
    }
    ALOGD("[2] get event: %s", buf);
    return nread;
}

int wifi_wait_for_event(char *buf, size_t buflen)
{
    return wifi_wait_on_socket(buf, buflen);
}

void wifi_close_sockets()
{
    ALOGD("enter -->%s\n", __func__);
    if (ctrl_conn != NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }

    if (monitor_conn != NULL) {
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
    }

    if (exit_sockets[0] >= 0) {
        close(exit_sockets[0]);
        exit_sockets[0] = -1;
    }

    if (exit_sockets[1] >= 0) {
        close(exit_sockets[1]);
        exit_sockets[1] = -1;
    }
}

void wifi_close_supplicant_connection()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; /* wait at most 5 seconds to ensure init has stopped stupplicant */

    ALOGD("enter -->%s\n", __func__);

    wifi_close_sockets();

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    if (strcmp(current_fw_path, WIFI_DRIVER_FW_PATH_AP) == 0) {
        /* wifi connected to hostapd */
    } else {
        /* wifi connected to supplicant */
#endif
    while (count-- > 0) {
        if (property_get(supplicant_prop_name, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0)
                return;
        }
        usleep(100000);
    }
#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    }
#endif
}

int wifi_command(const char *command, char *reply, size_t *reply_len)
{
    return wifi_send_command(command, reply, reply_len);
}

const char *wifi_get_fw_path(int fw_type)
{
    ALOGD("enter -->%s fw_type=%d\n", __func__, fw_type);
    switch (fw_type) {
    case WIFI_GET_FW_PATH_STA:
        return WIFI_DRIVER_FW_PATH_STA;
    case WIFI_GET_FW_PATH_AP:
        return WIFI_DRIVER_FW_PATH_AP;
    case WIFI_GET_FW_PATH_P2P:
        return WIFI_DRIVER_FW_PATH_P2P;
    }
    return NULL;
}

int wifi_change_fw_path(const char *fwpath)
{
    int len;
    int fd;
    int ret = 0;

    ALOGD("enter -->%s fwpath=%s\n", __func__, fwpath);

    if (!fwpath)
        return ret;
    fd = TEMP_FAILURE_RETRY(open(WIFI_DRIVER_FW_PATH_PARAM, O_WRONLY));
    if (fd < 0) {
        ALOGE("Failed to open wlan fw path param (%s)", strerror(errno));
        return -1;
    }
    len = strlen(fwpath) + 1;
    if (TEMP_FAILURE_RETRY(write(fd, fwpath, len)) != len) {
        ALOGE("Failed to write wlan fw path param (%s)", strerror(errno));
        ret = -1;
    }
    close(fd);

#ifdef CONFIG_HOTSPOT_MGR_SUPPORT
    /* Store current fw path in property */
    property_set(FW_PATH_PROP_NAME, fwpath);
#endif
    return ret;
}
#ifdef CONFIG_MEDIATEK_WIFI_BEAM
int wifi_get_own_addr(char *mac) 
{
    struct ifreq ifr= {0};
    int driver_loaded = 0;
    int skfd = 0;
    int ret, read_cnt = 0;
    unsigned char *own_addr;
    
    if (is_wifi_driver_loaded()) {
        driver_loaded = 1;   
    } else {     
        wifi_load_driver();
    }
    
    /* initialize socket */
    skfd = socket(PF_INET, SOCK_DGRAM, 0);
    
    strncpy(ifr.ifr_name, WIFI_INTERFACE, IFNAMSIZ);
    ifr.ifr_name[strlen(WIFI_INTERFACE)] = '\0';

    /* do ioctl */
    while((ret = ioctl(skfd, SIOCGIFHWADDR, &ifr)) < 0) {
        usleep(20000);                                          // wait for 20 ms
        read_cnt++;
        if (read_cnt > 100) {
            ALOGE("Netowrk %s UP timeout(2 seconds)", WIFI_INTERFACE);
            break;    
        }
    };    
    if (ret >= 0) {
        own_addr = ifr.ifr_hwaddr.sa_data;
        if (*own_addr & 0x02){											// change to P2P mac address
        	*own_addr &= ~0x02;                                  
        } else { 	
        	*own_addr |= 0x02;
        }                                  
        
        sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
        *own_addr, *(own_addr + 1), *(own_addr + 2), *(own_addr + 3), *(own_addr + 4), *(own_addr + 5));  
        if (read_cnt) {
            ALOGD("Network UP takes %d ms", read_cnt * 20);
        }
        ALOGD("GET_MAC_ADDR Success MAC %s", mac);
    } else {
        ALOGE("GET_MAC_ADDR Failed %s", strerror(errno));
    }
    
    close(skfd);

    if (driver_loaded == 0) {
        wifi_unload_driver();
    }
    return ret;

}
int wifi_build_cred(char *cred, size_t *cred_len)
{
    unsigned char ssid[36];
    size_t ssid_len;
    unsigned char passphrase[12];
    unsigned char *p;
    
    memcpy(ssid, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN);
    wifi_random_for_ssid((char *) &ssid[P2P_WILDCARD_SSID_LEN], 2);
    // Add ssid postfix
    // memcpy(&ssid[P2P_WILDCARD_SSID_LEN + 2], ssid_postfix, ssid_postfix_len);
    ssid_len = P2P_WILDCARD_SSID_LEN + 2;
    ssid[ssid_len] = '\0';
    wifi_random_for_ssid(passphrase, 8);
    passphrase[8] = '\0';
    p = cred;
    p += sprintf(p, "ssid=%s", ssid);
    p += sprintf(p, " auth_type=0x0020");
    p += sprintf(p, " encr_type=0x0008");
    p += sprintf(p, " psk=%s", passphrase);
    *cred_len = strlen(cred);
    ALOGD("Build Credential %s", cred);
    return 0;
}

#ifndef WPA_SUPPLICANT_VERSION
static int os_get_random(unsigned char *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "rb");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}
#endif

int wifi_random_for_ssid(char *buf, size_t len)
{
	unsigned char val;
	size_t i;
	unsigned char letters = 'Z' - 'A' + 1;
	unsigned char numbers = 10;

	if (os_get_random((unsigned char *) buf, len))
		return -1;
	/* Character set: 'A'-'Z', 'a'-'z', '0'-'9' */
	for (i = 0; i < len; i++) {
		val = buf[i];
		val %= 2 * letters + numbers;
		if (val < letters)
			buf[i] = 'A' + val;
		else if (val < 2 * letters)
			buf[i] = 'a' + (val - letters);
		else
			buf[i] = '0' + (val - 2 * letters);
	}
	return 0;
}
#endif
