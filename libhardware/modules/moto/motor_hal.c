#define LOG_TAG "motorStub"  

#include <hardware/hardware.h>
#include <hardware/motor_hal.h> 
#include <fcntl.h>
#include <errno.h>
#include <cutils/log.h>
#include <cutils/atomic.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/mman-proprietary.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <utils/threads.h>



#define DEVICE_NAME          "/dev/motor"
#define MODULE_NAME           "motor"
#define MODULE_AUTHOR         "lifei@yongyida.com"
#define MOTOR_FILE              "/sys/class/motor/motor/motor_ctl"




/*设备打开和关闭接口*/
static int motor_device_open(const struct hw_module_t* module, const char* name, struct hw_device_t** device);
static int motor_device_close(struct hw_device_t* device);

/*设备访问接口*/
 
static int motor_io_ctrol(struct motor_device_t* dev,unsigned char cmd,int param);

/*模块方法表*/
static struct hw_module_methods_t motor_module_methods = {
	open: motor_device_open
};

/*模块实例变量*/
/*
//实例变量名必须为HAL_MODULE_INFO_SYM，tag也必须为HARDWARE_MODULE_TAG，这是Android硬件抽象层规范规定的
//framworks 通过这个实例变量来调用硬件模块。
*/
struct motor_module_t HAL_MODULE_INFO_SYM = { 
	common: {
		tag: HARDWARE_MODULE_TAG,
		version_major: 1,
		version_minor: 0,
		id: MOTOR_HARDWARE_MODULE_ID,
		name: MODULE_NAME,
		author: MODULE_AUTHOR,
		methods: &motor_module_methods,
	}
};




static int motor_device_open(const struct hw_module_t* module, const char* name, struct hw_device_t** device)
{
	struct motor_device_t *motordev=NULL;
	int ret;
	motordev=(struct motor_device_t*)malloc(sizeof(struct motor_device_t));
	if(!motordev)
		{
		ALOGE("malloc motordev fail----------\n");		
		return -EFAULT;
	 }	
	memset(motordev, 0, sizeof(struct motor_device_t));
	motordev->common.tag=HARDWARE_DEVICE_TAG;
	motordev->common.version=0;
	motordev->common.module=(hw_module_t*)module;
	motordev->common.close=motor_device_close;
	motordev->io_ctrol=motor_io_ctrol;


	motordev->fd=open(MOTOR_FILE,O_RDWR);//O_RDWR  DEVICE_NAME   "/sys/class/motor/motor/motor_ctl"
	if(motordev->fd <0)
	{
		ALOGE("motor stub: fail to open /dev/motor---------\n");
		return -EFAULT;
	}
	*device=&(motordev->common);
	ALOGE("motor stub: successfully to open /dev/motor-----yes-----\n");

	return 0;
}

static int motor_device_close(struct hw_device_t* device)
{

	struct motor_device_t *motor=(struct motor_device_t *)device;
	if(motor)
		{
		close(motor->fd);
		free(motor);
	 }
	return 0;
}


static int motor_io_ctrol(struct motor_device_t* dev,unsigned char cmd,int param)
{
	struct motor_device_t  *motordev=dev;
	unsigned char buffer[3];
	int len,num;
	
	 if(!motordev)return -EFAULT;	
	  memset(buffer, 0, 3);
	 	
	 //	cmd=cmd&0xff;
	 //	param_1=param_1&0xff;
	 //	param_2=param_2&0xff;
	 	
	// num+=sprintf(buffer+num, "%c,", cmd); //app调用sprintf这个会死掉
	// num+=sprintf(buffer+num, "%c,", param_1);
	// num+=sprintf(buffer+num, "%c,", param_2);
	// ioctl(motordev->fd,cmd,param);//要自己封装幻数，_IO(); 参考 com_android_server_AlarmManagerService.cpp
	buffer[0]=cmd&0xff;
	buffer[1]=	param&0xff;
	buffer[2] = '\0';
	len=write(motordev->fd,buffer,3);	
	
	return len;
}


