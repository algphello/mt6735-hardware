#ifndef ANDROID_MOTOR_INTERFACE_H   //标准格式
#define ANDROID_MOTOR_INTERFACE_H
#include <hardware/hardware.h>

#include <sys/stat.h>  
#include <sys/ioctl.h>  
#include <fcntl.h>  
#include <errno.h> 


__BEGIN_DECLS   //-------- 标准android 格式



#define MOTOR_HARDWARE_MODULE_ID          "motor_hal"

#if 1
#define MOTOR_MAGIC  'm'  
#define ROBOT_FORWORD   _IOW(MOTOR_MAGIC,  1,int)
#define ROBOT_BACK   _IOW(MOTOR_MAGIC,  2,int)
#define ROBOT_LEFT   _IOW(MOTOR_MAGIC,  3,int)
#define ROBOT_RIGHT   _IOW(MOTOR_MAGIC,  4,int)

#define ROBOT_HEAD_UP   _IOW(MOTOR_MAGIC,  5,int)
#define ROBOT_HEAD_DOWN   _IOW(MOTOR_MAGIC,  6,int)
#define ROBOT_HEAD_LEFT   _IOW(MOTOR_MAGIC,  7,int)
#define ROBOT_HEAD_RIGHT   _IOW(MOTOR_MAGIC,  8,int)

#endif

//#define MOTOR_MAGIC  'm'  
#define C_ROBOT_FORWORD  'A'
#define C_ROBOT_BACK   'B'
#define C_ROBOT_LEFT   'C'
#define C_ROBOT_RIGHT   'D'
#define C_ROBOT_STOP   'E'

#define C_ROBOT_HEAD_UP  'I'
#define C_ROBOT_HEAD_DOWN  'J'
#define C_ROBOT_HEAD_LEFT  'K'
#define C_ROBOT_HEAD_RIGHT   'L'
#define C_ROBOT_H_STOP   'M'
#define C_ROBOT_V_STOP   'S'

#define C_ROBOT_STOP_DANCE   'N'
#define C_ROBOT_START_DANCE   'H'


struct motor_module_t {
	struct hw_module_t common;
};

struct motor_device_t {
	struct hw_device_t common;
	int  fd;	
	int (*io_ctrol)(struct motor_device_t* dev,unsigned char cmd,int param);
};

__END_DECLS   

#endif

