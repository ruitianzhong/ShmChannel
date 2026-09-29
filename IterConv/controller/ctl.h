// controller 的 unix 命令服务接口。实现见 ctl.cpp; 用到的 Router/Link 结构与共享
// 状态见 core.h。
#ifndef CTL_H
#define CTL_H

#include <string>

// 定义在 ctl.cpp: 主线程的 unix 命令服务(ping/offline/online/quiescent)
void CtlService(const std::string& path);

#endif  // CTL_H