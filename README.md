# tartext
参考fartext的脱壳机


由于目前只有一个手机nx6p，最高系统版本是安卓8，而fartext aosp 版本是10，所以尝试将其改为aosp 8

编译时禁用Jack make ANDROID_COMPILE_WITH_JACK=false

自己添加的类不在白名单报错的话需要在/build/core/tasks/check_boot_jars/package_whitelist.txt 文件添加 或者直接修改同级目录下的check_boot_jars.py逻辑
