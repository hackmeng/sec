#!/bin/bash
#Filename: sec.sh
#Author: Hackmeng
#Source: https://github.com/hackmeng/sec
#Date: 2021年1月28日

#更新记录
#2021年1月28日
#初次创建，参考多个脚本整合

echo "##########################################################################"
echo "#                                                                        #"
echo "#                        主机安全检测加固脚本v1.0.1                      #"
echo "#                           更新日期：2021年1月29日                     #"
echo "#             脚本持续更新地址：https://github.com/hackmeng/sec           #"
echo "#                                                                        #"
echo "#警告:本脚本只是一个检查的操作,未对服务器做任何修改,管理员可以根据此报告 #"
echo "#进行相应的安全整改                                                      #"
echo "##########################################################################"
echo " "
#全局变量配置开始
mArr=()
PASSMAXDAYS="12"
PASSMINDAYS="12"
PASSMINLEN="12"
PASSWARNAGE="12"
#全局变量配置结束

#查看系统信息
function systeminfo(){
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统基本信息<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    hostname=$(uname -n)
    system=$(cat /etc/os-release | grep "^NAME" | awk -F\" '{print $2}')
    version=$(cat /etc/redhat-release | awk '{print $4$5}')
    kernel=$(uname -r)
    platform=$(uname -p)
    address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
    cpumodel=$(cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq)
    cpu=$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)
    machinemodel=$(dmidecode | grep "Product Name" | sed 's/^[ \t]*//g' | tr '\n' '\t' )
    date=$(date)
    echo "主机名:           $hostname"
    echo "系统名称:         $system"
    echo "系统版本:         $version"
    echo "内核版本:         $kernel"
    echo "系统类型:         $platform"
    echo "本机IP地址:       $address"
    echo "CPU型号:          $cpumodel"
    echo "CPU核数:          $cpu"
    echo "机器型号:         $machinemodel"
    echo "系统时间:         $date"
    echo " "
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>资源使用情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    summemory=$(free -h |grep "Mem:" | awk '{print $2}')
    freememory=$(free -h |grep "Mem:" | awk '{print $4}')
    usagememory=$(free -h |grep "Mem:" | awk '{print $3}')
    uptime=$(uptime | awk '{print $2" "$3" "$4" "$5}' | sed 's/,$//g')
    loadavg=$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')

    echo "总内存大小:           $summemory"
    echo "已使用内存大小:       $usagememory"
    echo "可使用内存大小:       $freememory"
    echo "系统运行时间:         $uptime"
    echo "系统负载:             $loadavg"
    echo "=============================dividing line================================"
    echo "内存状态:"
    vmstat 2 5
    echo "=============================dividing line================================"
    echo "僵尸进程:"
    ps -ef | grep zombie | grep -v grep
    if [ $? == 1 ];then
        echo ">>>无僵尸进程"
    else
        echo ">>>有僵尸进程------[需调整]"
    fi
    echo "=============================dividing line================================"
    echo "耗CPU最多的进程:"
    ps auxf |sort -nr -k 3 |head -5
    echo "=============================dividing line================================"
    echo "耗内存最多的进程:"
    ps auxf |sort -nr -k 4 |head -5
    echo "=============================dividing line================================"
    echo  "环境变量:"
    env
    echo "=============================dividing line================================"
    echo  "路由表:"
    route -n
    echo "=============================dividing line================================"
    echo  "监听端口:"
    netstat -tunlp
    echo "=============================dividing line================================"
    echo  "当前建立的连接:"
    netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'
    echo "=============================dividing line================================"
    echo "开机启动的服务:"
    systemctl list-unit-files | grep enabled
    echo " "
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统用户情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    echo  "活动用户:"
    w | tail -n +2
    echo "=============================dividing line================================"
    echo  "系统所有用户:"
    cut -d: -f1,2,3,4 /etc/passwd
    echo "=============================dividing line================================"
    echo  "系统所有组:"
    cut -d: -f1,2,3 /etc/group
    echo "=============================dividing line================================"
    echo  "当前用户的计划任务:"
    crontab -l
    echo " "
    main
}

#密码复杂度配置
function mPasswordSet(){
    # read -p  "设置密码最多可多少天不修改：" PASSMAXDAYS
	# read -p  "设置密码修改之间最小的天数：" PASSMINDAYS
	# read -p  "设置密码最短的长度：" PASSMINLEN
	# read -p  "设置密码失效前多少天通知用户：" PASSWARNAGE
    sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   '$PASSMAXDAYS'' /etc/login.defs
	sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   '$PASSMINDAYS'' /etc/login.defs
	sed -i '/^PASS_MIN_LEN/c\PASS_MIN_LEN     '$PASSMINLEN'' /etc/login.defs
	sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   '$PASSWARNAGE'' /etc/login.defs
    echo "密码复杂度配置完毕！"
    mPasswordCheck
}
#备份配置文件
function mBackupSetting(){
    echo "开始备份$1文件"
    echo "路径为：`dirname $1`"
    echo "文件名：`basename $1`"
    BackupTime=$(date '+%Y%m%d%H%M')
    BackupFile=$(echo "$1.meng_bak$BackupTime")
    cp $1 $BackupFile
    if [ -f $BackupFile ];then
        echo "备份成功，备份的文件为：$BackupFile"
        return 0
    else
        echo "备份失败！请手动备份！"
        main
    fi
}
#密码复杂度检测
function mPasswordCheck(){
    PASS_MAX_DAYS=$(cat /etc/login.defs |grep -v "#"|grep "PASS_MAX_DAYS"|awk '{print $2}')
    PASS_MIN_DAYS=$(cat /etc/login.defs |grep -v "#"|grep "PASS_MIN_DAYS"|awk '{print $2}')
    PASS_MIN_LEN=$(cat /etc/login.defs |grep -v "#"|grep "PASS_MIN_LEN"|awk '{print $2}')
    PASS_WARN_AGE=$(cat /etc/login.defs |grep -v "#"|grep "PASS_WARN_AGE"|awk '{print $2}')
    if [ "$PASS_MAX_DAYS" -gt "$PASSMAXDAYS" ];then
    \033[31;5m 输入无效 \033[0m
        echo -e "检查密码最多使用天数---结果：\033[1;31m 不符合要求 \033[0m当前值是："$PASS_MAX_DAYS
    else
        echo "检查密码最多使用天数---结果：符合要求，当前值是："$PASS_MAX_DAYS
    fi
    if [ "$PASS_MIN_DAYS" -gt "$PASSMINDAYS" ];then
        echo -e "检查密码修改最小天数---结果：\033[1;31m 不符合要求 \033[0m当前值是："$PASS_MIN_DAYS
    else
        echo "检查密码修改最小天数---结果：符合要求，当前值是："$PASS_MIN_DAYS
    fi
    if [ "$PASS_MIN_LEN" -gt "$PASSMINLEN" ];then
        echo -e "检查密码最短长度---结果：\033[1;31m 不符合要求 \033[0m当前值是："$PASS_MIN_LEN
    else
        echo "检查密码最短长度---结果：符合要求，当前值是："$PASS_MIN_LEN
    fi
    if [ "$PASS_WARN_AGE" -gt "$PASSWARNAGE" ];then
        echo -e "检查密码到期前多少天通知用户---结果：\033[1;31m 不符合要求 \033[0m当前值是："$PASS_WARN_AGE
    else
        echo "检查密码到期前多少天通知用户---结果：符合要求，当前值是："$PASS_WARN_AGE
    fi
    read -p "是否设置密码策略[y/n]:" Y
    if [ "$Y" == "y" ];then
        mBackupSetting /etc/login.defs
        if [ $? -eq 0 ];then
            mPasswordSet
        fi
    else
        main
    fi
}

function main(){
    echo -e "\033[1;31m
    #########################################################################################
    #                                        Menu                                           #
    #         1:查看系统信息                                                                #
    #         2:查看/设置密码策略                                                           #
    #         3:创建管理员账户                                                              #
    #         4:查看/设置远程登陆策略(SSH)                                                  #
    #         5:查看/设置历史记录及超时锁定策略                                             #
    #         6:查看/设置SSH端口                                                            #
    #         7:查看/设置登陆失败策略                                                        #
    #         8:其他工具                                                                    #
    #         9:退出                                                                        #
    ######################################################################################### \033[0m"
    read -p "请选择功能[1-9]:"
    case $REPLY in
    1)
        systeminfo
    ;;
    2)
        mPasswordCheck
    ;;
    3)
    ;;
    4)
    ;;
    5)
    ;;
    6)
    ;;
    7)
    ;;
    8)
    ;;
    9)
        exit 0
        ;;
    *)
        echo -e "\033[31;5m 输入无效 \033[0m"
        main
        ;;
    esac
} 
main