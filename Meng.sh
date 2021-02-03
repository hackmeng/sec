#!/bin/bash
#Filename: Meng.sh
#Author: Hackmeng
#Source: https://github.com/hackmeng/sec
#Date: 2021年1月28日



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
PASSMAXDAYS="12" #密码最大使用天数
PASSMINDAYS="12" #密码最小使用天数
PASSMINLEN="12"  #密码最短长度
PASSWARNAGE="12" #密码到期多少天通知用户
pam_crack='retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1' #密码复杂度
pam_tally='deny=3 unlock_time=5 even_deny_root root_unlock_time=10' #密码连续输入错误锁定
REMEMBER='5' #密码重复使用次数
TMOUT='300' #超时锁定
HISTSIZE='10' #历史记录保存数量
UMASK='077'
#通过停用服务关闭不必要的端口，下面括号内服务为检测项，需仔细确认！！
SERV=(ntalk lpd kshell sendmail klogin printer nfslock discard chargen bootps daytime tftp ypbind ident)
PASSCK=(retry difok minlen ucredit lcredit dcredit)
#全局变量配置结束


#系统变量开始
mArr=()
aArr=()
passwd_flag=0
authhead=(auth account password session -session session optional required requisite sufficient)
authpam_pwqualityhead='password    requisite     pam_pwquality.so try_first_pass local_users_only authtok_type='
#系统变量结束
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

#配置函数
function mSetting(){
    case "$1" in
        PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)
            if (( $# == 2 )); then
                sed -i "/^${1}/c\\${1}  ${2}" /etc/login.defs
            else
                echo "传递参数不够，$1设置失败！"
            fi
        ;;
        pam_pwquality|3)
            if (( $2 == 0 )); then
                sed -i "s/^password.*requisite.*pam_pwquality\.so.*/& $4/" /etc/pam.d/system-auth
                echo "$1参数修改完毕！"
            else
                echo "$3 $4" >> /etc/pam.d/system-auth
                echo "$1参数增加完毕！"
            fi
            
        ;;
        *)
            echo "default"
        ;;
    esac
    
}

#密码时效配置
function mPasswordSet(){
    mSetting PASS_MAX_DAYS $PASSMAXDAYS
    mSetting PASS_MIN_DAYS $PASSMINDAYS
    mSetting PASS_MIN_LEN $PASSMINLEN
    mSetting PASS_WARN_AGE $PASSWARNAGE
    echo "密码复杂度配置完毕！"
    mPasswordCheck
}
#判断数组是否为空，为空返回 0
function isn(){
    arr=("$@")
    len=${#arr[*]}
    if [ $len == 0 ];then
        return 0
    else
        return 1
    fi
}
#备份配置文件
function mBackupSetting(){
    echo "#######################"
    echo -e "\033[1;31m 开始备份$1文件 \033[0m"
    echo -e "\033[1;31m 路径为：`dirname $1`\033[0m"
    echo -e "\033[1;31m 文件名：`basename $1`\033[0m"
    BackupTime=$(date '+%Y%m%d%H%M')
    BackupFile=$(echo "$1.meng_bak$BackupTime")
    cp $1 $BackupFile
    if [ -f $BackupFile ];then
        echo -e "\033[1;31m 备份成功，备份的文件为：$BackupFile\033[0m"
        return 0
    else
        echo -e "\033[1;31m 备份失败！请手动备份！\033[0m"
        main
    fi
}

#密码时效检测过程
function mPasswdCheck(){
    if (( $# == 4 )); then
        str=$(cat /etc/login.defs |grep -v "#"|grep "$1"|awk '{print $2}')
        if [[ $str -gt $2 ]];then
        echo -e "检查$3---结果：\033[1;31m 不符合要求 \033[0m当前值是："$str
        mArr[$4]="$1"
        else
            echo "检查$3---结果：符合要求，当前值是："$str
            unset mArr["$4"]
        fi
    else
        echo "$1传递值数量不够！"
    fi
}
#复杂度检测过程
function mPassFCheck(){
    if (( $# == 4 )); then
        cat /etc/pam.d/system-auth |grep -v "^#"|grep "$1"
        if (( $? == 0 )); then
            for item in $2; do
                cat /etc/pam.d/system-auth |grep -v "^#"|grep "$item" >> /dev/null
                if (( $? == 0 )); then
                    echo "$3检测结果： 包含$item配置项，检测合格"
                    unset aArr[$4]
                else
                    echo -e "$3检测结果：不包含$item配置项，\033[1;31m检测不通过\033[0m"
                    aArr[$4]="$1"
                fi
            done
        else
            passwd_flag=1
            echo "$3\033[1;31m检测不通过，缺少该项配置\033[0m"
            aArr[$4]="$1"
        fi
        
    else
        echo "参数数量不够！"
    fi
    
}
function mauthCheck(){
    passwd_flag=0
    mPassFCheck pam_pwquality "${PASSCK[*]}" "密码复杂度" 0 
    isn "${aArr[@]}"
    if [ $? == 0 ];then
        echo -e "\033[1;31m 所有system-auth策略都符合要求！\033[0m"
        main
    else
        read -p "是否设置system-auth策略[y/n]:" Y
        if [ "$Y" == "y" ];then
            mBackupSetting /etc/pam.d/system-auth
            if [ $? -eq 0 ];then
                mSetting pam_pwquality $passwd_flag "$authpam_pwqualityhead" "$pam_crack"
            fi
        else
            main
        fi
    fi
}
#密码时效检测结果
function mPasswordCheck(){
    mPasswdCheck PASS_MAX_DAYS $PASSMAXDAYS "密码最多使用天数" 0
    mPasswdCheck PASS_MIN_DAYS $PASSMINDAYS "密码修改最小天数" 1
    mPasswdCheck PASS_MIN_LEN $PASSMINLEN "密码最短长度" 2
    mPasswdCheck PASS_WARN_AGE $PASSWARNAGE "密码到期前通知用户天数" 3
    isn "${mArr[@]}"
    if [ $? == 0 ];then
        echo -e "\033[1;31m 所有密码策略都符合要求！\033[0m"
        main
    else
        read -p "是否设置密码策略[y/n]:" Y
        if [ "$Y" == "y" ];then
            mBackupSetting /etc/login.defs
            if [ $? -eq 0 ];then
                mPasswordSet
            fi
        else
            main
        fi
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
        mauthCheck
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