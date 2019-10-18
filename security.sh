#!/bin/bash -
###################################################################################################################################################
#security.sh
#author:dongfeng
#date:2019-03-27
###################################################################################################################################################
function test_input() {
	while :
	do
		read -p "$1:" tmp
		if [ "$tmp" -gt 0 ] 2>/dev/null;then
			eval $2=$tmp
			break
		else
			echo -e "\033[31m输入非法！\033[0m"
			continue
		fi
	done
}

function set_passwd() {
	[[ ! -f /etc/login.defs.bak ]] && cp -rf /etc/login.defs /etc/login.defs.bak
	[[ ! -f /etc/pam.d/system-auth.bak ]] && cp -rf /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
	[[ ! -f /etc/pam.d/sshd.bak ]] && cp -rf /etc/pam.d/sshd /etc/pam.d/sshd.bak
	test_input "设置密码最多可多少天不修改[90]" A
	test_input "设置密码修改之间最小的天数[10]" B
	test_input "设置密码最短的长度[8]" C
	test_input "设置密码失效前多少天通知用户[7]" D
	sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   '$A'' /etc/login.defs
	sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   '$B'' /etc/login.defs
	sed -i '/^PASS_MIN_LEN/c\PASS_MIN_LEN     '$C'' /etc/login.defs
	sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   '$D'' /etc/login.defs
 	echo -e "\033[32m已对密码进行加固，新用户不得和旧密码相同，且新密码必须同时包含数字、小写字母，大写字母！！\033[0m"
	sed -i '/pam_pwquality.so/c\password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=  difok=1 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1' /etc/pam.d/system-auth 
	echo -e "\033[32m已对密码进行加固，如果输入错误密码超过3次，则锁定账户！！\033[0m"
	n=`cat /etc/pam.d/sshd | grep "auth required pam_tally2.so "|wc -l`
	if [ $n -eq 0 ];then
		sed -i '/%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=150 even_deny_root root_unlock_time=300' /etc/pam.d/sshd
	fi
}

function unset_passwd() {
	[[ -f /etc/login.defs.bak ]] && cp -rf /etc/login.defs.bak /etc/login.defs
	[[ -f /etc/pam.d/system-auth.bak ]] && cp -rf /etc/pam.d/system-auth.bak /etc/pam.d/system-auth
	[[ -f /etc/pam.d/sshd.bak ]] && cp -rf /etc/pam.d/sshd.bak /etc/pam.d/sshd
}

function set_rootlogin() {
	[[ ! -f /etc/ssh/sshd_config.bak ]] && cp -rf /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
	sed -i '/PermitRootLogin/c\PermitRootLogin no'  /etc/ssh/sshd_config
	systemctl restart sshd.service
	echo -e "\033[32m已设置禁止root用户远程登录！！\033[0m"
}

function unset_rootlogin() {
	[[ -f /etc/ssh/sshd_config.bak ]] && cp -rf /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
	systemctl restart sshd.service
}

function set_history_timeout() {
	[[ ! -f /etc/profile.bak ]] && cp -rf /etc/profile /etc/profile.bak
	[[ ! -f /etc/bashrc.bak ]] && cp -rf /etc/bashrc /etc/bashrc.bak
	test_input "设置账户自动注销时间[300]" F
	sed -i '/^HISTSIZE/a\TMOUT='$F'' /etc/profile
	test_input "设置历史命令保存条数[1000]" E
	sed -i '/^HISTSIZE/c\HISTSIZE='$E'' /etc/profile
	source /etc/profile
	cat /etc/passwd | grep "^epc:" || echo -e "\033[32m已添加用户\033[31mepc \033[32m默认密码\033[31mEPC@baicells\033[0m"
	useradd epc && echo epc:EPC@baicells | chpasswd && usermod -g epc -G wheel,epc epc
	local file_cfg='/etc/bashrc'
	local prompt_command_format='{ date "+%Y-%m-%d %T ##### $(who am i |awk "{print \$1\" \"\$2\" \"\$5}") #### $(pwd) #### $(history 1 | { read x cmd; echo "$cmd"; })"; } >> /home/epc/history.log'
	source $file_cfg
	[[ ! -d /home/epc ]] && mkdir -p /home/epc
	[[ ! -f /home/epc/history.log ]] && touch /home/epc/history.log
	chown epc:epc /home/epc/history.log
	chmod 666 /home/epc/history.log
	sed -i "/.*\(export PROMPT_COMMAND=\).*/d" $file_cfg
	echo "export PROMPT_COMMAND='$prompt_command_format'" >> $file_cfg
	echo -e "\033[32m已对操作日志进行记录：/home/epc/history.log\033[0m"
}

function unset_history_timeout() {
	[[ -f /etc/profile.bak ]] && cp -rf /etc/profile.bak /etc/profile
	[[ -f /etc/bashrc.bak ]] && cp -rf /etc/bashrc.bak /etc/bashrc
	source /etc/profile
	source /etc/bashrc
}

function set_su() {
	[[ ! -f /etc/pam.d/su.bak ]] && cp -rf /etc/pam.d/su /etc/pam.d/su.bak
	[[ ! -f /etc/login.defs.bak ]] && cp -rf /etc/login.defs /etc/login.defs.bak
	sed -i '/pam_wheel.so use_uid/c\auth            required        pam_wheel.so use_uid ' /etc/pam.d/su
	n=`cat /etc/login.defs | grep SU_WHEEL_ONLY | wc -l`
	if [ $n -eq 0 ];then
		echo SU_WHEEL_ONLY yes >> /etc/login.defs
	fi
	echo -e "\033[32m已设置只允许wheel组的用户可以使用su命令切换到root用户！\033[0m"
}

function unset_su() {
	[[ -f /etc/pam.d/su.bak ]] && cp -rf /etc/pam.d/su.bak /etc/pam.d/su
	[[ -f /etc/login.defs.bak ]] && cp -rf /etc/login.defs.bak /etc/login.defs
}

function check_user() {
	echo "即将对系统中的账户进行检查...."
	echo "系统中有登录权限的用户有："
	awk -F: '($7=="/bin/bash"){print $1}' /etc/passwd
	echo "********************************************"
	echo -e "系统中UID=0的用户有：\033[34m$(awk -F: '($3=="0"){print $1}' /etc/passwd)\033[0m"
	echo "********************************************"
	N=`awk -F: '($2==""){print $1}' /etc/shadow|wc -l`
	echo -e "系统中空密码用户有：\033[34m$N\033[0m"
	if [ $N -eq 0 ];then
		echo -e "\033[32m系统中无空密码用户！！\033[0m"
 		echo "********************************************"
	else
 		i=1
 		while [ $N -gt 0 ]
 		do
    		None=`awk -F: '($2==""){print $1}' /etc/shadow|awk 'NR=='$i'{print}'`
    		echo "------------------------"
    		echo $None
    		echo -e "\033[31m必须为空用户设置密码！！\033[0m"
    		passwd $None
    		let N--
 		done
 		M=`awk -F: '($2==""){print $1}' /etc/shadow|wc -l`
 		if [ $M -eq 0 ];then
  			echo -e "\033[32m系统中已经没有空密码用户了！\033[0m"
 		else
			echo -e"\033[31m系统中还存在空密码用户：$M\033[0m"
 		fi
	fi
}

function lock_file() {
	echo "即将对系统中重要文件进行锁定，锁定后将无法添加删除用户和组"
	read -p "警告：此脚本运行后将无法添加删除用户和组！！确定输入Y，取消输入N；Y/N：" i
	case $i in
	[Y,y])
		chattr +i /etc/passwd
		chattr +i /etc/shadow
		chattr +i /etc/group
		chattr +i /etc/gshadow
		echo "锁定成功！";;
	[N,n])
		chattr -i /etc/passwd
		chattr -i /etc/shadow
		chattr -i /etc/group
		chattr -i /etc/gshadow
		echo "取消锁定成功！！";;
	*)
		echo "请输入Y/y or  N/n"
	esac
}

function unlock_file() {
	chattr -i /etc/passwd
	chattr -i /etc/shadow
	chattr -i /etc/group
	chattr -i /etc/gshadow
}

function set_sshd() {
	[[ ! -f /etc/ssh/sshd_config.bak ]] && cp -rf /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
	sed -i '/Port 22/c\Port 50683' /etc/ssh/sshd_config
	systemctl restart sshd.service
	echo -e "\033[32m已改变SSH默认登录端口22->50683\033[0m"
} 

function unset_sshd() {
	[[ -f /etc/ssh/sshd_config.bak ]] && cp -rf /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
	systemctl restart sshd.service
}

function clear_iptables() {
	iptables -F          
	iptables -F -t nat  
	iptables -X         
	iptables -X -t nat	
	iptables -Z         
	iptables -Z -t nat  
}

function default_policy_iptables() {
	iptables -P INPUT ACCEPT      
	iptables -P OUTPUT ACCEPT     
	iptables -P FORWARD ACCEPT    
}

function test_interface() {
	local interface=$(ifconfig | awk -F: '/mtu/{print $1}' | sort -u)
	echo "本机所有接口如下："
	echo $interface
	while :
	do
		read -p "请输入应用iptables的公网接口:" interface_tmp
		local flag=("true")
		for interface_i in $interface_tmp
		do
			local flag_i=false
			for interface_j in $interface
			do
				if [[ $interface_i == $interface_j ]];then
					flag_i=true
					break
				fi
			done
			flag+=("$flag_i")
		done
		for f in ${flag[@]}
		do
			if [[ $f != "true" ]];then
				continue 2
			fi
		done
		interface_name=$interface_tmp
		return 0
	done
}


function check_ipaddr()
{
	while :
	do
		local f1=true
		local f2=true
		read -p "请输入允许访问redis的IP地址：" ip_tmp
		for ip in $ip_tmp
		do
			echo $ip | grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}$" > /dev/null;
			if [ $? -ne 0 ];then
				echo -e "\033[31mIP地址必须全部为1-3位数字\033[0m"
				f1=false	
				break
			fi
			ipaddr=$ip
			a=`echo $ipaddr|awk -F . '{print $1}'` 
			b=`echo $ipaddr|awk -F . '{print $2}'`
			c=`echo $ipaddr|awk -F . '{print $3}'`
			d=`echo $ipaddr|awk -F . '{print $4}'`
			for num in $a $b $c $d
			do
				if [ $num -gt 255 ] || [ $num -lt 0 ];then
					echo -e "\033[31m$ipaddr 中，字段$num错误\033[0m" 
					f2=false
					break
				fi
			done
		done
		if [[ $f1 == "true" ]] && [[ $f2 == "true" ]];then
			redis_ip=$ip_tmp
			return 0
		fi
	done
}

function add_firewalld_iptables() {
	test_interface
	check_ipaddr
	for interface_one in $interface_name
	do	
		iptables -A INPUT -p tcp --dport 50683 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p tcp --dport 6633 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p tcp --dport 6640 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p tcp --dport 80 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p tcp --dport 8080 -i ${interface_one} -j ACCEPT
		#iptables -A INPUT -p tcp --dport 3306 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2123 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2124 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2125 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2100 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2101 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2102 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2103 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2104 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p sctp --dport 36412 -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p udp --dport 2152 -i ${interface_one} -j ACCEPT
		for ip in $redis_ip
		do
			iptables -A INPUT -s $ip -p tcp --dport 6379 -i ${interface_one} -j ACCEPT
		done
		iptables -A INPUT -m state --state RELATED,ESTABLISHED -i ${interface_one} -j ACCEPT
		iptables -A INPUT -p icmp -i ${interface_one} -j ACCEPT
		[[ $interface_one ]] && iptables -A INPUT -p all -i ${interface_one} -j DROP
		echo -e "\033[32m已对公网接口\033[34m$interface_one\033[32m添加iptables规则\033[0m"
	done
}

function install_iptables_services() {
	yum install -y epel-release &>/dev/null
	yum install -y iptables-services &>/dev/null
	systemctl enable iptables &>/dev/null
	systemctl start iptables &>/dev/null
	echo -e "\033[32m已启用iptables-services!\033[0m"
}

function set_iptables() {
	clear_iptables
	default_policy_iptables
	add_firewalld_iptables
	service iptables save
}

function unset_iptables() {
	clear_iptables
	service iptables save
}

function main() {
	set_passwd
	set_rootlogin
	set_history_timeout
	set_su
	check_user
	#lock_file
	set_sshd
	install_iptables_services
	set_iptables
}

function unset_main() {
	unset_passwd
	unset_rootlogin
	unset_history_timeout
	unset_su
	#unlock_file
	unset_sshd
	unset_iptables
}

case "$1" in
"")
	main
	exit;;
"-d")
	unset_main
	exit;;
"-h")
	echo "**************************"
	echo "$0       安装"
	echo "$0 -d    卸载"
	echo "$0 -h    帮助"
	echo "**************************"
esac
