## 0x00 概述
linux命令是对Linux系统进行管理的命令，对于linux系统来说，无论是中央服务器、内存、磁盘驱动、键盘、鼠标还是用户等都是文件，linux系统管理命令是其运行的核心，分为内置shell命令和linux命令，下面总结150个常用的命令以及功能说明；
## 0x01 线上查询及帮助命令（2个）
man：查看命令帮助，命令的词典，更复杂的还有info；  
help：查看Linux内置命令的帮助，比如cd命令；
## 0x02 文件和目录操作命令（18个）
ls：list，列出目录的内容及其内容属性信息；  
cd：change directory，从当前工作目录切换到指定的工作目录；  
cp：copy，复制文件或目录；  
find：查找，用于查找目录及目录下的文件；  
mkdir：make directories，创建目录；  
mv：move，移动或重命名文件；  
pwd：print working directory，显示当前工作目录的绝对路径；  
rm：remove，删除一个或多个文件或目录；  
rmdir：remove empty directories，删除空目录；  
touch：创建新的空文件，改变已有文件的时间戳属性；  
tree：以树形结构显示目录下的内容；
basename：显示文件名或目录名；  
dirname：显示文件或目录路径；  
chattr：改变文件的扩展属性；  
lsattr：查看文件扩展属性；  
file：显示文件类型；  
md5sum：计算和校验文件的MD5值；
## 0x03 查看文件以及内容处理命令（21个）
cat：全拼concatenate，功能是用于连接多个文件并且打印到屏幕输出或重定向到指定文件中；  
tac：tac是cat的反向拼写，因此命令的功能为反向显示文件内容；  
more：分页显示文件内容；  
less：分页显示文件内容，more命令的相反用法；  
head：显示文件内容的头部；  
tail：显示文件内容的尾部；  
cut：将文件的每一行按指定分隔符分割并输出；  
split：分割文件为不同的小片段；  
paste：按行合并文件内容；  
sort：对文件的文本内容排序；  
uniq：去除重复行；  
wc：统计文件的行数、单词数或字节数；  
iconv：转换文件的编码格式；  
dos2unix：将DOS格式文件转换成UNIX格式；  
diff：difference，比较文件的差异，常用于文本文件；  
vimdiff：命令行可视化文件比较工具，常用于文本文件；  
rev：反向输出文件内容；  
grep/egrep：过滤字符串；  
join：按两个文件的相同字段合并；  
tr：替换或删除字符；  
vi/vim：命令行文本编辑器；  
## 0x04 文件压缩以及解压缩命令（4个）
tar：打包压缩；  
unzip：解压文件；  
gzip：gzip压缩工具；  
zip：压缩工作；
## 0x05 信息显示命令（11个）
uname：显示操作系统相关信息的命令；  
hostname：显示或者设置当前系统的主机名；
dmesg：显示开机信息，用于诊断系统故障；  
uptime：显示系统运行时间及负载；  
stat：显示文件或文件系统的状态；  
du：计算磁盘空间使用情况；  
df：报告文件系统磁盘空间的使用情况；  
top：实时显示系统资源使用情况；  
free：查看系统内存；  
date：显示与设置系统时间；  
cal：查看日历等事件信息；
## 0x06 搜索文件命令（4个）
which：查找二进制命令，按环境变量PATH路径查找；  
find：从磁盘遍历查找文件或目录；  
whereis：查找二进制命令，按环境变量PATH路径查找；  
locate：从数据库 (/var/lib/mlocate/mlocate.db) 查找命令，使用updatedb更新库；
## 0x07 用户管理命令（10个）
useradd：添加用户；  
usermod：修改系统中已存在的用户属性；  
userdel：删除用户；  
groupadd：添加用户组；  
passwd：修改用户密码；  
chage：修改用户密码有效期限；  
id：查看用户的uid,gid及归属的用户组；  
su：切换用户身份；  
visudo：编辑/etc/sudoers文件的专属命令；  
sudo：以另外一个用户身份（默认root用户）执行事先在sudoers文件允许的命令；
## 0x08 基础网络操作命令（11个）
telnet：使用TELNET协议远程登录；  
ssh：使用SSH加密协议远程登录；  
scp：secure copy，用于不同主机之间复制文件；  
wget：命令行下载文件；
ping：测试主机之间的网络连通性；
route：显示和设置linux系统的路由表；  
ifconfig：查看、配置、启用或禁用网络接口；  
ifup：启动网卡；  
ifdown：关闭网卡；  
netstat：查看网络状态；  
ss：查看网络状态；
## 0x09 深入网络操作命令（9个）
nmap：网络扫描命令；  
lsof：list open files，列举系统中已经被打开的文件；  
mail：发送和接收邮件；  
mutt：邮件管理命令；  
nslookup：交互式查询互联网DNS服务器的命令；  
dig：查找DNS解析过程；  
host：查询DNS的命令；  
traceroute：追踪数据传输路由状况；  
tcpdump：命令行的抓包工具；  
## 0x10 有关磁盘与文件系统的命令（16个）
mount：挂载文件系统；  
umount：卸载文件系统；  
fsck：检查并修复Linux文件系统；  
dd：转换或复制文件；  
dumpe2fs： 导出ext2/ext3/ext4文件系统信息；  
fdisk：磁盘分区命令，适用于2TB以下磁盘分区；  
parted：磁盘分区命令，没有磁盘大小限制；  
mkfs：格式化创建Linux文件系统；  
partprobe：更新内核的硬盘分区表信息；  
e2fsck：检查ext2/ext3/ext4类型文件系统；  
mkswap：创建Linux交换分区；  
swapon：启用交换分区；  
swapoff：关闭交换分区；  
sync：将内存缓冲区内的数据写入磁盘；  
resize2fs：调整ext2/ext3/ext4文件系统大小；
## 0x11 系统权限及用户授权相关命令（4个）
chmod：改变文件或目录权限；  
chown：改变文件或目录的属主和属组；
chgrp：更改文件用户组；  
umask：显示或设置权限掩码；  
## 0x12 查看系统用户登陆信息的命令（7个）
whoami：显示当前有效的用户名称，相当于执行id -un命令；  
who：显示目前登录系统的用户信息；  
w：显示已经登陆系统的用户列表，并显示用户正在执行的指令；  
last：显示登录系统的用户；  
lastlog：显示系统中所有用户最近一次登录信息；  
users：显示当前登录系统的所有用户的用户列表；  
finger：查找并显示用户信息；
## 0x13 内置命令及其它（19个）
echo：打印变量，或直接输出指定的字符串；  
printf：将结果格式化输出到标准输出；  
rpm：管理rpm包的命令；  
yum：自动化管理rpm包的命令；  
watch：周期性的执行给定的命令，并将命令的输出以全屏方式显示；  
alias：设置别名；  
unalias：取消别名；  
date：查看系统时间；  
clear：清屏；  
history：查看命令执行的历史记录；  
eject：弹出光驱；  
time：计算命令执行时间；  
nc：功能强大的网络工具；  
xargs：将标准输入转换成命令行参数；  
exec：调用并执行指令的命令；  
export：设置或者显示环境变量；  
unset：删除变量或函数；  
type：用于判断另外一个命令是否是内置命令；  
bc：命令行科学计算器；
## 0x14 系统管理与性能监视命令（9个）
chkconfig：管理Linux系统开机启动项；  
vmstat：虚拟内存统计；  
mpstat：显示各个可用CPU的状态统计；
iostat：统计系统IO；  
sar：全面地获取系统的CPU、运行队列、磁盘 I/O、分页（交换区）、内存等性能数据；  
ipcs：用于报告Linux中进程间通信设施的状态，显示的信息包括消息列表、共享内存和信号量的信息；  
ipcrm：用来删除一个或更多的消息队列、信号量集或者共享内存标识；
strace：用于诊断、调试Linux用户空间跟踪器；  
itrace：命令会跟踪进程的库函数调用,它会显现出哪个库函数被调用；
## 0x15 关机/重启/注销和查看系统信息的命令（6个）
shutdown：关机；  
halt：关机；  
poweroff：关闭电源；  
logout：退出当前登录的shell；  
exit：退出当前登录的shell；  
ctrl+d：退出当前登录的Shell的快捷键；
## 0x16 进程管理相关命令（15个）
bg：将一个在后台暂停的命令，变成继续执行（在后台执行）；  
fg：将后台中的命令调至前台继续运行；  
jobs：查看当前有多少在后台运行的命令；  
kill：终止进程；  
killall：通过进程名终止进程；  
pkill：通过进程名终止进程；  
crontab：定时任务；  
ps：显示进程快照；
pstree：树形显示进程；  
nice/renice：调整程序运行的优先级；  
nohup：忽略挂起信号运行指定的命令；  
pgrep：查找匹配条件的进程；  
runlevel：查看系统当前运行级别；  
init：切换运行级别；  
service：启动、停止、重新启动和关闭系统服务，还可以显示所有系统服务的当前状态；

