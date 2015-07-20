#!/bin/bash

echo ">>> Get all IOC Files"

sudo last > ~/ATFM/Honeypot_Raspberry/datas/last.ioc
sudo w > ~/ATFM/Honeypot_Raspberry/datas/w.ioc
sudo ls / -lat > ~/ATFM/Honeypot_Raspberry/datas/ls.ioc
sudo ps aux > ~/ATFM/Honeypot_Raspberry/datas/ps_aux.ioc
sudo ps elf > ~/ATFM/Honeypot_Raspberry/datas/ps_elf.ioc
sudo lsof > ~/ATFM/Honeypot_Raspberry/datas/lsof.ioc
sudo date > ~/ATFM/Honeypot_Raspberry/datas/date.ioc
sudo netstat > ~/ATFM/Honeypot_Raspberry/datas/netstat.ioc
cat ~/.bash_history > ~/ATFM/Honeypot_Raspberry/datas/bash_history.ioc
sudo cat /root/.bash_history > ~/ATFM/Honeypot_Raspberry/datas/bash_history_root.ioc
sudo chown pi:pi ~/ATFM/Honeypot_Raspberry/datas/*

echo ">>> Clean some important files"
sudo truncate -s 0 /root/.bash_history
sudo truncate -s 0 ~/.bash_history

