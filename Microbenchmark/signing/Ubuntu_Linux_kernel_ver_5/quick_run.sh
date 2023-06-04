#!/bin/bash

sudo dmesg --clear
sudo insmod quick512.ko len=64
sudo dmesg
sudo rmmod quick512


sudo dmesg --clear
sudo insmod quick512.ko  len=128
sudo dmesg
sudo rmmod quick512

sudo dmesg --clear
sudo insmod quick512.ko  
sudo dmesg
sudo rmmod quick512

sudo dmesg --clear
sudo insmod quick512.ko  len=320
sudo dmesg
sudo rmmod quick512

sudo dmesg --clear
sudo insmod quick512.ko  len=384
sudo dmesg
sudo rmmod quick512