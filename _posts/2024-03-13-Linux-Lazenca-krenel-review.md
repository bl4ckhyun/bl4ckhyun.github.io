---
layout: post
title: "Lazenca : krenel review"
date: '2024-3-13 11:11:11 +0900'
description: 'Review about Kernel of Lazenca'
categories: [Dev&Backorund, Linux]
tags: [linux, kernel, Review]
---

# Before Start
>linux kenel CVE 분석에 앞서, 기본적인 내용을 공부하기 위해 [Lazenca](https://www.lazenca.net/display/TEC/07.Linux+Kernel+exploitation+techniques)에 있는 내용을 공부하려고 합니다.  
>그냥 무지성 노력이 아닌, 잘하기 위해 노력해 보겠습니다.

# Simple Linux kernel Module
* Linux kernel module을 만들기 위해 아래 패키지를 설치한다.

```
apt-get install build-essential linux-headers-$(uname -r)
```
* `module_init()` 매크로를 사용하여 커널에게 모듈의 초기화 함수를 지정합니다
* `module_exit()` 매크로를 사용하여 커널에게 모듈의 종료 함수를 지정합니다
* `printk()` 리눅스 커널에서 사용되는 표준 출력 함수로, 커널 내부에서 메시지를 출력하고 로그를 기록하는 데 사용된다

```c
#include <linux/module.h>
#include <linux/kernel.h>  
#include <linux/init.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OfficaLee"); 
MODULE_DESCRIPTION("Simple Hello World module");

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello world!\n");
    return 0;    
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
```

### Kernel module 삽입
```bash
$ insmod hello.ko

$ dmesg | tail -1
 [ 8394.731865] Hello world!

$ rmmod hello.ko

$ dmesg | tail -1
 [ 8707.989819] Cleaning up module. 
```

* `insmod` : kernel module을 로드한다.
* `dmesg` : Linux 운영 체제에서 커널 메시지 버퍼(Kernel Message Buffer)를 출력한다.
* `rmmod` : kernel module을 삭제한다.

## printk, log level
`printk()`는 유저와 통신하기 위한 함수가 아니다.
* printk는 Linux 커널에서 메시지를 출력하는 함수입니다.
* 커널 코드 내에서 printk를 사용하여 디버깅, 상태 확인, 오류 보고 등을 할 수 있습니다.
* 커널 메시지는 커널 메시지 버퍼에 저장되며, dmesg 명령어로 확인할 수 있습니다.

# User Space VS Kernel Space
<p align="left">
<img src ="https://github.com/hyuntaeLee/hyuntaeLee.github.io/assets/97331148/4bbb95fe-dab9-47ec-ae3d-a68b3a29d588" alt="image" width = 500>
</p>

* `Kernel`: 운영 체제의 핵심 부분으로, 시스템 자원 관리, 프로세스 관리, 메모리 관리 등의 기능을 수행한다.
* `Ring 0, Ring 1, Ring 2, Ring 3`: 운영 체제 아키텍처의 특권 수준을 나타낸다. Ring 0이 가장 높은 특권 수준으로, 커널과 일부 시스템 드라이버가 이 수준에서 동작한다. 사용자 애플리케이션은 Ring 3에서 실행된다.
* `Device drivers`: 하드웨어 장치들을 제어하고 관리하는 드라이버 계층이다.
* `Applications`: 사용자 애플리케이션 계층이다.  

사용자 Application에서 사용하는 라이브러리 함수들은 실제 시스템 자원에 접근하기 위해서는 kernel의 도움이 필요하다. 이를 위해 애플리케이션은 **시스템 호출(system call)** 을 통해 kernel에 요청을 한다.
>예를 들어 printf() 함수를 호출하면, printf() 함수는 내부적으로 write() 시스템 호출을 수행한다. 이때 커널은 supervisor 모드로 전환되어 입출력 처리를 담당하고, 처리가 완료되면 다시 사용자 모드로 돌아온다



### reference
* [https://www.lazenca.net/pages/viewpage.action?pageId=23789735](https://www.lazenca.net/pages/viewpage.action?pageId=23789735)
* [https://velog.io/@msh1307/Linux-Kernel-module-Programming](https://www.lazenca.net/pages/viewpage.action?pageId=23789735)