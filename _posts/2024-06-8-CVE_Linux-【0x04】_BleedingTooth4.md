---
layout: post
title: "BleedingTooth_0x04 : BleedingTooth Exploit"
date: '2024-6-10 11:11:11 +0900'
description: 'about BleedingTooth Exploit'
categories: [Vulnerability, Linux_Kernel]
tags: [CVE, Linux, Analysis, Bluetooth]
---

## **BleedingTooth : Exploitation**

### **Summery Before Start**
* **Target Version** : Linux kernel 4.19 (with Bluetooth 5)
* **Vulnerabilities**
    * BadVibes: Heap-Based Buffer Overflow (CVE-2020-24490)
    * BadChoice: Stack-Based Information Leak (CVE-2020-12352)
    * BadKarma: Heap-Based Type Confusion (CVE-2020-12351)
* **Understanding the Attack Surface**
    * BleedingTooth는 Linux Bluetooth 서브시스템의 zero-click vulnerabilities 집합으로, unauthenticated remote attacker가 근접한 거리에서 취약한 장치에 대해 커널 권한으로 임의의 코드를 실행할 수 있게 한다. 이 취약점들은 Linux 기반 IoT 장치에 핵심 Bluetooth 계층과 프로토콜을 지원하는 BlueZ 프로토콜 스택에 영향을 미친다.
* **Exploitation Process**
* BleedingTooth의 공격은 원격 코드 실행을 달성하기 위해 여러 취약점을 연계해야 한다.
    * **Info leak** : 공격자는 먼저 BadChoice 취약점(CVE-2020-12352)을 사용하여 커널 스택 정보를 유출한다. 이 정보는 메모리 레이아웃을 예측하고 KASLR(Kernel Address Space Layout Randomization)을 무력화하는 데 사용된다.
    * **Memory Corruption**: 그 다음 BadVibes 취약점(CVE-2020-24490)을 이용하여 힙 기반 버퍼 오버플로우를 일으킨다.
    * **Code Execution** : BadKarma 취약점(CVE-2020-12351)을 활용하여 임의 코드 실행을 한다. 공격자가 악의적인 l2cap 패킷을 보내 잠재적으로 커널 권한으로 코드 실행을 할 수 있게 한다.