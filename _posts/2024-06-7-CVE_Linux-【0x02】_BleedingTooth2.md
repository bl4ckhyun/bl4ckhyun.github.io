---
layout: post
title: "BleedingTooth_0x02 : CVE-2020-12352"
date: '2024-6-7 11:11:11 +0900'
description: 'CVE about BleedingTooth'
categories: [Vulnerability, Linux_Kernel]
tags: [CVE, Linux, Analysis, Bluetooth]
---

## **BadChoice: Stack-Based Information Leak (CVE-2020-12352)**

이전 포스트에서 설명한 BadVibes 취약점은 임의의 값을을 R/W 를 하기에 충분하지 않은 취약점이고, victim의 메모리 레이아웃을 유출할 방법이 없어 보인다다.
- **why?**
  - 손상될 수 있는 유일한 중요 멤버는 순환 리스트에 대한 포인터임.
  - 순환 데이터 구조이므로 시작점으로 다시 돌아가도록 보장하지 않고는 변경할 수 없음.
  - victim의 메모리 레이아웃이 무작위화되어 있어 이 요구사항을 충족하기 어려움.

따라서 BadVibes를 악용하려면 먼저 메모리 레이아웃에 대한 정보가 필요하다. <br>
구체적으로, 공격자가 제어하거나 예측할 수 있는 내용을 가진 피해자의 메모리 주소를 유출해야 한다.

일반적으로 info leak은 아래와 같은 방법을 이용한다.
- Out-of-Bounds Access
- Use of Uninitialized Variables
- Execution of Side-Channel/Timing Attacks

해당 취약점 발견자는 1,2번에 초점을 맞춰서, 공격자에게 정보를 반환하는 모든 서브루틴을 검토하여 Out-of-Bounds OR Uninitialized memory leak이 가능한지 찾아봤다고 한다.

그 결과, A2MP 프로토콜의 A2MP_GETINFO_REQ 명령에서 두 번째 취약점을 발견했다. 이 취약점은 Linux 커널 3.6 이후부터 존재했으며, CONFIG_BT_HS=y가 설정된 경우(기본적으로 활성화됨) 접근 가능하다.

A2MP_GETINFO_REQ 명령에 의해 호출되는 a2mp_getinfo_req() 서브루틴을 살펴보면 취약점의 세부 사항을 확인할 수 있습니다.

```c
static int a2mp_getinfo_req(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_req *req  = (void *) skb->data;
	struct hci_dev *hdev;
	struct hci_request hreq;
	int err = 0;

	if (le16_to_cpu(hdr->len) < sizeof(*req))
		return -EINVAL;

	BT_DBG("id %d", req->id);

	hdev = hci_dev_get(req->id);
	if (!hdev || hdev->dev_type != HCI_AMP) {
		struct a2mp_info_rsp rsp;                 // kernel stack에 할당됨

                                              // 아래 와 같이 총 2개만 초기화
		rsp.id = req->id;                         // rsp-> id
		rsp.status = A2MP_STATUS_INVALID_CTRL_ID; // rsp-? A2MP_STATUS_INVALID_CTRL_ID

		a2mp_send(mgr, A2MP_GETINFO_RSP, hdr->ident, sizeof(rsp),
			  &rsp);

		****goto done;
	}
...

done:
	if (hdev)
		hci_dev_put(hdev);

	skb_pull(skb, sizeof(*req));
	return 0;
}

...
#define A2MP_GETINFO_RSP         0x07
struct a2mp_info_rsp {
	__u8	id;
	__u8	status;
	__le32	total_bw;
	__le32	max_bw;
	__le32	min_latency;
	__le16	pal_cap;
	__le16	assoc_size;
} __packed;
```

- `A2MP_GETINFO_REQ` 명령은 `a2mp_getinfo_req` 함수를 호출
- `a2mp_info_rsp` 구조체를 선언한다
- `rsp`구조체의 일부 필드만 초기화된다 (2개).
- 나머지 필드들은 초기화되지 않은 채로 남아있어, 이전에 해당 메모리 위치에 있던 값들을 그대로 가지고 있을 수 있다.
- 이 스택은 커널 공간에 위치하기 때문에, 초기화되지 않은 "쓰레기 값"들은 커널 주소를 포함할 가능성이 높다.

> **just saying**
>해당 함수내에서 hdev가 없거나 hdev→dev_type이 HCI_AMP가 아니라면, victim에게 A2MP_STATUS_INVALID_CTRL_ID를 a2mp_info_rsp 구조체를 통해 전달한다. 이때 초기화하는 필드는 id와 status 뿐이고, 커널 내에 할당된 영역이기 때문에 초기화되지 않은 필드(16바이트)에는 커널 내부 주소가 쓰레기 값으로 들어있을 것이다.<br>
> ⇒ 16바이트만큼 leak가능
><br><br>
>이 구조체를 attacker에게 보내기 전에 스택 프레임에 유용한 주소를 가지고 있는(kernel base를 leak할 수 있는?) pointer들을 채워넣고 a2mp_geinfo_req가 이를 재사용할 수 있게 만들면 info leak을 시도할 수 있다.
><br>
> ⇒ 이것도 CONFIG_INIT_STACK_ALL_PATTERN을 설정해주면 막힘

### reference

[https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq)<br>
[BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html#badvibes-heap-based-buffer-overflow-cve-2020-24490)<br>
with Changhyun Lee
