---
layout: post
title: "BleedingTooth_0x01 : CVE-2020-24490"
date: '2024-6-5 11:11:11 +0900'
description: 'CVE about BleedingTooth'
categories: [Vulnerability, Linux_Kernel]
tags: [CVE, Linux, Analysis, Bluetooth]
---

# **Introduction**

- 필자는 syzkaller에 의해 bluetooth와 같은 하위 시스템은 그렇게 잘 커버되지 않을 인지
- 대부분의 공객된 bluetooth 취약점
    1. 펌웨어나 사양 자체에만 영향을 미친다
    2. 공격자가 정보를 엿듣거나 조작할수 있게만 했다
- 필자는 아래와 같은 질문을 하게 된다.
    - 공격자가 기기를 완저히 제어할 수 있다면 어떨까?
        - 해당 질문에 걸맞는 시나리오 예시
            1. BlueBorne
            2. BlueFrag
- 필자가 해당 프로젝트에서의 목표
    - Blueborne의 연구 결과를 기반으로 Bluetooth에서 유사한 취약점을 발견 및 분석
    - **syzkaller을 /dev/vhci 장치를 퍼징할 수 있는 기능으로 확장하는 것**
- 결과
    - 고위험성 취약점을 발견하며, 결국 x86-64 Ubuntu 20.04.1을 대상으로 하는 완전한 RCE(원격 코드 실행) 익스플로잇을 체인으로 연결

# **Vulnerabilities**

- Bluetooth chip은 HCI프로토콜을 사용해서 Host(운영체제)와 통신한다.
- 일반적인 패킷 종류
    - Command packets –호스트에서 컨트롤러로 보냅니다.
    - Event packets – 이벤트에 대해 알리기 위해 컨트롤러에서 호스트로 보냅니다.
    - Data packets – 보통 전송 계층을 구현하는 L2CAP(Logical Link Control and Adaptation Protocol) 패킷을 운반합니다.
- A2MP(AMP Manager Protocol) 또는 SMP(Security Management Protocol)와 같은 상위 프로토콜은 L2CAP 위에 구축된다.
    - 이러한 모든 프로토콜이 인증 없이 노출되며, 이 프로토콜 중 일부는 심지어 커널 내부에 존재하기 때문에 여기에 있는 취약점은 매우 중요하다.
- 발견된 취약점
    - **BadVibes (CVE-2020-24490)**
    - **BadChoice (CVE-2020-12352)**
    - **BadKarma (CVE-2020-12351)**

## **BadVibes: Heap-Based Buffer Overflow (CVE-2020-24490)**

- **공격 조건**
	- Linux kernel 4.19 (with Bluetooth 5)
	- 스캐닝 모드가 활성화된 상태
	- 공격자가 근거리에 위치

- **공격 방법**
	- 공격자는 Extended Advertising data를 브로드캐스트 할수 있어야함
	- 시퀀스 다이어그램에서 보이는 'Advertise Packet' 메시지를 악용

![Desktop View](/assets/images/data/blue1.png)

>스캐닝 모드란?<br>
>주변의 연결 가능한 BluetoothLE 장치의 이름과 주소를 검색한다.<br>
>간단하게 페어링이라고 생각하면 된다.

HCI 이벤트 패킷은 보통 해커가 직접 조작할 수 없지만(블루투스 펌웨어까지 제어권을 가진 경우에 한함), 블루투스 칩에서 생성되어 원격 블루투스 기기에서 오는 **advertisement reports**를 파싱하는 목적의 두 가지 유사한 메서드인 `hci_le_adv_report_evt()`와 `hci_le_ext_adv_report_evt()`가 있다.

이 **reports**의 크기는 가변적이다.

`hci_le_ext_adv_report_evt` 는 `hci_le_adv_report_evt`를 기반으로 만든 extended advertising report events를 처리하기 위한 함수

```c
//https://elixir.bootlin.com/linux/v4.19.136/source/net/bluetooth/hci_event.c#L5314
static void hci_le_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_advertising_info *ev = ptr;
		s8 rssi;

		if (ev->length <= HCI_MAX_AD_LENGTH) {                    
			rssi = ev->data[ev->length];
			process_adv_report(hdev, ev->evt_type, &ev->bdaddr,  //process_adv_report()
					   ev->bdaddr_type, NULL, 0, rssi,
					   ev->data, ev->length);
		} else {
			bt_dev_err(hdev, "Dropping invalid advertising data");
		}

		ptr += sizeof(*ev) + ev->length + 1;
	}

	hci_dev_unlock(hdev);
}

....

//https://elixir.bootlin.com/linux/v4.19.136/source/net/bluetooth/hci_event.c#L5386
static void hci_le_ext_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_ext_adv_report *ev = ptr;
		u8 legacy_evt_type;
		u16 evt_type;

		evt_type = __le16_to_cpu(ev->evt_type);
		legacy_evt_type = ext_evt_type_to_legacy(evt_type);
		if (legacy_evt_type != LE_ADV_INVALID) {
			process_adv_report(hdev, legacy_evt_type, &ev->bdaddr,  //rocess_adv_report()
					   ev->bdaddr_type, NULL, 0, ev->rssi,
					   ev->data, ev->length);
		}

		ptr += sizeof(*ev) + ev->length + 1;
	}

	hci_dev_unlock(hdev);
}
```

- 첫번째 함수 `hci_le_adv_report_evt()` 는  `ev->length` 를 확인하는 부분이 존재
- 두번째 함수`hci_le_ext_adv_report_evt()` 는 `ev->length` 를 확인하는 부분이 존재하지 않는다.
    - 하지만, 해당 함수가 확장된 이벤트인 extended advertising report events를 처리하기 때문에 의도된 코드라고 생각된다.
    - `ev->length` 는 8비트이기 때문에, 확장된 advertising events는 최대 255바이트만 될수있다.
    - `struct ev`
        
        ```c
        struct hci_ev_le_ext_adv_report {
        	__le16 	 evt_type;
        	__u8	 bdaddr_type;
        	bdaddr_t bdaddr;
        	__u8	 primary_phy;
        	__u8	 secondary_phy;
        	__u8	 sid;
        	__u8	 tx_power;
        	__s8	 rssi;
        	__le16 	 interval;
        	__u8  	 direct_addr_type;
        	bdaddr_t direct_addr;
        	__u8  	 length;
        	__u8	 data[0];
        } __packed;
        ```
        

- `process_adv_report()`
    - 본격적으로, 해당함수에서 event를 처리하는거 같다.
    - if the advertiser is doing **indirect advertisement** and the recipient is doing **active scanning**
        - 그리고, 해당 함수에 있는 `store_pending_adv_report()` 를 통해서 저장된다.

```c
//https://elixir.bootlin.com/linux/v4.19.136/source/net/bluetooth/hci_event.c#L5117
static void process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
			       u8 bdaddr_type, bdaddr_t *direct_addr,
			       u8 direct_addr_type, s8 rssi, u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;
	struct smp_irk *irk;
	struct hci_conn *conn;
	bool match;
	u32 flags;
	u8 *ptr, real_len;

	switch (type) {
	case LE_ADV_IND:
	case LE_ADV_DIRECT_IND:
	case LE_ADV_SCAN_IND:
	case LE_ADV_NONCONN_IND:
	case LE_ADV_SCAN_RSP:
		break;
	default:
		bt_dev_err_ratelimited(hdev, "unknown advertising packet "
				       "type: 0x%02x", type);
		return;
	}

	...
	
	if (!has_pending_adv_report(hdev)) {
		...
		if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
			store_pending_adv_report(hdev, bdaddr, bdaddr_type,  //store_pending_adv_report()
						 rssi, flags, data, len);
			return;
		}
		...
	}
	...
}
```

The `store_pending_adv_report()` subroutine copies the data into `d->last_adv_data`.

```c
//https://elixir.bootlin.com/linux/v4.19.136/source/net/bluetooth/hci_event.c#L1226
static void store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
				     u8 bdaddr_type, s8 rssi, u32 flags,
				     u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;

	bacpy(&d->last_adv_addr, bdaddr);
	d->last_adv_addr_type = bdaddr_type;
	d->last_adv_rssi = rssi;
	d->last_adv_flags = flags;
	memcpy(d->last_adv_data, data, len);
	d->last_adv_data_len = len;
}
```

- `store_pending_adv_report()` 에서 memcpy를 하는데
    - `last_adv_data`는 Bluetooth advertise data 를 저장하는 버퍼이다.
    - 그리고 버퍼의 크기가 `HCI_MAX_AD_LENGTH=31bytes` 로 정의되어 있다.
- Bluetooth 4.0에서 Advertising payload는 31byte였는데, Bluetooth 5에서 지원하는 Extended Advertising Data의 크기가 최대 255바이트까지 가능하다.

![Desktop View](/assets/images/data/blue1-2.png)

```c
//https://elixir.bootlin.com/linux/v4.19.136/source/include/net/bluetooth/hci_core.h#L205
struct hci_dev {
	
	...
	
	//https://elixir.bootlin.com/linux/v4.19.136/source/include/net/bluetooth/hci_core.h#L62
	struct discovery_state {
		...
		/* typedef u8 -> __u8 */ unsigned char      last_adv_data[31];           /* 0xab0  0x1f */
		...
	} discovery; /* 0xa68  0x88 */
	
	...
	
	//https://elixir.bootlin.com/linux/v4.19.136/source/drivers/gpu/drm/nouveau/include/nvif/list.h#L110
	struct list_head {
		struct list_head * next;                                                 /* 0xb18   0x8 */
		struct list_head * prev;                                                 /* 0xb20   0x8 */
	} mgmt_pending; /* 0xb18  0x10 */
	...
	/* size: 4264, cachelines: 67, members: 192 */
	/* sum members: 4216, holes: 17, sum holes: 48 */
	/* paddings: 10, sum paddings: 43 */
	/* forced alignments: 1 */
	/* last cacheline: 40 bytes */
} __attribute__((__aligned__(8)));
```
- **결국, 31바이트로는 255바이트를 저장할수 없기에 memory corrupton이 발생한다.**

### reference

[Linux: Heap-Based Buffer Overflow in HCI event packet parser (BleedingTooth)](https://github.com/google/security-research/security/advisories/GHSA-ccx2-w2r4-x649)<br>
[BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html#badvibes-heap-based-buffer-overflow-cve-2020-24490)<br>
[https://github.com/google/security-research/blob/master/pocs/linux/bleedingtooth/readme.md](https://github.com/google/security-research/blob/master/pocs/linux/bleedingtooth/readme.md)
<br>with Changhyun Lee