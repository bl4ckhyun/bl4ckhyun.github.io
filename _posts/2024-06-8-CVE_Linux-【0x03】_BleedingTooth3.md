---
layout: post
title: "BleedingTooth_0x03 : CVE-2020-12351"
date: '2024-6-8 11:11:11 +0900'
description: 'CVE about BleedingTooth'
categories: [Vulnerability, Linux_Kernel]
tags: [CVE, Linux, Analysis, Bluetooth]
---

## **BadKarma: Heap-Based Type Confusion (CVE-2020-12351)**

>Author say : <br>
>I discovered the third vulnerability while attempting to trigger BadChoice and confirm its exploitability

![Desktop View](/assets/images/data/blue3.png)

* **BadKarma 취약점의 함수 호출 루틴**
    * **초기 패킷 수신**:
        * `hci_acldata_packet()`: ACL 데이터 패킷을 처리하는 시작점
        * `l2cap_recv_acldata()`: L2CAP 계층으로 데이터 전달
        * `l2cap_recv_frame()`: 프레임 처리 및 CID 확인
    * **채널 분기 처리**:
        * CID 값에 따라 두 가지 경로로 분기
        * `l2cap_sig_channel`: 시그널링 채널 처리
        * `l2cap_data_channel`: 데이터 채널 처리 (취약점 발생 지점)

```c
//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c?h=v4.9#n6907
static void l2cap_recv_frame(struct l2cap_conn *conn, struct sk_buff *skb)
{
	struct l2cap_hdr *lh = (void *) skb->data;
	struct hci_conn *hcon = conn->hcon;
	u16 cid, len;
	__le16 psm;

  ...

	switch (cid) {                         //cid에 따른 switch문
	case L2CAP_CID_SIGNALING:
		l2cap_sig_channel(conn, skb);
		break;

	case L2CAP_CID_CONN_LESS:
		psm = get_unaligned((__le16 *) skb->data);
		skb_pull(skb, L2CAP_PSMLEN_SIZE);
		l2cap_conless_channel(conn, psm, skb);
		break;

	case L2CAP_CID_LE_SIGNALING:
		l2cap_le_sig_channel(conn, skb);
		break;

	default:
		l2cap_data_channel(conn, cid, skb);
		break;
	}
}
```
* cid에 따른 switch문을 확인이 가능하다.
* 특별한 case가 아닐 경우 취약한 함수인 `l2cap_data_channel()` 들어간다.

```c
#https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c?h=v4.9#n6796
static void l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = l2cap_get_chan_by_scid(conn, cid);
	if (!chan) {
		if (cid == L2CAP_CID_A2MP) {
			chan = a2mp_channel_create(conn, skb); //a2mp_channel_create() call 
	 ...
	}
  ...
	switch (chan->mode) {
	...
	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		l2cap_data_rcv(chan, skb);  //l2cap_data_rcv() call
		goto done;
  ...
	}

drop:
	kfree_skb(skb);

done:
	l2cap_chan_unlock(chan);
}
```
* `l2cap_data_channel()`에 진입 후 `a2mp_channel_create()`를 호출한다.
    * `a2mp_channel_create()`해당 함수는 아래에서 설명할 예정.
* `chan->mode`의 값이이 ERTM 또는 Streaming 모드인지에 따라 `l2cap_data_rcv()`를 호출한다.

```c
//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c?h=v4.9#n6588
static int l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct l2cap_ctrl *control = &bt_cb(skb)->l2cap;
	u16 len;
	u8 event;

	__unpack_control(chan, skb);

	len = skb->len;

	/*
	 * We can just drop the corrupted I-frame here.
	 * Receiver will miss it and start proper recovery
	 * procedures and ask for retransmission.
	 */
	if (l2cap_check_fcs(chan, skb)) //checksum validation
		goto drop;

	if (!control->sframe && control->sar == L2CAP_SAR_START) //length check
		len -= L2CAP_SDULEN_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16) //length check
		len -= L2CAP_FCS_SIZE;

	if (len > chan->mps) {
		l2cap_send_disconn_req(chan, ECONNRESET);
		goto drop;
	}

	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb)) //sk_filter() call
		goto drop;

  ....
}

```
* 4개의 if 문을 통해 packet를 확인하고
* 마지막 if문에서 `sk_filter()`를 호출하는데, 인자로 `chan->data`를 사용한다.
    * `sk_filter()` 함수는 데이터 필터링을 위한 함수이며, 특정 조건에 따라 패킷을 드롭한다.

```c
//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h?h=v4.9#n552
static inline int sk_filter(struct sock *sk, struct sk_buff *skb) //=> Type confusion
{
	return sk_filter_trim_cap(sk, skb, 1);
}
```
* `sk_filter()`함수의 인자를 확인해보면 sock인걸 알 수 있다.
* 하지만 `chan->data`는 sock이 아니라 amp_mgr이다.
* 왜 sock이 아니라 amp_mgr 일까?

### Why is `chan->data` pointing to `amp_mgr` instead of `sock`?
```c
//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.h?h=v4.9#n27
struct amp_mgr {
	struct list_head	list;
	struct l2cap_conn	*l2cap_conn;
	struct l2cap_chan	*a2mp_chan;
	struct l2cap_chan	*bredr_chan;
	struct kref		kref;
	__u8			ident;
	__u8			handle;
	unsigned long		state;
	unsigned long		flags;

	struct list_head	amp_ctrls;
	struct mutex		amp_ctrls_lock;
};

//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c?h=v4.9#n841
struct l2cap_chan *a2mp_channel_create(struct l2cap_conn *conn,
				       struct sk_buff *skb)
{
	struct amp_mgr *mgr;  //struct amp_mgr

	if (conn->hcon->type != ACL_LINK)
		return NULL;

	mgr = amp_mgr_create(conn, false);
	if (!mgr) {
		BT_ERR("Could not create AMP manager");
		return NULL;
	}

	BT_DBG("mgr: %p chan %p", mgr, mgr->a2mp_chan);

	return mgr->a2mp_chan;
}

//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c?h=v4.9#n878
static struct amp_mgr *amp_mgr_create(struct l2cap_conn *conn, bool locked)
{
	struct amp_mgr *mgr;
	struct l2cap_chan *chan;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL); //kzalloc
	if (!mgr)
		return NULL;

	BT_DBG("conn %p mgr %p", conn, mgr);

	mgr->l2cap_conn = conn;

	chan = a2mp_chan_open(conn, locked);
	if (!chan) {
		kfree(mgr);
		return NULL;
	}

	mgr->a2mp_chan = chan;
	chan->data = mgr;                 //chan->data = mgr

	conn->hcon->amp_mgr = mgr;

	kref_init(&mgr->kref);

	/* Remote AMP ctrl list initialization */
	INIT_LIST_HEAD(&mgr->amp_ctrls);
	mutex_init(&mgr->amp_ctrls_lock);

	mutex_lock(&amp_mgr_list_lock);
	list_add(&mgr->list, &amp_mgr_list);
	mutex_unlock(&amp_mgr_list_lock);

	return mgr;
}
```
* `a2mp_channel_create()`는 `l2cap_data_channel()`에서 호출되는 서브루틴이다.
* 해당 함수에서 `chan->data = mgr` 을 해주는데 mgr은 GFP_KERNEL로 할당된 오브젝트이다.
* 그래서 `sk_filter()` 호출하기 전에 `chan->data = amp_mgr`이기 때문에 `sock`를 인자로 사용하는 `sk_filter()`에서 Type Confusion이 발생한다. 
    * 아래 그림을 통해 `amp_mgr` 구조체를 확인해보면 알겠지만, sock 구조체보다 확실히 크기가 작은게 확인이 된다.

![Desktop View](/assets/images/data/blue3-1.png)
- Again
	- 결과적으로, 함수에서는 `amp_mgr` 구조체를 벗어난 메모리 주소로 접근하게 된다.
		- 이는 kernel panic을 발생시키게 됩니다.
	- `amp_mgr+0x110`에 있는 주소값을 임의로 조작하여 임의의 메모리 쓰기나 읽기를 시도할 수 있지만 이는 커널 힙 영역이기 때문에 일반적으로는 유저가 직접 조작할 수 없는 영역이다.
		- 이때 heap spray라는 기법을 통해 공격자가 원하는 값을 주입하게 됩니다.

### reference
[https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq](https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq)<br>
[BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html#badvibes-heap-based-buffer-overflow-cve-2020-24490)<br>
with Changhyun Lee