# REQUIREMENTS — ต้องลงอะไรบ้าง

เอกสารนี้บอกว่าเครื่องต้องมีอะไรก่อนจะรันโปรเจกต์นี้ได้ ถ้าเพิ่งลง Ubuntu มาเปล่าๆ
**ลงทุกอย่างได้ด้วยคำสั่งเดียว** (ดูข้อ 2) ส่วนรายการเต็มอยู่ข้อ 3 เผื่ออยากรู้ว่ามีอะไรบ้าง

---

## 1. ระบบปฏิบัติการ / เคอร์เนล (ข้อบังคับ)

| ต้องมี | รายละเอียด | เช็กยังไง |
|---|---|---|
| **Linux + เคอร์เนลใหม่พอ** | ทดสอบบน Ubuntu 26.04 / kernel **7.0** — ต้องการ **≥ 6.10** (เพราะ eBPF probe ตัว accept ใช้ซิกเนเจอร์ `inet_csk_accept(sk, arg)` ของเคอร์เนลรุ่นนี้) | `uname -r` |
| **cgroup v2** | ใช้ระบุ container (ดูจาก `bpf_get_current_cgroup_id()`) | `stat -fc %T /sys/fs/cgroup` → ต้องได้ `cgroup2fs` |
| **BTF เปิดอยู่** | จำเป็นสำหรับ eBPF CO-RE | `ls /sys/kernel/btf/vmlinux` → ต้องมีไฟล์ |
| **สิทธิ์ root** | โหลด eBPF ต้องใช้ root (`sudo`) | — |

> โปรเจกต์นี้ออกแบบมาให้รันใน **VirtualBox VM Ubuntu** ถ้ารันบนเครื่องจริง/คลาวด์ที่เคอร์เนลเก่ากว่า 6.10 probe ตัว accept อาจ attach ไม่ได้

---

## 2. ลงทุกอย่างด้วยคำสั่งเดียว (แนะนำ)

```bash
sudo bash scripts/install-toolchain.sh
```

เสร็จแล้ว **ออกจากระบบแล้วล็อกอินใหม่** (หรือพิมพ์ `newgrp docker`) เพื่อให้ใช้ docker ได้โดยไม่ต้อง sudo

สคริปต์นี้ลง 4 กลุ่มให้ครบ (ดูข้อ 3) พร้อมเปิดบริการ docker ให้อัตโนมัติ

---

## 3. รายการเต็ม (สคริปต์ข้อ 2 ลงให้ทั้งหมดนี้)

### 3.1 ชุดเครื่องมือ build eBPF
`clang` `llvm` `libbpf-dev` `libelf-dev` `zlib1g-dev` `build-essential` `pkg-config` `make` `git`
- `clang` คอมไพล์ `*.bpf.c` → eBPF bytecode
- `libbpf-dev` = ไลบรารีโหลด eBPF + header `bpf_helpers.h`
- `libelf` / `zlib` = dependency ของ libbpf

### 3.2 เครื่องมือเคอร์เนล / BPF
`bpftool` `bpftrace` `linux-tools-common` `linux-tools-$(uname -r)` `linux-headers-$(uname -r)`
- `bpftool` สร้าง `vmlinux.h` + skeleton header และดู program/map ที่โหลดอยู่

### 3.3 Container
`docker.io` `docker-compose-v2`
- รัน testbed 3 container (redos / inloop / baseline)
- **ของข้างใน container (Flask, gunicorn, Node.js) ไม่ต้องลงเอง** — Docker build ให้จาก Dockerfile อัตโนมัติ

### 3.4 วิเคราะห์ผล (Python)
`python3` `python3-scipy` `python3-numpy` `python3-pandas` `python3-matplotlib` `curl` `jq` `sysstat`
- `scipy` = ทำ paired t-test + Wilcoxon (ถ้าไม่มี โปรแกรมยังรันได้ แต่ข้ามสถิติส่วนนี้)
- `gen.py` ใช้แค่ Python standard library (ไม่ต้องลงเพิ่ม)

---

## 4. แยก "แค่รัน" กับ "build เอง"

| อยากทำ | ต้องมีอย่างน้อย |
|---|---|
| **แค่ดูผลที่เก็บไว้** (`analyze.py --trials`) | `python3` (+ `python3-scipy` ถ้าอยากได้ค่าสถิติ) |
| **build tracer เอง** (`make`) | ชุด 3.1 + 3.2 |
| **รันการทดลองสด** (smoke/experiment/trials) | ครบทั้ง 4 กลุ่ม |

---

## 5. ตรวจว่าพร้อมหรือยัง

```bash
uname -r                                   # เคอร์เนล >= 6.10
stat -fc %T /sys/fs/cgroup                 # cgroup2fs
ls /sys/kernel/btf/vmlinux                 # มีไฟล์
clang --version && bpftool version         # build chain พร้อม
docker --version && docker compose version # docker พร้อม
python3 -c 'import scipy; print("scipy ok")'
```
ถ้าผ่านหมด = พร้อมทำตาม `README.md` ได้เลย
