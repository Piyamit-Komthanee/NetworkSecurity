# CODAX reproduction — คู่มือตั้งแต่ต้น (README)

โปรเจกต์นี้ทำซ้ำ (reproduce) แก่นของงานวิจัย **"eBPF-Based Runtime Detection of Semantic DDoS
Attacks in Linux Containers"** (Remya et al., IEEE Access 2025) — ไฟล์ `CODAX.pdf` ในโฟลเดอร์นี้

สรุปสั้นๆ: ใช้ **eBPF** ดักดูที่เคอร์เนลว่าแต่ละ connection ของ container เปิดอยู่นานผิดปกติไหม เพื่อ
ตรวจจับการโจมตีแบบ **Semantic DoS** (ยิง request น้อยแต่ทำให้ server ทำงานหนักจนค้าง) แล้วเทียบ 2 วิธี:
**CODA** (วิธีเดิม ตัดสินตอน connection ปิด) กับ **CODAX** (วิธีใหม่ ตรวจก่อนปิด จับ attack ที่ไม่ยอมปิดได้)

> อยากเข้าใจเนื้อหาเชิงลึก → อ่าน `REPORT.md` · อยากรู้ว่าตอน demo พิมพ์อะไร → อ่าน `DEMO.md`

---

## ภาพรวม 5 ขั้น

```
0) เช็กเครื่อง  →  1) ลง toolchain  →  2) build tracer  →  3) เปิด container  →  4) รันการทดลอง + ดูผล
```
คำสั่งทั้งหมดเริ่มจากโฟลเดอร์โปรเจกต์นี้ (เช่น `cd ~/codax-project`)

---

## ขั้น 0 — เช็กว่าเครื่องรองรับ

```bash
uname -r                        # เคอร์เนล ควร >= 6.10 (ทดสอบบน 7.0)
stat -fc %T /sys/fs/cgroup      # ต้องได้ cgroup2fs
ls /sys/kernel/btf/vmlinux      # ต้องมีไฟล์ (BTF เปิดอยู่)
```
รายละเอียดข้อกำหนดทั้งหมดอยู่ใน **`REQUIREMENTS.md`**

---

## ขั้น 1 — ลงเครื่องมือทั้งหมด (ครั้งเดียว)

```bash
sudo bash scripts/install-toolchain.sh
```
ลง clang/libbpf/bpftool (สำหรับ eBPF) + docker (สำหรับ container) + python3-scipy (สำหรับสถิติ) ให้ครบ

**เสร็จแล้วออกจากระบบแล้วล็อกอินใหม่** (หรือ `newgrp docker`) เพื่อให้ใช้ docker ได้ — หรือจะใช้ `sudo docker`
ไปก่อนก็ได้ (คู่มือนี้ใช้ `sudo docker` เพื่อความชัวร์)

---

## ขั้น 2 — Build ตัว tracer (eBPF)

```bash
make
```
จะได้โปรแกรม **`bin/codax_tracer`** (ขั้นตอนข้างใน: clang คอมไพล์ `bpf/codax.bpf.c` เป็น eBPF bytecode →
bpftool สร้าง skeleton → คอมไพล์ตัวโหลด `user/codax_tracer.c`) — ดูหัวข้อ "Makefile คืออะไร" ด้านล่าง

> `make` ไม่ต้องใช้ root แต่ตอน **รัน** tracer ต้องใช้ root เสมอ (eBPF ต้องการสิทธิ์เคอร์เนล)

---

## ขั้น 3 — เปิด container ทดสอบ 3 ตัว

```bash
cd testbed && sudo docker compose up -d --build ; cd ..
sudo docker ps                 # ต้องเห็น codax_redos / codax_inloop / codax_baseline = Up ครบ 3
```
ครั้งแรกจะช้าหน่อย (ต้อง build image) ครั้งต่อไปเร็ว

---

## ขั้น 4 — รันการทดลอง + ดูผล

### 4.1 เช็ก logic เร็วๆ (ไม่ต้อง root ไม่ต้อง container)
```bash
python3 analysis/analyze.py --selftest
```
พิสูจน์ด้วยข้อมูลจำลองว่า CODAX จับ attack ที่ไม่ปิดได้เร็วกว่า CODA

### 4.2 ดู eBPF จับเหตุการณ์จริง
```bash
sudo bash scripts/smoke.sh
```
เปิด tracer → ยิง request ตัวอย่าง → โชว์ event (JSON) ที่จับได้ ดูเลข `elapsed_ns`:
ปกติหลักล้าน (ms), โจมตีหลักพันล้าน (วินาที)

### 4.3 รัน pipeline เต็ม 1 รอบ
```bash
sudo bash scripts/run-experiment.sh
```

### 4.4 รัน 10 รอบ เก็บสถิติ (ตัวเลขหลักของรายงาน, ~7–8 นาที)
```bash
sudo bash scripts/run-trials.sh
```
พอจบจะพิมพ์สรุป ADR / FPR / TPR + latency + ค่า p ของทั้ง CODA และ CODAX

### 4.5 ดูผลที่เก็บไว้ซ้ำ (ไม่รันใหม่ ไม่ต้อง root)
```bash
python3 analysis/analyze.py --trials data/trials -k 4 --tau-min-ms 5
```

> ⚠️ **สำคัญ — เรื่อง IP ปลายทาง:** สคริปต์ตั้งค่า default ยิงไปที่ `192.168.56.102` (IP ของ VM เครื่องนี้)
> **อย่าใช้ `127.0.0.1`** เพราะ loopback วิ่งผ่าน docker-proxy ทำให้เลข port ไม่ตรงกัน join เฉลยไม่ได้
> ถ้ารันบนเครื่องที่ IP ต่างออกไป ให้หา IP ด้วย `hostname -I` แล้วสั่งแบบนี้:
> ```bash
> HOST=<ip-ของเครื่อง> sudo bash scripts/run-experiment.sh
> ```

---

## โครงสร้างโปรเจกต์

| ที่ | คืออะไร |
|---|---|
| `bpf/codax.bpf.c` | **โค้ด eBPF (รันในเคอร์เนล)** — ดัก accept/close ของ connection |
| `bpf/codax.h` | struct ข้อมูลที่ kernel ↔ userspace ใช้ร่วมกัน |
| `bpf/vmlinux.h` | type ของเคอร์เนล (สำหรับ CO-RE) — checked-in ไว้แล้ว |
| `user/codax_tracer.c` | ตัวโหลด eBPF เข้าเคอร์เนล + อ่าน event ออกมาเป็น JSON |
| `analysis/analyze.py` | คำนวณ threshold + ตัดสิน CODA/CODAX + คิด ADR/FPR/latency |
| `attacker/gen.py` | ตัวยิง traffic (benign + attack) พร้อมจดเฉลย |
| `testbed/` | container 3 ตัว: `redos` (ReDoS), `inloop` (busy loop), `baseline` (สะอาด) |
| `scripts/` | สคริปต์ช่วยรัน (ดูตารางด้านล่าง) |
| `Makefile` | สูตร build (ดูหัวข้อถัดไป) |
| `REPORT.md` / `DEMO.md` | เอกสารอธิบายเชิงลึก / คู่มือ demo |

### สคริปต์ใน `scripts/`
| ไฟล์ | ทำอะไร |
|---|---|
| `install-toolchain.sh` | ลงเครื่องมือทั้งหมด (ขั้น 1) |
| `cgids.sh` | หา cgroup id ของ 3 container ที่รันอยู่ |
| `smoke.sh` | ทดสอบเร็วๆ ว่า eBPF จับเหตุการณ์ได้ |
| `watch.sh` | เฝ้าดู eBPF สดต่อเนื่องแบบ wireshark (ยิง curl เองอีก terminal) |
| `run-experiment.sh` | รัน pipeline เต็ม 1 รอบ |
| `run-trials.sh` | รัน 10 รอบ + สรุปสถิติ |

---

## Makefile คือไฟล์เอาไว้ทำอะไร

`Makefile` คือ **"สูตร build อัตโนมัติ"** — บอกว่าจะสร้างโปรแกรมจาก source ต้องคอมไพล์ไฟล์ไหนด้วยคำสั่งอะไร
ตามลำดับไหน พอพิมพ์ `make` ครั้งเดียว มันทำให้ครบ (และ build ใหม่เฉพาะไฟล์ที่เปลี่ยน) จะได้ไม่ต้องจำ/พิมพ์
คำสั่ง clang ยาวๆ เองทุกครั้ง

ของโปรเจกต์นี้ `make` ทำ 3 ขั้น:
1. **clang** คอมไพล์ `bpf/codax.bpf.c` → `build/codax.bpf.o` (eBPF **bytecode**) ด้วย flag `-target bpf`
2. **bpftool gen skeleton** เอา bytecode ไปฝังใน `build/codax.skel.h` (โค้ด glue สำหรับ load/attach)
3. **clang/cc** คอมไพล์ `user/codax_tracer.c` (ที่ `#include` skeleton) ลิงก์ libbpf → ได้ `bin/codax_tracer`

คำสั่งที่เกี่ยวข้อง:
```bash
make            # build ทั้งหมด -> bin/codax_tracer
make clean      # ลบ build/ กับ bin/ (เริ่มใหม่สะอาดๆ)
```

---

## ถ้ามีปัญหา (troubleshooting)

| อาการ | แก้ |
|---|---|
| `make` error หา `bpf_helpers.h` ไม่เจอ | ยังไม่ได้ลง toolchain → รันขั้น 1 |
| `docker: permission denied` | ยังไม่ได้ re-login หลังลง docker → `newgrp docker` หรือใช้ `sudo docker` |
| `sudo docker ps` ไม่เห็น container ครบ 3 | รันขั้น 3 ใหม่ แล้วรอ ~5 วิ |
| `inloop` ค้าง/ยิงแล้วไม่ตอบ | `sudo docker restart codax_inloop` |
| ผลออกมา TP/FP เป็น 0 หมด | ยิงผิด IP → อย่าใช้ 127.0.0.1 ใช้ IP จริง (ดูหมายเหตุขั้น 4) |
| tracer บอก attach ไม่ได้ | เคอร์เนลเก่าเกิน (< 6.10) หรือไม่ได้รันด้วย sudo |

---

## อ่านต่อ
- **`REQUIREMENTS.md`** — รายการสิ่งที่ต้องลงแบบละเอียด
- **`REPORT.md`** — อธิบายส่วนประกอบ/เทคโนโลยี/ผล/ส่วนที่ต่างจาก paper (ภาษาไทย เข้าใจง่าย)
- **`DEMO.md`** — คู่มือตอนนำเสนอ (พิมพ์อะไร พูดอะไร)
