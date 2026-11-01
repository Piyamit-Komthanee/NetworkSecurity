# คู่มือการรัน Demo (CODAX)

เอกสารนี้อธิบาย **ขั้นตอนการรัน demo ของโปรเจกต์** ว่าต้องพิมพ์คำสั่งอะไร และจะเห็นผลอะไร
คำสั่งทั้งหมดพิมพ์ใน terminal โดยเริ่มจากโฟลเดอร์โปรเจกต์: `cd /home/vboxuser/codax-project`
คำสั่งที่ขึ้นต้นด้วย `sudo` จะถามรหัสผ่านของเครื่อง

> ต้องติดตั้งเครื่องมือและ build ให้เรียบร้อยก่อน (ดู `README.md` และ `REQUIREMENTS.md`)

---

## 0. เตรียมก่อนรัน

```bash
cd /home/vboxuser/codax-project

# (1) เปิด container ทั้ง 3 ตัว
cd testbed && sudo docker compose up -d --build ; cd ..

# (2) เช็กว่าขึ้นครบ 3 ตัว (codax_redos / codax_inloop / codax_baseline = Up)
sudo docker ps

# (3) เช็กว่า tracer ถูก build ไว้แล้ว (มีไฟล์ bin/codax_tracer)
ls -l bin/codax_tracer
```

---

## 1. ลำดับการรัน demo

### ขั้น A — ตรวจสอบ logic ด้วยข้อมูลจำลอง (ไม่ต้องใช้ root)
```bash
python3 analysis/analyze.py --selftest
```
**ผลที่เห็น:** บรรทัดท้าย `attack 2002: CODA latency=5000ms  CODAX latency=1001ms` และ
`OK: CODAX catches the persistent attack far earlier than CODA.` — ยืนยันว่า CODAX จับ attack ที่
ค้างได้เร็วกว่า CODA

### ขั้น B — eBPF จับเหตุการณ์จริง (ยิง request ให้อัตโนมัติ)
```bash
sudo bash scripts/smoke.sh
```
**ผลที่เห็น:** (1) ตาราง container→cgroup ID (2) tracer เริ่มทำงาน (3) ยิง request ตัวอย่าง 4 แบบ
(4) เหตุการณ์ที่จับได้ เป็น JSON บรรทัดละเหตุการณ์ สังเกตค่า `elapsed_ns`:
- `/safe` ของ baseline → หลักล้าน (ไม่กี่ ms) = request ปกติ
- `redos n=22` → หลักพันล้าน (~1 วินาที) = attack ช้ากว่าปกติมาก

### ขั้น B2 — eBPF ดูสดต่อเนื่องแบบ wireshark (ยิงเอง)
เปิด **2 terminal**

terminal 1 (จอเฝ้า — เปิดทิ้งไว้ จนกด Ctrl-C):
```bash
sudo bash scripts/watch.sh
```
terminal 2 (ยิงเอง):
```bash
curl -s '192.168.56.102:8003/safe'              # ปกติ
curl -s '192.168.56.102:8001/vulnerable?n=22'   # โจมตี ReDoS
```
**ผลที่เห็น:** event JSON เด้งขึ้นที่ terminal 1 ทุกครั้งที่ยิง — `elapsed_ns` ของ `/safe` หลักล้าน (ms),
ของ `n=22` หลักพันล้าน (~1 วินาที)

### ขั้น C — รัน pipeline เต็ม 1 รอบ
```bash
sudo bash scripts/run-experiment.sh
```
**ผลที่เห็น:** PHASE 0–3 ไล่ไปจนออกตาราง `detection scores` และ `detection latency` ของรอบนั้น
(CODA พลาด persistent attack = FN / CODAX จับครบ)

### ขั้น D — ดูผลสรุป 10 trials (ตัวเลขหลักของรายงาน, ไม่ต้องใช้ root)
```bash
python3 analysis/analyze.py --trials data/trials -k 4 --tau-min-ms 5
```
**ผลที่เห็น:** ตาราง ADR/FPR/TPR ของ CODA vs CODAX + latency improvement + ค่า p
(TPR ของ CODAX = 1.0, CODA ≈ 0.62; CODAX ตรวจจับเร็วกว่า ~2.2 วินาที)

---

## 2. สรุปคำสั่ง

| ทำอะไร | คำสั่ง | ต้อง root? | เวลา |
|---|---|---|---|
| ตรวจ logic (ข้อมูลจำลอง) | `python3 analysis/analyze.py --selftest` | ไม่ | ทันที |
| eBPF จับเหตุการณ์ (ยิงให้เอง) | `sudo bash scripts/smoke.sh` | ใช่ | ~20s |
| eBPF ดูสดต่อเนื่อง | `sudo bash scripts/watch.sh` | ใช่ | จนกด Ctrl-C |
| pipeline เต็ม 1 รอบ | `sudo bash scripts/run-experiment.sh` | ใช่ | ~1–2 นาที |
| รัน 10 trials (เก็บสถิติ) | `sudo bash scripts/run-trials.sh` | ใช่ | ~7–8 นาที |
| ดูผลสรุป 10 trials ที่เก็บไว้ | `python3 analysis/analyze.py --trials data/trials -k 4 --tau-min-ms 5` | ไม่ | ทันที |
| เปิด container | `cd testbed && sudo docker compose up -d --build ; cd ..` | ใช่ | ~10s |
| ดูสถานะ container | `sudo docker ps` | ใช่ | ทันที |

> **1 รอบ vs 10 trials:** `run-experiment.sh` = ทำครบวงจร 1 รอบ (~1–2 นาที) ส่วน `run-trials.sh`
> = ทำซ้ำ 10 รอบแล้วเฉลี่ย + ทดสอบสถิติ (~7–8 นาที) หมายเหตุ: `run-trials.sh` จะลบ `data/trials`
> เก่าทิ้งแล้วเก็บชุดใหม่ ถ้าอยากดูผลเดิมใช้คำสั่ง "ดูผลสรุป 10 trials ที่เก็บไว้"

> **watch.sh:** ต้องเปิด 2 terminal (จอเฝ้า + ยิงเอง) และอย่ารันพร้อม `run-experiment.sh`
> เพราะ run-experiment จะรีสตาร์ท container ทำให้ cgroup id เปลี่ยน

---

## 3. แก้ปัญหาที่พบบ่อย

- **`sudo docker ps` ไม่เห็น container ครบ 3:** รัน `cd testbed && sudo docker compose up -d ; cd ..` ใหม่ แล้วรอ ~5 วิ
- **smoke.sh / run-experiment.sh แจ้ง "no containers":** container ยังไม่ขึ้น ทำข้อบน
- **`inloop` ค้าง / ยิงแล้วไม่ตอบ:** `sudo docker restart codax_inloop` (run-experiment.sh รีสตาร์ทให้เองใน PHASE 0)
- **ผล TP/FP เป็น 0 หมด:** ยิงผิด IP — ต้องยิงไป IP จริงของเครื่อง ไม่ใช่ 127.0.0.1 (ดู README หัวข้อขั้น 4)
- **tracer แจ้ง attach ไม่ได้:** ต้องรันด้วย `sudo` และเคอร์เนลต้อง ≥ 6.10
