# ทดลอง CAP-Evidence ทีละขั้น

> **ALLOW ≠ SAFE** — ผล evaluator ไม่ใช่ใบรับรองความปลอดภัย และ harness PASS ไม่ใช่ authorization ALLOW

สถานะ Foundation: `foundation-0.2` ยังไม่ใช่ production-ready; Signing/CEL/Break Glass เป็นข้อเสนอ ยังไม่มีคำสั่งใช้งาน

## 1. เข้าโฟลเดอร์ให้ถูก

สำหรับ Codespaces ของ repository นี้:

```bash
cd /workspaces/cap-evidence
pwd
ls go.mod experiments/linux-collector/harness.py
```

ควรเห็นทั้งสองไฟล์ หากแตก ZIP ให้เข้าโฟลเดอร์ `capevidence` ที่มี `go.mod` แทน อย่าวาง `harness.py` ไว้ข้าง `go.mod`: ตำแหน่งจริงคือ `experiments/linux-collector/harness.py` หากไฟล์หาย ให้ตรวจ branch/แพ็กเกจที่ใช้อยู่ก่อน

## 2. ตรวจเครื่อง

ต้องมี Linux สำหรับ live harness; Windows/macOS ใช้ทดสอบ Core ได้ แต่ยังไม่ใช่ runtime ของ collector

```bash
go version
python3 --version
python3 experiments/linux-collector/collector.py probe
```

Go ที่โครงการระบุอยู่ใน `.go-version` (1.26.8) ส่วน compiler, strace และ bubblewrap ต้องติดตั้งโดยผู้ดูแล environment ด้วย

**ตัวอย่างผลลัพธ์ ไม่ใช่คำสั่ง:**

```json
{"runtime":{"tracing":"available","sandbox":"available","compiler":"available"},"authorization_ready":false}
```

ถ้ามี `blocked` หรือเครื่องมือไม่พร้อม อย่าข้าม sandbox ให้ใช้ Linux environment ที่ผู้ดูแลอนุญาต tracing/namespaces การเพิ่ม capability เพียงอย่างเดียวไม่รับประกันว่าจะผ่าน kernel policy ห้ามใช้ `--privileged` เป็นทางลัด

`cat experiments/linux-collector/testdata/runtime-probe.json` อ่านตัวอย่างเก่าเท่านั้น ไม่ได้ตรวจเครื่องของคุณ

## 3. Build แล้วรัน controlled live harness

```bash
go build -mod=vendor -trimpath -o /tmp/cap-rawpreview ./cmd/rawpreview
python3 experiments/linux-collector/harness.py --preview /tmp/cap-rawpreview
echo "exit_code=$?"
```

| Status | Exit | สิ่งที่ยืนยัน |
| --- | --- | --- |
| PASS | 0 | เก็บ trace จริงของ workload ควบคุม ตรวจ marker และ preview แล้ว pipeline ยังคง BLOCK; ledger ไม่ถูกเขียน |
| BLOCKED | 2 | prerequisite ไม่พร้อม ไม่อ้างว่าเก็บ trace สำเร็จ |
| FAIL | 1 | การเก็บหรือการตรวจสอบผิดพลาด อ่าน reason และ checks |

PASS ต้องมี `genuine_trace_collected=true`, `authorization_ready=false`, `pipeline_status=BLOCK` จำนวน event เปลี่ยนได้ ไม่ต้องตรงตัวอย่าง และ unsupported events ไม่ได้แปลว่า coverage ครบ

หากต้องการเก็บรายงานแบบไม่มี raw trace:

```bash
python3 experiments/linux-collector/harness.py --preview /tmp/cap-rawpreview --report /tmp/cap-live-report.json
```

## 4. ตรวจ Core และ integration tests

```bash
go test -mod=vendor ./...
go vet -mod=vendor ./...
go test -mod=vendor -race ./...
CAP_PREVIEW_TEST_BIN=/tmp/cap-rawpreview python3 -m unittest discover -s experiments/linux-collector -v
```

Race ต้องมี C compiler และ CGO ที่ใช้งานได้ หากล้มเหลวให้เก็บ error ไม่แทนด้วยการปิด race แล้วอ้างว่าผ่าน

ตัวอย่าง fuzz target ที่มีอยู่จริง:

```bash
go test -mod=vendor ./internal/evaluate -run '^$' -fuzz '^FuzzCanonicalConflictHost$' -fuzztime=30s -parallel=1
```

ต้องเห็นช่วง fuzz และจำนวน executions; คำว่า PASS อย่างเดียวไม่ยืนยันว่า fuzz target ถูกเรียก

## 5. ทดลอง CLI ของ Core แยกจาก harness

```bash
CGO_ENABLED=0 go build -mod=vendor -trimpath -o /tmp/capevidence ./cmd/capevidence
/tmp/capevidence policy check --evidence spec/v0.1/examples/evidence.json --policy spec/v0.1/examples/policy.yaml --registry spec/v0.1/examples/registry.json --artifact spec/v0.1/examples/artifact.txt --evaluation-time 2026-10-08T10:00:00Z
echo "exit_code=$?"
```

ควรได้ `review`, exit 1 เพราะ CLI ให้ trust เป็น unverified เวลานี้เป็น fixture input สำหรับทำซ้ำ ไม่ใช่เวลาสำหรับรับ run สด อย่าเปลี่ยนเป็นเวลาปัจจุบันแล้วคาดว่าจะได้ผลเหมือนเดิม

| Core CLI | Exit |
| --- | --- |
| enforce ALLOW | 0 |
| enforce REVIEW / DENY | 1 |
| Failure | 2 |

Audit/inform อาจ exit 0 เมื่อประเมินสำเร็จ จึงห้ามใช้ exit ของโหมดเหล่านั้นเป็น authorization gate ตารางนี้ต่างจาก harness

Windows PowerShell (Core เท่านั้น):

```powershell
$env:CGO_ENABLED = "0"
go build -mod=vendor -trimpath -o capevidence.exe ./cmd/capevidence
.\capevidence.exe policy check --evidence spec/v0.1/examples/evidence.json --policy spec/v0.1/examples/policy.yaml --registry spec/v0.1/examples/registry.json --artifact spec/v0.1/examples/artifact.txt --evaluation-time 2026-10-08T10:00:00Z
$LASTEXITCODE
```

## แก้ปัญหา

| อาการ | สิ่งที่ทำต่อ |
| --- | --- |
| `runtime_prerequisite_blocked` | รัน probe จริง ตรวจเครื่องมือและนโยบาย kernel กับผู้ดูแล; ไม่รัน unsandboxed |
| `controlled_events_missing` | เก็บ reason/checks ของ harness รอบที่ล้มเหลว; trace ของคนละรอบไม่พิสูจน์ว่ารอบนี้ผ่าน |
| `preview_unavailable` / หา binary ไม่พบ | build ใหม่ใน terminal เดียวกัน แล้วตรวจ `/tmp/cap-rawpreview` |
| PASS แต่ pipeline BLOCK | เป็นพฤติกรรมที่ตั้งใจไว้ Mapping ยังไม่เปิด |
| `command not found` จากชื่อ JSON field | field เป็นผลลัพธ์ ไม่ใช่คำสั่ง คัดลอกเฉพาะ code block ของคำสั่ง |
| Trace มี unsupported จำนวนมาก | coverage ยังไม่ครบ ห้ามแปลว่าไม่มีพฤติกรรมหรือปลอดภัย |

อย่าเผยแพร่ raw trace/environment/arguments เพราะอาจมีข้อมูลลับ ส่งเฉพาะรายงาน sanitized ไม่ลบ ledger เพื่อแก้ replay และไม่แก้ไฟล์ evidence หลัง hashing

## กรณีฉุกเฉิน

ขณะนี้ **ไม่มี Emergency Bypass ที่ implement แล้ว** อย่าปิด enforcement หรือแปลง BLOCK เป็น ALLOW อัตโนมัติ ให้เก็บ reason, version และ sanitized report เพื่อวินิจฉัย [Break Glass proposal](proposals/break-glass.md) เป็นเอกสารให้พิจารณา ไม่ใช่วิธีปลด sandbox

ดู [ข้อเสนอส่วนเสริม](proposals/README.md), [รายงาน implementation](implementation-report.md) และ [DEC เดิม](../spec/v0.1/decision-register.md)

### สถานะข้อเสนอและ ledger

`PROPOSED` เป็นสถานะของเอกสาร ไม่ใช่ evidence หรือคิวรออนุมัติใน replay ledger ไม่มี pending-evidence queue ในข้อเสนอนี้ การตรวจลายเซ็นก่อน consume run เป็นข้อกำหนดอนาคต ยังไม่ใช่ความสามารถของ inspection utility ปัจจุบัน

Break Glass ที่เสนอจะใช้ dedicated exception keys และ remote audit ที่ยืนยันบันทึกสำเร็จก่อนดำเนินการ แต่ยังไม่มี implementation เครื่องที่ถูกยึด root ไม่สามารถรับประกันว่าบันทึกครบหรือบังคับกฎได้ทุกกรณี ห้ามใช้ข้อเสนอนี้เป็นวิธีปิด sandbox
