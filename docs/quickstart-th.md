# เริ่มใช้งาน CAP-Evidence ฉบับแก้ไข

สถานะ: Semantic Design Baseline — Pre-Spike Validation
Semantic state: foundation-0.2

แพ็กเกจนี้มีซอร์สและ vendor ไม่มี binary ที่สร้างไว้ล่วงหน้า

1. ติดตั้ง Go 1.26.8 ตาม `.go-version`
2. แตก ZIP แล้วเปิด terminal ในโฟลเดอร์ `capevidence`
3. รัน `go test -mod=vendor ./...` และ `go vet -mod=vendor ./...` โดยไม่ต้องดาวน์โหลด dependency เพิ่ม

## Windows PowerShell

```powershell
$env:CGO_ENABLED = "0"
go build -trimpath -o bin/capevidence.exe ./cmd/capevidence
.\bin\capevidence.exe policy check --evidence spec/v0.1/examples/evidence.json --policy spec/v0.1/examples/policy.yaml --registry spec/v0.1/examples/registry.json --artifact spec/v0.1/examples/artifact.txt --evaluation-time 2026-10-08T10:00:00Z
```

## Linux

```bash
CGO_ENABLED=0 go build -trimpath -o bin/capevidence ./cmd/capevidence
./bin/capevidence policy check --evidence spec/v0.1/examples/evidence.json --policy spec/v0.1/examples/policy.yaml --registry spec/v0.1/examples/registry.json --artifact spec/v0.1/examples/artifact.txt --evaluation-time 2026-10-08T10:00:00Z
```

ตัวอย่างต้องให้ `review` และ exit code 1 เพราะ CLI รับหลักฐานเป็น unverified แม้ ALLOW rule จะ match ส่วน audit/inform ให้ exit 0 เมื่อประเมินสำเร็จเท่านั้น และไม่ใช้เป็น authorization gate

เวลาที่ระบุเป็น input สำหรับการประเมินซ้ำ ไม่มีการใช้เวลาระบบโดยอัตโนมัติ และ failure ไม่ใช่ DENY

ฉบับนี้แก้ bundle ผสม UNKNOWN, การคง DENY และลงทะเบียนการเทียบ IPv4-mapped สำหรับ DENY/REVIEW แล้ว แต่ OpenSSF, canonical hashing และ semantics ที่ยังเปิดอยู่ยังไม่พร้อม production ดู `docs/security-fix-report.md` และ `docs/public-release-checklist.md`
