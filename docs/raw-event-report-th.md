# รายงาน raw-event contract และ adapter ต้นแบบ

ทำครบสโคปรอบนี้: contract ที่แยกทิศทาง/action result, binding ของ bytes/run/artifact/analyzer, coverage/drop accounting, unknown-event diagnostics และการป้องกันข้อมูลลับใน error พร้อมต้นแบบแยกและ regression tests รายละเอียดข้อเสนอทั้งหมดอยู่ใน `raw-event-contract.md` สถานะ PROPOSED — pending owner approval ช่อง approver ว่าง ไม่เปลี่ยน DEC เดิม

ต้นแบบสร้างเพียง Candidate สำหรับตรวจสอบ ไม่มี CAP Evidence และไม่มี authorization แม้ producer อ้าง complete=true ยังไม่มีสิทธิ์อนุญาต package Summary adapter เดิมยังคืน adapter_pending_spike

ตรวจบัคแล้วแก้กรณี event อ้าง phase ที่ not_run: ต้อง reject ทั้ง input เพิ่ม regression test เฉพาะจุด ตรวจ duplicate ID, missing/invalid coverage, malformed/duplicate-key JSON, port เกินช่วง, mixed targets, unknown events, binding ไม่ตรง, failed/unknown action, record limit, order independence และ input ไม่ถูกแก้

ผล test/vet/race/fuzz และจำนวนล่าสุดอยู่ใน `test-summary.json` Hash เปรียบเทียบก่อน/หลังอยู่ใน `raw-event-scope-audit.json` ไม่มี evaluator, register, summary adapter, CI, module, LICENSE หรือ vendor เปลี่ยน สโคปรอบนี้ไม่เปลี่ยน known limitations เรื่อง exact-key conflict

งานที่ยังค้าง: อนุมัติ semantics และ capability mapping, raw collector จริง, protected orchestration/authentication/replay policy, artifact-byte verification, coverage attestation, timestamp freshness และ live end-to-end integration ข้อมูลทดสอบเป็น synthetic ไม่อ้างว่าเชื่อม OpenSSF สำเร็จหรือพร้อม production ระบบป้องกัน log ใช้ fixed codes และไม่รับ environment/argv แต่ไม่ใช่ตัวตรวจ secrets ใน arbitrary target strings
