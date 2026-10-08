# รายงาน collector / orchestration PoC และสถานะระบบ

## สถานะปัจจุบัน

Foundation/evaluator/strict parser, conflict aggregation, raw-event preview และ regression tests ทำแล้ว แต่เส้นทางใช้งานจริง artifact → sandbox collector → protected binding → CAP Evidence → authorization ยังไม่เสร็จ จึงยังใช้เป็นระบบอนุญาต package จริงไม่ได้ ไม่มีฐานที่เหมาะสมสำหรับเปอร์เซ็นต์รวมทั้งระบบ

## สิ่งที่ทำในรอบนี้

เพิ่ม `experiments/linux-collector/` แยกจาก core: runtime preflight, controlled C workload, parser ของ syscall trace ที่แยกผล/ทิศทาง, hash ของ workload bytes/source/trace/payload, run IDs และ timestamps, timeout/process-group cleanup, resource limits และ fixed-code error output ไม่มี arbitrary package runner

เพิ่ม local acceptance API ตรวจ payload/run/artifact/analyzer binding, freshness, event timestamps และ replay ผ่าน SQLite transaction การทดสอบใช้ ledger ใน private temp directory API นี้ยังไม่ถูกต่อกับ collector/Go preview เป็น live end-to-end และไม่ใช่ remote authentication หรือ signed attestation

## Runtime blocker ที่ตรวจจริง

เครื่องมี strace/bwrap/cc แต่ ptrace ถูกปฏิเสธ และ bwrap สร้าง NETLINK_ROUTE/network namespace ไม่ได้ ผล probe จริงอยู่ใน `experiments/linux-collector/testdata/runtime-probe.json` คำสั่ง collect คืน `runtime_prerequisite_blocked` exit 2 โดยไม่รัน workload ไม่ทำ unsandboxed fallback จึงไม่มี genuine syscall fixture ในรอบนี้ ข้อจำกัดนี้เป็นข้อจำกัด runtime ไม่ใช่คำขออนุมัติ spec

## ตรวจบัค

พบ record-limit bypass เมื่อ trace line malformed: branch ที่ append แล้ว continue ข้ามการเช็กจำนวน แก้โดยตรวจ limit ก่อนประมวลผลแต่ละ line มีเทสต์ input 1025 malformed lines ยืนยันว่าถูกบล็อก ตรวจ failed syscall, connect/bind, port, content read/write, unsupported/escaped/truncated events, EINPROGRESS, input encoding/bytes/records, binding tamper, freshness/future timestamps, event นอก run, replay และ blocked runtime ไม่มี raw input/secret ใน error

Python unit tests 9 ผ่าน; C workload ผ่าน `-Wall -Wextra -Werror -fsyntax-only` แต่ไม่ได้รัน workload Go regression tests/race/vet ผ่านตาม `test-summary.json` เทสต์ parser ของ collector ใช้ synthetic traces เท่านั้น ไม่อ้างว่าเป็นหลักฐานจากการรันจริง การทดสอบ fuzz ของ Go preview เป็นผลรอบก่อน ส่วน randomized collector smoke รอบนี้ระบุแยกไว้ใน summary ไม่ใช่ coverage-guided fuzz

## ความพร้อมด้าน error และความลื่นไหล

มี preflight ให้รู้ blocker ก่อนเริ่ม run, error เป็น reason code, limits, timeout, input validation และ replay failure paths แต่ยังไม่มีการทดสอบ UX กับผู้ใช้จริงหรือ live success path จึงยังรับรองว่าทำงานลื่นไหลทั้งระบบไม่ได้ Trace เก็บแบบ private แต่ไม่ใช่ arbitrary-secret redaction engine และ sandbox ที่ mount host แบบ read-only ยังมองเห็นข้อมูล host จึงไม่รองรับ hostile workloads

## สิ่งสำคัญที่ยังขาด

1. Runtime ที่รองรับ ptrace/namespaces และ live end-to-end test ของ collector/orchestrator/preview
2. Collector completeness/process attribution และ coverage attestation; รอบนี้ complete=false เสมอ
3. Owner approval ของ proposed semantics, capability mapping และ DEC ที่เปิดอยู่
4. Protected orchestration, authentication/replay policy ระดับ production, artifact/archive-byte verification และ secure retention
5. Candidate → CAP Evidence integration และการพิสูจน์ gating authorization บนข้อมูลจริง
6. External CI/release readiness และ UX; SDK/plugins/indexer เป็นงานขยายภายหลัง

Evaluator, DEC register, OpenSSF summary adapter, raw preview, CI/module/LICENSE/vendor ไม่เปลี่ยน ตรวจด้วย scope hash audit และ manifest มีรายงาน `collector-scope-audit.json` ไม่มี binary อยู่ในแพ็กเกจ
