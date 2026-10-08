# รายงาน OpenSSF Package Analysis spike

รอบนี้ทำครบการตรวจ 8 ประเด็น โดยไม่เปิดใช้งาน adapter และไม่เปลี่ยน evaluator หรือสถานะ DEC ใด ผลสรุปคือข้อมูล summary ที่ตรวจยังไม่พอสำหรับ authorization; adapter ยังคง fail-closed ไม่มี CAP evidence ถูกสร้างจากข้อมูลที่ semantics ยังไม่ชัดเจน

## หลักฐานและวิธีตรวจ

ตรวจ source ของ repository ทางการที่ commit `c5c45008da694036d701ba76fe9567fc8a5b9675` และเก็บ source ที่ใช้อ้างอิงพร้อม LICENSE ใน `adapters/ossf-package-analysis/testdata/spike/upstream-source/` ดึง JSON จริงสองชุดจากลิงก์ใน upstream case studies: discordcmd 0.0.2 และ colorsss 0.0.2 เก็บ bytes เดิมพร้อม URL, SHA-256 และเวลารับข้อมูลใน `testdata/spike/provenance.json`

ไม่ได้ดาวน์โหลดหรือรัน package ที่เป็นอันตราย ไม่รันคำสั่งใน JSON และไม่ได้รัน analyzer ต้นทาง การตรวจเป็น source review และ fixture boundary tests ไม่ใช่ end-to-end live analysis ตัวอย่างย้อนหลังไม่ยืนยันว่าสร้างด้วย commit ที่ตรวจ Hash เป็นหลักฐานของ bytes ที่รับมา ไม่ใช่ลายเซ็นผู้เผยแพร่

## Mapping matrix

| ประเด็น | สิ่งที่ยืนยันจาก source / fixture | สิ่งที่ยังแปลงไม่ได้และข้อเสนอ |
|---|---|---|
| SPIKE-NET-001 | Socket มี Address, Port, Hostnames; parser รวม bind และ connect ในชุดเดียว | ไม่ทราบทิศทางหรือ syscall success; ห้ามแปลงเป็น network.outbound PRESENT อัตโนมัติ ต้อง raw events ที่แยก connect, result และ DNS provenance; ห้ามทิ้ง port |
| SPIKE-PATH-001 | Files มี Path และ Read/Write/Delete; parser ใช้ lexical join และนับ stat เป็น read | ไม่ทราบ contents access หรือ success; มี relative/pseudo paths และลำดับถูกยุบ ต้องกำหนด target semantics ก่อนแปลง |
| SPIKE-CMD-001 | Commands เก็บ argv และ environment | ไม่ยืนยัน executable identity หรือ execution success; ห้ามถือ argv เป็น command สำเร็จ และต้องระวังข้อมูลลับใน environment |
| SPIKE-ACTION-001 | Status เป็นผลระดับ phase; parser ไม่เก็บ syscall return code ใน summary และ upstream test มี failed open ที่นับ read | completed ไม่ยืนยัน action success; ต้องมี per-event result ห้ามแต่ง success |
| SPIKE-RUN-001 | Package key กับ CreatedTimestamp; phase install/import/execute อยู่ใน source ปัจจุบัน; fixtures มี install/import | timestamp ไม่ใช่ authenticated unique run ID; ห้ามรวมคนละ run จากชื่อ package ต้อง evaluator-owned run binding |
| SPIKE-COVERAGE-001 | discordcmd ทั้งสอง phase completed; colorsss install completed แต่ import error_analysis; ไม่พบ Coverage ในสอง fixtures | completed และรายการว่างไม่ยืนยัน completeness; worker อาจหยุดเมื่อ phase ล้มเหลว ห้ามสร้าง NOT_OBSERVED/ABSENT จากการไม่พบรายการ |
| SPIKE-ARTIFACT-001 | dynamic summary มี package key; internal static result มี archive SHA256; result store ตั้งชื่อ archive ด้วย hash | dynamic summary ที่ตรวจไม่มี binding ของ archive digest; hash ของ JSON ไม่ใช่ package digest ต้องผูก archive bytes/run/analysis ด้วย protected context; ไม่ดาวน์โหลด archive ในรอบนี้ |
| SPIKE-UNKNOWN-001 | strace parse failures บางชนิดถูก log แล้ว continue; unmatched/unsupported calls อาจไม่สร้าง record | summary ย้อนคืน event ที่ตกหล่นไม่ได้; adapter ต้อง reject ทั้ง input จนมี completeness contract หรือส่ง UNKNOWN ที่มี provenance; ห้ามอ้างว่าการปิด adapter ตรวจพบทุก event ที่ upstream ทิ้งไป |

แหล่งหลัก: `pkg/api/analysisrun/result.go`, `phase.go`, `internal/strace/strace.go` และ tests, `internal/analysis/status.go`, `internal/dynamicanalysis/analysis.go`, `internal/worker/rundynamic.go`, `internal/resultstore/resultstore.go`, `internal/staticanalysis/result.go`, `docs/data_schema.md` ทั้งหมดอยู่ใน snapshot ที่ hash ตรวจได้ มีความต่างระหว่าง docs เก่าที่ระบุ execute ยังไม่พร้อมกับ source ปัจจุบัน จึงไม่ใช้ docs เพียงอย่างเดียวกำหนด schema

## การตรวจบัคและ regression

เพิ่ม `spike_test.go`: ตรวจ hash ของ source/fixtures 14 ไฟล์, ตรวจ input ไม่ถูกแก้, ผลลัพธ์จริงทั้ง bundle และแยกแต่ละ phase ต้องถูกบล็อก, unknown event/phase, empty completed, failed phase, malformed JSON และ input เกิน limit ต้องไม่สร้าง evidence กรณีดัดแปลงเป็น synthetic boundary probes ระบุไว้ในเทสต์ ไม่อ้างว่าเป็นผลจาก upstream จริง

พบข้อจำกัดจาก upstream ข้างต้น แต่ไม่พบ regression ใน CAP-Evidence จากการเพิ่ม fixtures/tests รอบนี้ ไม่แก้ Parse: malformed หรือ unknown input ยังคืน adapter_pending_spike ไม่ใช่ parser validation ที่เสร็จแล้ว เทสต์นี้ยืนยัน fail-closed เท่านั้น ไม่ยืนยัน adapter สามารถแปลงข้อมูลได้

ผลรันล่าสุดและจำนวนเทสต์อยู่ใน `test-summary.json` การเปรียบเทียบ hash ก่อน/หลังอยู่ใน `openssf-spike-scope-audit.json` ยืนยัน evaluator, decision register, OpenSSF adapter implementation, CI, module, LICENSE และ vendor ไม่เปลี่ยน Manifest ตรวจความสมบูรณ์ของไฟล์ ไม่ใช่ trust anchor

## งานที่ยังค้างหลังจบ spike

1. เจ้าของพิจารณา mapping/semantics และรายการ DEC ที่ยัง PROPOSED/OPEN โดยรอบนี้ไม่เปลี่ยนสถานะหรืออ้างการอนุมัติ
2. ต้องได้ raw event contract ที่มีทิศทาง/result, run/artifact binding และ coverage/drop accounting ก่อนเขียน adapter ที่เปิดใช้งานได้
3. ยังไม่มี live analyzer end-to-end, signed artifact attestation หรือ external CI run; ยังไม่พร้อมประกาศ production compatibility
4. Core limitations เดิมยังอยู่ รวม exact-key conflict: host canonical แต่ scope/OS/target_scope ต่างกันยังไม่รวมเป็น conflict และ security equivalence ไม่ได้เปลี่ยน conflict identity
