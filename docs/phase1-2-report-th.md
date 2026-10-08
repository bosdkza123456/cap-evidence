# Phase 1–2: Runtime และ Loss/Ambiguity Gate

## สถานะที่ตรวจได้จริง

Phase 1 **BLOCKED**: probe จริงยังได้ tracing=blocked, sandbox=blocked, compiler=available ไม่พบ Docker/Podman/QEMU ที่เรียกใช้งานได้ใน workspace และไม่มี supported external host ที่เชื่อมไว้ จึงยังไม่มี genuine syscall trace หรือ live sandbox/timeout cleanup proof ไม่ bypass นโยบายเครื่อง

Phase 2 **implemented and tested on synthetic inputs; live validation pending**: เพิ่ม loss sidecar, conservative attribution sanitization, target ambiguity checks และ strict gate ก่อน consume run ไม่เปลี่ยน core/DEC/contract approval และไม่เข้า Phase 3–5

## TDD และการแก้บัค

เขียนเทสต์ก่อน implementation: พบ bridge เดิมยอม consume inspection run แม้ coverage ไม่ครบ; เทสต์ incomplete-no-ledger และ producer-complete-claim block ล้มเหลวก่อนแก้ เพิ่ม loss visibility และ identity tests ก่อนสร้าง collection() จากนั้นแก้จนผ่าน

ตอนนี้ incomplete/drop/parse-failure → collection_incomplete, unsupported/unknown operation/action → collection_ambiguous, relative/deleted path หรือ port 0 → target_identity_ambiguous เมื่อ producer อ้าง complete=true และไม่มีข้อผิดพลาดที่เห็นได้ ก็ยัง adapter_pending_spike เพราะไม่มี independent completeness/identity proof ไม่มี ledger writes ใน pipeline route นี้ Separate accept() ยังเป็น local inspection utility ไม่ใช่ authorization API

CLI ใช้ pipeline_status=BLOCK/exit 2 แยกจาก DENY ของ evaluator เพื่อไม่เปลี่ยน policy semantics Standalone preview ยังใช้ตรวจ candidates ได้ แต่ไม่สามารถ override guard

## Loss/target handling

loss-accounting.json มี raw lines, events, metadata/blank lines, parse failures, truncation/resumed markers, unsupported events, unattributed events และ known identity ambiguities จำนวน dropped ที่วัดไม่ได้เป็น null ไม่แต่ง 0 หรืออ้าง completeness Verified=false เสมอ Wire contract 0.1 ยังมี dropped=0 placeholder กับ complete=false; ไม่ใช่ attestation และไม่มีการยกระดับ schema/approval

Unattributed events คงอยู่ใน payload เป็น unsupported และ original trace คง bytes เดิมก่อน hash ไม่ map เป็น package action Relative paths, deleted FD paths, zero ports และ invalid IP ไม่ถูกตีความเป็น authoritative identity IPv6 spelling กับ port คงเดิม Path/symlink/interpreter และ loss ของ tracer ที่ตรวจไม่พบยังเป็น known limitations; guard บล็อกทั้งหมดอยู่แล้ว

## ผลทดสอบ

Python 27 tests ผ่าน รวม real Go preview process บน synthetic payload (ผลใหม่ต้อง BLOCK และไม่สร้าง ledger), loss counters, invalid IP/IPv6/port, unknown actions, replay utility, invalid times, injected output failure และ mocked cleanup Go pass events/skip และ vet/race/fuzz อยู่ใน test-summary.json C workload syntax ผ่าน ไม่ได้ execute External CI/live runtime ยังไม่ได้รัน

## งานที่ต้องทำต่อ

ต้องมี Linux host ที่รองรับและได้รับอนุญาตให้ใช้ จึงจะพิสูจน์ live collection/attribution/cleanup ได้ Target completeness/provenance/mapping ยังไม่อนุมัติ ไม่มี CAP Evidence authorization หรือ production authentication ในรอบนี้ การพัฒนาต่อไม่ถือเป็น owner approval รายงานเก่าเป็นประวัติ; รายงานนี้และ test-summary เป็นสถานะปัจจุบัน
