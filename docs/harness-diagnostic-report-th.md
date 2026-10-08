# Diagnostic revision: controlled_events_missing

เพิ่ม fixed boolean diagnostics ใน checks ของ run ที่ล้มเหลว: raw/parsed/attributed markers สำหรับ exec/file/bind, bind_loopback_present, event_records, parse_failures และ unattributed_events ไม่พิมพ์ arguments, PID หรือ raw trace ไม่เปลี่ยน PASS criteria, core, DEC หรือ collector semantics

TDD: เขียน 4 tests ก่อน helper แล้วเห็น failure ก่อนแก้; Python รวม 39 tests ผ่าน ยืนยันว่ามี marker อย่างเดียวไม่ทำให้ PASS, non-loopback bind ไม่ผ่าน, unfinished/unattributed events ยังไม่ผ่าน และ secrets ใน argv ไม่เข้า diagnostic Go regression/race/vet ผลล่าสุดอยู่ใน test-summary.json

Codespaces ของผู้ใช้ผ่าน preflight; controlled collection ที่ผู้ใช้ส่งมามี exec/file/bind markers พร้อม workload attribution แต่ harness ในคนละ run ยัง FAIL ข้อมูลที่มีไม่พอยืนยัน root cause ของ run นั้น รุ่นนี้จึงเพิ่ม diagnostics ใน run ที่ FAIL โดยตรง ไม่อ้างว่าแก้ live FAIL แล้ว และไม่บังคับ PASS

ให้อัปเดต experiments/linux-collector/harness.py แล้วรัน harness อีกครั้ง ผล checks จะระบุเงื่อนไขที่ไม่ผ่าน โดยไม่ต้องแชร์ trace ทั้งไฟล์ Source payload bytes ไม่เปลี่ยน Authorization mapping ยังปิดไว้
