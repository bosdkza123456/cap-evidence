# Controlled Integration Harness & CI Alignment

## สิ่งที่ส่งมอบ

เพิ่ม Dockerfile, docker-compose.yml และ .dockerignore สำหรับทดสอบแบบไม่ privileged: cap_drop ALL และ cap_add SYS_PTRACE/NET_ADMIN, non-root, read-only filesystem, bounded tmpfs, network none, no-new-privileges ไม่มี host mounts/Docker socket และไม่ปิด seccomp/AppArmor ข้อจำกัด kernel ยังคงมีผล จึงไม่รับประกันว่า profile นี้จะรันได้ทุก host

เพิ่ม harness.py: PASS/BLOCKED/FAIL และ exit 0/2/1 ตามลำดับ PASS ต้องมี trace จาก controlled collector, hash trace/payload/source ตรง, พบ workload exec และ file/bind attempts ที่ระบุ แล้ว real Go preview ต้องเข้าสู่ pipeline BLOCK โดยไม่มี ledger ห้ามใช้แค่ unit-test success หรือ prerequisite ที่ผ่านเป็น PASS

controlled C workload เพิ่ม open(/restricted/forbidden.txt) และ loopback bind port 12345 ไม่มี package ภายนอกหรือ malicious package การตรวจผลเป็น pipeline BLOCK เพราะ mapping/coverage ยังปิด ไม่ใช่การอ้างว่า core ตัดสิน policy DENY หรือปลดล็อก ALLOW แล้ว

ปรับ CI เดิม: regression/vet, go test -v -race, parser/host/raw-preview/canonical-conflict fuzz, Python suite ที่ build Go preview จริง, C syntax check และ live harness job แยก BLOCKED exit 2 ทำให้ job ไม่ผ่านและบันทึกสถานะลง summary ไม่ใช้ continue-on-error หรือ || true Dedicated runner ใช้เฉพาะ trusted manual workflow_dispatch; PR ใช้ hosted runner

## ผลที่ตรวจจริง

- Python 35 tests ผ่าน รวม harness empty/no-trace, prerequisite, invalid hash, report write error และ collector tests
- Go 246 pass events, skip 4 เดิม; go vet และ go test -v -race ผ่าน; gofmt clean
- FuzzInspect 10 วินาทีที่กำหนด 113,664 executions ผ่าน
- C warnings-as-errors syntax check ผ่าน ไม่ได้ execute workload
- Harness จริงใน workspace: **BLOCKED**, runtime_prerequisite_blocked, genuine_trace_collected=false; หลักฐานอยู่ใน integration-harness-live-result.json
- Docker/Compose ไม่มี engine ที่เรียกใช้งานได้ จึงตรวจ configuration ด้วย Go/YAML regression tests แต่ยังไม่ได้ build/run image หรือเรียก docker compose config
- CI บน GitHub ยังไม่เคยรัน ไม่อ้างว่ามี supported-host PASS

## TDD / regression / ข้อจำกัด

เพิ่ม harness tests ก่อน implementation และยืนยันว่า failure เกิดจาก harness ที่ยังไม่มี ก่อนพัฒนาและทำให้ผ่าน เพิ่ม config assertions ป้องกัน privileged/unconfined/extra capabilities และ CI ที่ซ่อน BLOCKED เทสต์เพิ่มเติมป้องกัน trace ว่าง/hash ผิดไม่ให้เป็น PASS และ report เขียนไม่ได้ต้อง FAIL โดยไม่ overwrite

bridge tests ต้อง build /tmp/cap-rawpreview ใหม่หลัง temporary binary เดิมไม่อยู่ มิฉะนั้นได้ preview_unavailable; รันชุดสุดท้ายหลัง build แล้วผ่าน เทสต์ mocked/injected failure ไม่ใช่ผล live failure ของ host

สถานะ PASS ของ live harness หมายถึง collection และ negative fail-closed contract ผ่านเท่านั้น ไม่ใช่ production, completeness, authenticated provenance หรือ authorization Approval/DEC/core/exact-key semantics เดิมไม่เปลี่ยน ผู้ใช้ต้องทดสอบบน Linux host ที่รองรับจริงก่อนปิด live blocker Image tags/apt repositories ยัง mutable ไม่อ้าง build reproducibility แบบ immutable digest ไม่เผยแพร่ raw traces ที่อาจมี secrets

รายงานนี้เป็นสถานะรอบล่าสุด; รายงานเก่าเป็นประวัติ Scope audit/manifest อัปเดต และแพ็กเกจไม่มี binaries
