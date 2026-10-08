# รายงานตรวจสโคปและ hardening รอบล่าสุด

## ผลสรุป

ทำและทดสอบเส้นทาง local protected payload → Go preview → local acceptance/replay ได้จริงระหว่าง Python กับ Go โดยใช้ synthetic payload ไม่ใช่ live syscall collection ส่วน artifact → live sandbox ยังติด ptrace/namespaces ตาม probe จริง และ Candidate → CAP Evidence → authorization ยังไม่เปิดเพราะ semantics ยัง PROPOSED ไม่อ้างว่าสมบูรณ์หรือพร้อม production

## ตรวจตามสโคป

| รายการ | ผลที่ทำ | หลักฐาน / ข้อจำกัด |
|---|---|---|
| Runtime จริง | probe และ pipeline command หยุดเมื่อ prerequisite ไม่ผ่าน | tracing/sandbox blocked, compiler available; workload ไม่ถูก execute |
| Acceptance ↔ preview | เพิ่ม cmd/rawpreview และ pipeline/bridge; snapshot bytes แบบ private ก่อนส่ง Go; preview failure ไม่ consume run | real Go executable integration test ผ่านบน synthetic payload; ไม่ใช่ remote binding authentication |
| Process attribution | sidecar PID/event ID; successful workload exec และ observed clone/fork descendants; ล้าง ownership เมื่อพบ exit | synthetic traces ผ่าน; missing/resumed clones และ PID namespaces ยังไม่ครบ; unattributed events ไม่ถูกแปลงเป็น package operations |
| Target identity | แยก connect/bind และ stat/read, เก็บ port และ lexical identities | FD decode/path/symlink/interpreter ยังไม่ใช่ authenticated identities; ไม่ต่อ core host-only conversion |
| Sandbox | empty root; mount runtime dirs read-only, private work, proc/dev/tmp; ไม่มี host root/home/etc mount | argument construction tested; live sandbox blocked; /usr ยังมองเห็น ต้อง review ก่อน hostile package |
| Artifact binding | executable/source/trace/payload digest ก่อน/หลังแบบ PoC | ยังไม่ใช่ signed archive attestation หรือ adversarial TOCTOU protection |
| Replay/freshness | private caller-owned SQLite, unique transaction, exact bytes/run/artifact/analyzer/time | local tests ผ่าน; deleting ledger resets history; distributed replay/authentication ยังขาด |
| Error/cleanup | resource limits, fixed-code errors, process-group timeout/reap, staged output, private files, no overwrite | injected write/fsync failure ไม่เหลือ partial run; mocked timeout/exit race ผ่าน; live descendant cleanup ไม่ได้พิสูจน์ |
| Coverage/UNKNOWN | complete=false เสมอ; unsupported/truncated events ยังอยู่ | ไม่อ้าง loss-free coverage หรือสร้าง negative assertion |
| UX | probe/collect/pipeline, README วิธี build/run/test และ blocker/exit codes | CLI smoke และ bridge ผ่าน; ยังไม่มี user acceptance test |
| Governance | ไม่เปลี่ยน DEC/approver และไม่อ้าง approval | owner ยังต้องตัดสิน semantics/capability mapping |
| Public release | แก้ checklist ที่ล้าสมัยเรื่อง OpenSSF spike | ไม่มี repo URL/repo name, private reporting channel หรือ license confirmation ที่ตรวจแล้ว; ไม่ publish |

## บัคที่แก้และการทดสอบ

- binding ที่หาย/ไม่ใช่ object และ naive timestamps: reject ด้วย fixed code แทน exception ที่ไม่ควบคุม
- start time หลัง end time: reject ก่อนยอมรับ event/replay
- PID หลัง observed exit: ไม่คง ownership ไปถึง PID reuse
- preview payload substitution: Go อ่าน private snapshot ของ bytes ที่ตรวจ digest แล้ว
- output writes: private staging, fsync, directory commit; injected failure ไม่ทำให้มี run บางส่วน
- timeout/process exit race: ProcessLookupError ยังต้อง reap process และคง failure

Python **20 tests passed** รวม integration กับ Go binary จริง แต่ syscall traces เป็น synthetic; Go **244 pass events**, **4 skips** เดิม; vet/race ผ่าน; FuzzInspect 10 วินาทีที่กำหนด **93,171 executions** ผ่าน C workload warnings-as-errors syntax check ผ่านแต่ไม่ได้ execute External CI ไม่ได้รัน ไม่ได้ทดสอบ Windows

Test `test_outside_run_does_not_consume` เดิมเปลี่ยน expected reason เป็น invalid_run_time เพราะ envelope นั้นมี start หลัง end; ยังคงตรวจว่า failed envelope ไม่ consume run ไม่เปลี่ยน core tests การทดสอบ direct output failure ใช้ fault injection ไม่ใช่การทำ disk เต็มจริง

## ข้อจำกัดสำคัญที่ยังเหลือ

ต้องใช้ Linux VM/runtime ที่ ptrace/namespaces ทำงานได้เพื่อพิสูจน์ live success path, process attribution และ cleanup จริงก่อน ข้อมูลที่อนุญาตเป็นเพียง controlled workload ห้ามรัน package อันตรายหรือ arbitrary command ใน PoC นี้ ไม่มี production auth/replay, signed provenance, complete coverage, authoritative path/executable identity, general secret-redaction engine หรือ full CAP authorization เส้นทาง pipeline exit 0 หมายถึง inspection เท่านั้น

หลักฐาน strace presentation: https://man7.org/linux/man-pages/man1/strace.1.html (การสลับ unfinished/resumed และ PID presentation เป็นเหตุให้ parser ยังอนุรักษ์นิยม) Manifest ตรวจ bytes ไม่ใช่ trust anchor Scope audit อยู่ใน pipeline-scope-audit.json
