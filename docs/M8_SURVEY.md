# M8 전수조사 — microSD · FAT · BIP-85 · 개인키 가져오기

레퍼런스 코드를 직접 읽고 정리했다 (M7과 같은 저장소). 외부 자료: BIP-85(본문·시험 벡터, 2.1.0), FatFs 설정(`ffconf.h`), STM32H747I-DISCO 자료.
목적: SD 카드를 **신뢰할 수 없는 매체**로 다루면서 PSBT·지갑 파일을 주고받는 가장 안전한 규칙을 고르고, BIP-85와 개인키 가져오기의 범위를 정하기 위함. 코드는 참고만 하고 복사하지 않는다.

| 약어 | 프로젝트 | 읽은 곳 |
|---|---|---|
| CC | Coldcard | `shared/files.py`(CardSlot·파일 이름·안전 삭제·포맷), `auth.py`(`sign_psbt_file`, `_save_to_disk`), `actions.py`(PSBT·메시지 파일 고르기), `drv_entro.py`(BIP-85), `wif.py`(WIF 저장소), `actions.py import_xprv` |
| KX | Krux | `sd_card.py`, `pages/file_operations.py`·`file_manager.py`, `encryption.py`·`kef.py`(SD 암호화 니모닉), `pages/home_pages/bip85.py` |
| SP | Specter DIY | `hosts/sd.py`, `apps/bip85.py` |
| PP | Passport Prime (KeyOS) | `apps/gui-app-file-browser`, `os/fs`(rust-fatfs 포크), `gui-app-seed-vault`(BIP-85) |
| KS | Keystone 3 | `external/fatfs/ffconf.h`, 멀티시그 SD 위젯 |
| OK | OneKey Pro | `trezorhal/fatfs/ffconf.h` |
| JD | Jade | `qrmode.c`(BIP-85, 암호화 응답) |
| SS | SeedSigner | SD는 OS 이미지 전용, 데이터 저장 없음(상태 없는 기기) |

## 1. SD 카드 수명 주기

| | 쓰는 방식 | 특징 |
|---|---|---|
| CC | 작업마다 마운트 → 끝나면 **언마운트 + 슬롯 전원 차단**, 활동 LED | 카드 감지 핀 디바운스(50 ms), 카드가 없으면 "Need a card" 후 재시도, 읽은 PSBT는 **PSRAM에 복사한 뒤 카드와 무관하게 처리**(다른 카드에 써도 됨) |
| SP | 읽은 즉시 내부 플래시로 복사하고 **곧바로 언마운트** | 이후 처리 중 카드가 바뀌어도 영향 없음 |
| KX | 작업마다 다시 마운트 | 설정 저장 위치로도 사용 |
| PP | 파일 브라우저 앱이 위치(SD·내부)별로 관리 | 숨김 파일 표시 토글, 파일 이름 검사 |

## 2. PSBT 파일 서명

| | 입력 | 출력 이름 | 덮어쓰기 | 원본 처리 |
|---|---|---|---|---|
| CC | `.psbt` 내용 맛보기: **바이너리 / hex / base64** 자동 판별, 최대 크기 검사(인코딩은 디코딩하며 검사), `-signed`가 든 파일은 목록에서 제외 | 완성: `이름-signed.psbt` + `이름-final.txn`(hex), 미완성(멀티시그): `이름-part.psbt` | **안 함**: 있으면 `-2`, `-3`…(지운 번호도 건너뜀) | 설정 "PSBT 지우기" 켜면 **0으로 덮고 → 이름을 `xxxx`로 바꾼 뒤 → 삭제**, 최종 tx는 `txid.txn` |
| SP | `.psbt` `.txt` `.json` 목록, 파일마다 메뉴 | `이름.signed.<서명자 지문>.psbt` (멀티시그 서명자끼리 겹치지 않음) | 있으면 "덮어쓸까요?" | 유지 |
| KX | SD에서 불러오기 | 사용자가 이름을 입력(기본: 원래 이름 + `-signed`) | 확인 | 유지 |
| KS | 멀티시그 PSBT를 SD에서 | — | — | "이미 서명된 거래" 감지 |

## 3. 기타 파일

| | 내용 |
|---|---|
| CC | 메시지 파일(`.txt` 1~3줄: 메시지·경로·주소 종류) 서명 → `.sig` 파일, 지갑 파일(멀티시그 텍스트·`ccxp` JSON) 내보내기/가져오기, 백업(암호화 7z), **SD 포맷**(앞 1,024블록을 난수로 덮고 새 FAT 생성), BIP-85 결과를 SD에 텍스트로 저장(+ 서명 파일) |
| KX | 니모닉을 **AES로 암호화해 SD에 저장**(KEF 형식, PBKDF2), 설정을 SD에 저장, 디스크립터·주소 CSV·서명·공개키·QR 이미지(BMP/SVG) 저장 |
| SP | BIP-85 니모닉을 SD에 저장 가능 |

## 4. BIP-85 (본문 2.1.0)

경로 `m/83696968'/{앱}'/…/{index}'`, 엔트로피 = `HMAC-SHA512("bip-entropy-from-k", 유도한 개인키)`.

| 앱 | 번호 | 출력 | CC | SP | KX | PP | JD |
|---|---|---|---|---|---|---|---|
| BIP-39 니모닉 | 39' | 12/18/24 단어 (영어 0') | ✓ | ✓ | ✓ | ✓ | ✓(암호화 QR 응답) |
| HD-Seed WIF | 2' | 압축 WIF | ✓ | ✓ | | | |
| XPRV | 32' | **앞 32바이트 = 체인코드, 뒤 = 개인키**(BIP-32와 반대 순서, 본문 경고) | ✓ | ✓ | | | |
| HEX | 128169' | 16~64바이트 | 32·64 | ✓ | | | |
| PWD BASE64 | 707764' | 20~86자 | 21자 고정 | | ✓(길이 선택) | | |
| PWD BASE85 | 707785' | 10~80자 | | | | | |
| DICE | 89101' | 주사위 값(BIP85-DRNG = **SHAKE256**) | | | | | |
| Nostr | 128002' | (2.1.0 신규) | | | | | |

- 공통 화면: 결과 + 경로 + 원시 엔트로피 표시, QR(CC는 니모닉을 단어 앞 4글자로 줄여 영숫자 QR), **유도된 시드로 전환/불러오기**(CC·SP·KX).
- CC: 패스프레이즈가 걸려 있으면 "새 시드에 반영된다"고 경고, 번호 상한(기본 9,999, 설정으로 해제).
- 결과를 **SD에 평문으로 저장**: CC·SP·KX 모두 허용 — 비밀이 신뢰할 수 없는 매체에 남는다(약점).
- 본문 시험 벡터: 니모닉 12/18/24, WIF, XPRV, HEX, PWD BASE64/85, DICE(6면 10회).

## 5. 개인키 가져오기

| | WIF | XPRV |
|---|---|---|
| CC | **WIF 저장소**(최대 30개): QR·NFC·직접 입력·SD 텍스트(쉼표/공백 구분, 쓰레기 줄 무시). **압축 키만**, 네트워크 일치 필수. PSBT 입력은 스크립트 해시로 매칭(P2PKH·P2WPKH·P2SH-P2WPKH, P2WSH·P2TR 제외) | QR·NFC·SD 파일에서 `xprv`/`tprv`(y/zprv 포함)를 찾아 **임시 시드로**(영구는 시크릿이 없을 때만) |
| SP | — | BIP-85 결과를 불러오기 |
| KX | — | — |

## 6. FAT 파일시스템

| | 구현 | exFAT | 긴 이름(LFN) |
|---|---|---|---|
| CC | MicroPython `vfs_fat`(ChaN FatFs) | — | ✓ |
| KS | ChaN FatFs | **켬** (`FF_FS_EXFAT 1`) | ✓ |
| OK | ChaN FatFs | 끔 (`FF_FS_EXFAT 0`) | ✓ |
| PP | rust-fatfs 포크(FAT12/16/32) | — | ✓(alloc) |

- 64 GB 이상(SDXC) 카드는 보통 exFAT로 출하된다 → FAT32로 다시 포맷해야 하는 경우가 많다(기기에서 포맷하는 기능이 있으면 편하다: CC).
- 신뢰할 수 없는 매체의 파서에서 흔한 위험: 잘못된 BPB(0 나누기·범위 밖), **클러스터 체인의 고리·교차**, 끝없는 디렉터리, LFN 체크섬 불일치·조각난 LFN, 파일 크기와 체인 길이 불일치, FSInfo 빈 공간 값 거짓.

## 7. 하드웨어 (H4 보드 결정 자료)

| 후보 | 무선 | 장점 | 주의 |
|---|---|---|---|
| **STM32H747I-DISCO** | 없음 | Cortex-M7(지금 빌드 대상 `thumbv7em`과 같은 계열), 4" MIPI-DSI 정전식 터치 LCD, SDRAM 256 Mbit, QSPI NOR 2×512 Mbit, **microSD**, **8비트 카메라 커넥터**(DCMI), 칩 내장 TRNG | 보드에 **이더넷 RJ45·USB OTG**가 있음 → 개발용으로만, 최종 보드에서는 빼야 함. LCD 해상도는 사용자 설명서로 확인 필요 |
| i.MX RT1170 EVK | 없음 | Cortex-M7 1 GHz, MIPI-CSI/DSI, SD, TRNG | 보드 가격·러스트 지원 정도 확인 필요 |
| Raspberry Pi Zero v1.3 | 없음 | SeedSigner와 같은 구성 | 카메라가 닫힌 펌웨어(VideoCore) 의존, 리눅스면 공격 표면이 큼 |
| Kendryte K210 (Maix Amigo) | 없음 | Krux가 쓰는 보드: 카메라·SD·화면 일체 | RISC-V, 러스트 생태계 약함, 하드웨어 TRNG 여부 확인 필요 |
| ESP32-P4 | 칩에 없음 | 카메라·DSI·SD | 많은 개발 보드가 **Wi-Fi 보조칩(ESP32-C6)을 함께 실음** → HW-1 위반 위험, 피하는 쪽이 안전 |

출처: [ST STM32H747I-DISCO 제품 페이지](https://www.st.com/en/evaluation-tools/stm32h747i-disco.html), [데이터 브리프](https://st.com/resource/en/data_brief/dm00504238.pdf), [UM2411 사용자 설명서](https://www.st.com/resource/en/user_manual/um2411-discovery-kit-with-stm32h747xi-mcu-stmicroelectronics.pdf).

## 8. 정리 — 가져올 것과 피할 것

| 가져올 것 | 출처 |
|---|---|
| 작업마다 마운트, 읽은 내용은 내부 버퍼로 복사 후 **즉시 언마운트·전원 차단** | CC, SP |
| PSBT 인코딩 자동 판별(바이너리·hex·base64) + 크기 상한을 **디코딩하면서** 검사 | CC |
| **덮어쓰지 않기**(번호 붙이기), `-signed`가 든 파일은 서명 목록에서 제외 | CC |
| 멀티시그 서명자별로 겹치지 않는 출력 이름(지문 포함) | SP |
| 원본 PSBT 지우기는 선택: 0으로 덮기 → 이름 바꾸기 → 삭제 (플래시 특성상 완전 삭제 보장은 없음을 알림) | CC |
| 메시지 `.txt` 서명 → `.sig` | CC |
| 기기에서 SD 포맷 | CC |
| 파일 이름 검사(제어문자·예약문자·끝 공백/점) | PP |
| BIP-85: 니모닉·WIF·XPRV·HEX·패스워드, 경로·엔트로피 표시, 유도 시드 불러오기, 패스프레이즈 경고 | CC, SP, KX |
| WIF: 압축만, 네트워크 일치, 스크립트 해시로 입력 매칭 | CC |

| 피할 것 | 이유 |
|---|---|
| BIP-85 결과·개인키를 SD에 평문 저장 (CC·SP·KX 허용) | 비밀이 신뢰할 수 없는 매체에 남고, 플래시는 지워도 남을 수 있음 |
| 서명 결과를 묻지 않고 덮어쓰기 | 다른 서명자의 결과를 잃을 수 있음 |
| exFAT 파서 (KS) | 구조가 복잡해 공격 표면이 큼; FAT32 재포맷으로 대신 |
| 설정을 SD에서 그대로 적용 (KX) | 바꿔치기한 파일로 수수료 차단선 등 보호를 약하게 할 수 있음 → SettingsQR처럼 "약화 금지" |
