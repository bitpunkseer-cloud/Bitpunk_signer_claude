# M8 전수조사 — microSD · FAT · BIP-85 · 개인키 가져오기

레퍼런스 코드를 직접 읽고 정리했다 (M7과 같은 저장소). 외부 자료: BIP-85(본문·시험 벡터, 2.1.0), FatFs 설정(`ffconf.h`), 개발 보드 자료(2026-11 기준으로 다시 조사, §7).
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

## 7. 하드웨어 (H4 보드 결정 자료) — v2 재조사 (2026-11)

### 7.1 선정 기준 (사용자 지정)

1. **최근 출시** — 2024년 이후 나온 보드
2. **앞으로 여러 해 생산** — 제조사가 공개한 장기 공급 약속이 있을 것
3. **통신 모듈이 아예 없음** — Wi-Fi·블루투스·NFC·셀룰러 칩과 **이더넷 PHY·RJ45**가 보드에 없을 것. USB 단자는 전원용으로만 쓰고 데이터는 펌웨어에서 켜지 않는다(가능하면 칩 설정으로 영구 차단)
4. **프로젝트 요건 전부** — 화면, 키보드(CardKB, I2C), 카메라(QR), microSD

v1에서 1순위로 냈던 STM32H747I-DISCO는 1(2019년 출시)과 3(이더넷 RJ45)을 못 지켜 **탈락**.

### 7.2 후보 비교

| 후보 | 출시 | 장기 공급 | 통신 모듈 | 화면 | 카메라 | microSD | 키보드(I2C) | 칩·메모리 | 러스트 | 판정 |
|---|---|---|---|---|---|---|---|---|---|---|
| **Waveshare RP2350-Touch-LCD-3.5-C** | 2026 (일본 판매점 표준판 발매일 2026-07-30) | **RP2350 칩 2045-01까지**, Pico 2 보드 2040-01까지 (Raspberry Pi 공표). 보드 자체 약속은 없음 | **없음** (칩·보드 모두 무선 없음). Waveshare 비교표의 "무선 Plus" 변형은 사면 안 됨 | 3.5" IPS 320×480, ST7796(SPI), 정전식 터치 FT6336 | **OV5640 기본 탑재**(-C판), DVP | **TF 슬롯** | 2.54 mm GPIO 헤더 | RP2350B Cortex-M33 ×2 150 MHz, SRAM 520 KB, 플래시 16 MB, PSRAM 언급 없음. 보호 케이스 포함 | embassy-rp·rp235x-hal (성숙) | **1순위** |
| STM32U5G9J-DK2 | 2024 | ST 10년 롤링 장기 공급 | 없음 (이더넷·무선 없음) | **5" 800×480** RGB 정전식 터치 (지금 UI와 같은 해상도) | 보드에 커넥터 확인 안 됨 | 슬롯 확인 안 됨 | 아두이노 헤더 | STM32U5G9 Cortex-M33 160 MHz, SRAM 3 MB, 플래시 4 MB, OSPI 1 Gbit, TrustZone | embassy-stm32 | 대안 (카메라·SD를 확장 모듈로 붙여야 함) |
| ALIENTEK DNESP32P4M | 2025-06 | ESP32-P4 칩 12년 (2025-01 ~ 2037-01) | 없음 (Wi-Fi·이더넷 없음) | MIPI DSI 커넥터 (5.5"/10.1" 별매) | MIPI CSI 커넥터 (별매) | 있음 | 헤더 (GPIO 48개) | ESP32-P4 RISC-V, PSRAM 32 MB, NOR 16 MB | esp-hal 1.2에 P4 대상 있음, 일부 기능 불안정 | 보류 |
| NXP MIMXRT700-EVK | 2024 말 | NXP 장기 공급 프로그램 (기간 확인 필요) | 이더넷·무선 칩 없음, 단 **무선 카드용 M.2 슬롯** | MIPI 화면 커넥터 (별매) | FlexIO 카메라 헤더 (OV7675 별매) | SD 슬롯 | 아두이노·PMod | i.MX RT700 Cortex-M33 ×2, SRAM 7.5 MB | RT700용 HAL은 초기 단계로 보임 | 보류 |

**탈락 (통신 모듈 있음):**

| 보드 | 출시 | 탈락 이유 |
|---|---|---|
| STM32H747I-DISCO (v1 1순위) | 2019 | 오래됨 + 이더넷 RJ45 |
| STM32N6570-DK | 2024-12 | 화면·카메라·microSD 모두 있지만 **1 Gbit 이더넷 PHY(RTL8211F)·RJ45** |
| STM32H7S78-DK | 2024 | **Wi-Fi 모듈** + 이더넷 RJ45 |
| Renesas EK-RA8P1 | 2025 | 이더넷 RJ45 |
| Espressif ESP32-P4(X)-Function-EV-Board, ESP32-P4X-EYE | 2024~2026 | **ESP32-C6 Wi-Fi·블루투스 모듈** |
| Olimex ESP32-P4-DevKit | 2025 | 이더넷 |

### 7.3 1순위의 비용과 위험 (RP2350-Touch-LCD-3.5-C)

| 항목 | 내용 | 대응 |
|---|---|---|
| 화면 해상도 | 지금 UI는 **800×480 가로**. 이 보드는 **320×480 세로** (Krux의 Maix Amigo와 같은 해상도) | H2에서 화면 배치를 320×480으로 다시 짠다. 한글 2칸 글꼴·문자열 표는 그대로. 시뮬레이터도 같이 바꾼다 |
| RAM 520 KB | 지금 앱 상태(`App`) 크기를 재 보니 **약 245 KB** (x86-64, 2026-11). 카메라 프레임(320×240 회색조 77 KB)·스택·QR 디코더를 더하면 빠듯 | H3에서 메모리 예산표를 만들고 큰 버퍼를 겹쳐 쓴다(예: PSBT 버퍼와 카메라 버퍼). 화면은 ST7796 내부 메모리에 띠 단위로 보내므로 MCU 프레임버퍼는 필요 없음 |
| 빌드 대상 | `thumbv7em` → `thumbv8m.main-none-eabihf` (Cortex-M33) | **지금 크레이트 6개가 수정 없이 빌드됨을 확인** (2026-11) |
| 보안 기능 | 서명된 부팅(OTP에 키 해시), OTP 8 KB, TrustZone-M, 글리치 검출기, SHA-256 가속기, TRNG. 디버그와 USB 부트 인터페이스를 OTP로 끌 수 있음 | USB 데이터 경로·디버그를 **칩 설정으로 영구 차단** (정확한 OTP 항목은 데이터시트로 확인 후 M9 설계) |
| 알려진 약점 | 2024 해킹 챌린지에서 A2 스테핑에 결함 주입 공격 여럿. **A4 스테핑(2025-07)**에서 부트 ROM·OTP 결함 수정. 다만 서명 부팅 우회 일부는 실리콘에 있어 아직 해결책 없음(39C3 발표) | **A4 칩만** 쓴다. 지금 설계는 시드를 저장하지 않으므로 영향은 펌웨어 바꿔치기로 제한 → 부팅 화면에 펌웨어 해시 표시 등 보완(M9) |
| 외부 플래시 | 펌웨어가 칩 밖 QSPI 플래시에 있음 → 물리 접근 시 읽기·교체 가능 | 서명 부팅으로 교체 탐지(위 약점 주의), 비밀은 플래시에 두지 않음 |
| 보드 공급 | Waveshare는 보드 단위 장기 공급을 약속하지 않음 | 부품이 단순(RP2350B·ST7796·OV5640·TF)하고 회로도가 공개돼 있어 H4 최종 보드는 같은 부품으로 직접 만들 수 있음. 개발용 2~3대 미리 확보 |
| 카메라 초점 | OV5640 모듈의 초점 방식(고정·자동) 미확인 | 가까운 거리 QR 인식을 첫 시험 항목으로 |
| 키보드 전압 | CardKB는 Grove 5 V | A4는 5 V 허용 GPIO이지만 칩 전원이 켜져 있어야 함 → I2C 풀업을 3.3 V로 두고 확인 |

**2순위(STM32U5G9J-DK2)를 고르면:** UI를 그대로 쓰고(800×480) RAM이 3 MB로 넉넉하며 TrustZone 기반 보안 기능이 많다. 대신 보드에 카메라·microSD가 없어서 아두이노 헤더에 SPI 카메라와 microSD 모듈을 붙여야 하므로 "보드 하나로 요건 전부"가 아니다.

**DNESP32P4M 보류 이유:** 통신 모듈은 없지만, Espressif가 2026년 PCN으로 ESP32-P4를 칩 v1.3 → v3.2로 바꾸고 있고 두 버전은 하드웨어·소프트웨어가 호환되지 않는다. 2025년에 나온 이 보드는 v1.x 칩일 가능성이 높아(확인 필요) 바뀌거나 단종될 위험이 있다. 무선 없는 v3.x 보드가 나오면 다시 본다.

출처: [Waveshare RP2350-Touch-LCD-3.5](https://www.waveshare.com/RP2350-Touch-LCD-3.5.htm), [회로도 PDF](https://files.waveshare.com/wiki/RP2350-Touch-LCD-3.5/RP2350-Touch-LCD-3.5.pdf), [Switch Science 판매 페이지](https://www.switch-science.com/collections/raspberry-pi/products/11204), [Raspberry Pi Pico 2 (2040년까지 생산)](https://www.raspberrypi.com/products/raspberry-pi-pico-2/), [Raspberry Pi 마이크로컨트롤러 제품 안내(RP2350 2045년)](https://pip-assets.raspberrypi.com/categories/1358-product-guides/documents/RP-009950-MM-1-Raspberry%20Pi%20Microcontrollers%20product%20guide.pdf), [RP2350 A4 스테핑](https://www.raspberrypi.com/news/rp2350-a4/), [해킹 챌린지 결과](https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/), [39C3: RP2350 서명 부팅 우회](https://media.ccc.de/v/39c3-of-boot-vectors-and-double-glitches-bypassing-rp2350-s-secure-boot), [Hackaday: RP2350 공격 정리](https://hackaday.com/2025/01/15/all-the-attacks-on-the-rp2350), [STM32U5G9J-DK2](https://st.com/en/evaluation-tools/stm32u5g9j-dk2.html), [UM3223](https://www.st.com/resource/en/user_manual/um3223-discovery-kit-with-stm32u5g9zj-mcu-stmicroelectronics.pdf), [STM32N6570-DK](https://st.com/en/evaluation-tools/stm32n6570-dk.html), [STM32H7S78-DK](https://www.st.com/en/evaluation-tools/stm32h7s78-dk.html), [CNX: ALIENTEK DNESP32P4M](https://www.cnx-software.com/2025/06/16/alientek-dnesp32p4m-an-esp32-p4-board-without-network-connectivity/), [Espressif 장기 공급 약속](https://www.espressif.com/en/products/longevity-commitment), [ESP32-P4 PCN202600801](https://documentation.espressif.com/en/PCN202600801_ESP32-P4_Chip_Revision_v3.2_Upgrade_Chip_Revision_v1.3_Demand_Collection_and_EOL_Plan_Description.html), [esp-hal ESP32-P4 문서](https://docs.espressif.com/projects/rust/esp-hal/1.2.0/esp32p4/esp_hal/index.html), [ESP32-P4X-Function-EV-Board](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32p4/esp32-p4x-function-ev-board/user_guide.html), [NXP MIMXRT700-EVK](https://www.nxp.com/design/design-center/development-boards-and-designs/MIMXRT700-EVK).

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
