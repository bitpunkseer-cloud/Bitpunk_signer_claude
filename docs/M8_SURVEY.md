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

## 7. 하드웨어 (H4 보드 결정 자료) — v3 (2026-11)

### 7.1 선정 기준 (사용자 지정, v3)

1. **최근 출시** — 2024년 이후 나온 보드
2. **앞으로 여러 해 생산** — 제조사가 공개한 장기 공급 약속이 있을 것
3. **통신 모듈 없음** — Wi-Fi·블루투스·NFC·셀룰러·이더넷. **통신 칩이 있어도 물리적으로 떼어 낼 수 있으면 후보로 본다** (§7.3 제거 정책)
4. **물리 키보드를 붙일 수 있음** — CardKB v1.1(I2C)을 전기적으로 연결하고 기기에 고정할 수 있을 것
5. **화면·카메라(QR)·microSD**가 있을 것

v1 1순위였던 STM32H747I-DISCO는 2019년 출시라 1을 못 지켜 탈락.

### 7.2 키보드 — CardKB v1.1

| 항목 | 내용 |
|---|---|
| 부품 | M5Stack Unit CardKB v1.1, QWERTY 50키, 인코딩 MCU ATmega8A |
| 연결 | I2C 주소 `0x5F`, HY2.0-4P(Grove 계열) 단자: GND · **5V** · SDA · SCL |
| 주의 | I2C 신호 전압은 공식 자료에 없음 → CardKB 회로도로 풀업 전압 확인. 5 V 풀업이면 I2C 레벨 변환기(예: PCA9306)를 넣는다 |
| 고정 | 화면 아래에 CardKB를 고정하는 케이스(3D 프린트) — H 트랙 |

### 7.3 통신 모듈 제거 정책

| # | 규칙 |
|---|---|
| R1 | 무선이 **주 칩(SoC) 안에** 있으면 떼어 낼 수 없으므로 **탈락** (예: ESP32-S3 키보드 일체형 기기) |
| R2 | 별도 칩·모듈·커넥터는 떼어 내고, 뗀 뒤에도 보드가 정상 동작해야 한다 |
| R3 | 떼어 낸 뒤에도 MCU 안의 이더넷 MAC·USB 컨트롤러는 남는다. 다만 밖으로 나가는 물리 계층(PHY·커넥터)이 없으므로 신호 경로가 없다. 펌웨어는 해당 클록을 켜지 않고 핀을 아날로그 입력으로 둔다 |
| R4 | **제거 확인 자가 시험** — 부팅할 때마다 GPIO로 MDIO를 직접 흉내 내(비트뱅) PHY 주소 0~31의 ID 레지스터를 읽는다. 응답이 있으면 "통신 칩 감지"로 보고 시드 불러오기·서명을 거부한다. 이더넷 주변장치는 켜지 않는다 |
| R5 | USB: 개발 중에는 디버거(ST-LINK) USB만 쓴다. OTG·호스트 단자는 펌웨어에서 켜지 않고, 최종 조립 때 떼어 낸다(선택). 최종 전원은 5 V 핀 |
| R6 | 제거는 되돌릴 수 없으므로 보드를 **2대** 사서 한 대로 먼저 해 본다. 제거 전·후 사진을 남긴다 |

### 7.4 후보 비교

| 후보 | 출시 | 장기 공급 | 통신 모듈 → 제거 | 화면 | 카메라 | microSD | 키보드 연결 | 칩·메모리 | 판정 |
|---|---|---|---|---|---|---|---|---|---|
| **STM32N6570-DK** | 2024-12 | ST 10년 롤링 (2025년 기준 **2035-01까지**, 매년 연장) | 1 Gbit 이더넷 PHY(RTL8211F) + RJ45(CN16) → **납땜 제거**. USB-A·OTG 단자는 끄고 최종 때 제거 | **5" 800×480** 정전식 터치 (**지금 UI와 같음**) | **5 MP MIPI CSI-2 모듈 포함**, ISP 내장 | 있음 | 아두이노 D14/D15(I2C1) + 5 V 핀 | STM32N657 Cortex-M55 800 MHz, SRAM 4.2 MB, PSRAM 256 Mbit, Octo-SPI 플래시 1 Gbit | **1순위** |
| STM32H7S78-DK | 2024-02 | ST 장기 공급 프로그램 (H7RS 날짜 미확인) | **Wi-Fi 도터보드(MB1400)** → 분리, 10/100 이더넷 RJ45 → 납땜 제거 | 5" 800×480 정전식 터치 | **FPC 커넥터만** (카메라 모듈 별매) | 있음 | 아두이노 헤더 | STM32H7S7 Cortex-M7 600 MHz(지금 빌드 대상과 같은 계열), SRAM 620 KB, PSRAM 256 Mbit, NOR 1 Gbit | 2순위 |
| Waveshare RP2350-Touch-LCD-3.5-C | 2026 | RP2350 칩 2045-01까지 (보드 약속 없음) | **없음 — 제거 작업 불필요** | 3.5" 320×480 (UI 재배치 필요) | OV5640 포함 | 있음 | 2.54 mm GPIO 헤더 (핀 배치 미확인) | RP2350B Cortex-M33 150 MHz, SRAM 520 KB (지금 `App` ≈ 245 KB) | 3순위 |
| M5Stack Tab5 | 2025 | 칩 2037 (보드 약속 없음) | ESP32-C6 모듈 → 케이스 안에서 납땜 제거 | 5" 1280×720 | 2 MP | 있음 | **Grove 단자(CardKB 바로 꽂힘)** | ESP32-P4 **v1.0 칩**, PSRAM 32 MB | 보류 |
| ESP32-P4X-Function-EV-Board | 2026 (v3.1) | 칩 2037 | ESP32-C6 모듈 → 납땜 제거 | 7" 1024×600 | 2 MP MIPI | 있음 | 헤더 | ESP32-P4 v3.x | 보류 |
| ALIENTEK DNESP32P4M | 2025-06 | 칩 2037 | 없음 | 별매 MIPI | 별매 MIPI | 있음 | 헤더 | ESP32-P4 (v1.x 가능성) | 보류 |
| NXP MIMXRT700-EVK | 2024 말 | 확인 필요 | 칩 없음, M.2 무선 슬롯 | 별매 | 별매 | 있음 | 아두이노·PMod | RT700, SRAM 7.5 MB | 보류 |
| STM32U5G9J-DK2 | 2024 | ST 10년 롤링 | 없음 | 5" 800×480 | **없음** | **없음** | 아두이노 | U5G9, SRAM 3 MB | 탈락 (카메라·SD 없음) |

**ESP32-P4 보드 보류 이유:** Espressif가 2026년 공지(PCN)로 칩을 v1.3 → v3.2로 바꾸고 있고 두 버전은 하드웨어·소프트웨어가 호환되지 않는다. Tab5는 v1.0 칩을 쓴다. 러스트 `esp-hal`의 P4 지원도 일부 불안정하다. v3.x 보드는 무선 모듈 제거가 필요하고 화면이 7"로 크다.

**참고로 본 키보드 일체형 기기:** M5Stack Cardputer·LilyGO T-Deck는 키보드가 붙어 있지만 무선이 주 칩(ESP32-S3) 안에 있어 R1로 탈락. ClockworkPi PicoCalc(2025)는 QWERTY 키보드·microSD에 Pico 2(무선 없음)를 꽂을 수 있지만 **카메라가 없어** 탈락.

### 7.5 1순위 STM32N6570-DK — 얻는 것과 치르는 것

| 얻는 것 | |
|---|---|
| 화면 | 800×480 → **지금 UI·시뮬레이터를 그대로** 쓴다 (재배치 없음) |
| 메모리 | SRAM 4.2 MB + PSRAM 32 MB → 앱 상태(약 245 KB)·카메라 프레임·큰 PSBT에 여유 |
| 카메라 | 5 MP 모듈 포함, 하드웨어 ISP로 축소·회색조 변환 → QR 인식에 유리 |
| 공급 | ST 10년 롤링 약속, 최신 STM32(2024-12) |
| 보안 기능 | TrustZone, 부트 ROM의 서명 부팅, OTP, 암호 가속기, TRNG, 탬퍼 핀 (M10 보안 저장에서 데이터시트로 확인) |
| 빌드 | Cortex-M55 → `thumbv8m.main-none-eabihf`. **지금 크레이트가 수정 없이 빌드됨을 확인** |

| 치르는 것 | 대응 |
|---|---|
| 이더넷 PHY(QFN)·RJ45 납땜 제거 (되돌릴 수 없음) | 핫에어·흡입기 작업 또는 수리점. 보드 2대, 사진 기록, R4 자가 시험 |
| 러스트 HAL: `stm32n6` 레지스터 정의(PAC)는 있으나 embassy 지원은 확인 안 됨 | 화면(LTDC)·카메라(CSI)·SDMMC·I2C·XSPI·클록 드라이버를 직접 작성 (프로젝트의 독립 코드 원칙과 같음, H2 작업량 증가) |
| 칩 안에 플래시 없음 → 펌웨어가 외부 플래시에 있음 | 부트 ROM이 서명을 검사한 뒤 내부 RAM에서 실행. 비밀은 플래시에 두지 않음 |
| USB 단자가 여럿 (ST-LINK·OTG·Type-A) | R5 |

출처: [STM32N6570-DK](https://st.com/en/evaluation-tools/stm32n6570-dk.html), [UM3300](https://www.st.com/resource/en/user_manual/um3300-discovery-kit-with-stm32n657x0-mcu-stmicroelectronics.pdf), [Zephyr STM32N6570-DK](https://docs.zephyrproject.org/latest/boards/st/stm32n6570_dk/doc/index.html), [ST STM32 장기 공급 확인 방법](https://community.st.com/t5/stm32-mcus/how-to-check-stm32-part-numbers-longevity/ta-p/863108), [stm32n6 PAC](https://docs.rs/crate/stm32n6/latest), [STM32H7S78-DK](https://st.com/en/evaluation-tools/stm32h7s78-dk.html), [UM3289](https://www.st.com/resource/en/user_manual/um3289-discovery-kit-with-stm32h7s7l8-mcu-stmicroelectronics.pdf), [Keil STM32H7S78-DK](https://www.keil.arm.com/boards/stmicroelectronics-stm32h7s78-dk-revd-be03ca6/), [MB1400 Wi-Fi 도터보드 (ST 커뮤니티)](https://community.st.com/t5/stm32-mcus-boards-and-hardware/procedure-to-update-mb1400-wi-fi-module-firmware-with-stm32h7s78/td-p/846939), [M5Stack CardKB v1.1](https://docs.m5stack.com/en/unit/Unit_CardKB_v1.1), [Waveshare RP2350-Touch-LCD-3.5](https://www.waveshare.com/RP2350-Touch-LCD-3.5.htm), [Switch Science 판매 페이지](https://www.switch-science.com/collections/raspberry-pi/products/11204), [Raspberry Pi 마이크로컨트롤러 제품 안내](https://pip-assets.raspberrypi.com/categories/1358-product-guides/documents/RP-009950-MM-1-Raspberry%20Pi%20Microcontrollers%20product%20guide.pdf), [RP2350 A4](https://www.raspberrypi.com/news/rp2350-a4/), [39C3: RP2350 서명 부팅 우회](https://media.ccc.de/v/39c3-of-boot-vectors-and-double-glitches-bypassing-rp2350-s-secure-boot), [M5Stack Tab5](https://docs.m5stack.com/en/core/Tab5), [CNX: Tab5](https://www.cnx-software.com/2025/05/09/m5stack-tab5-tablet-esp32-p4-iot-development-kit-5-inch-touchscreen-display-and-front-facing-camera/), [ESP32-P4X-Function-EV-Board](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32p4/esp32-p4x-function-ev-board/user_guide.html), [Espressif 장기 공급 약속](https://www.espressif.com/en/products/longevity-commitment), [ESP32-P4 PCN202600801](https://documentation.espressif.com/en/PCN202600801_ESP32-P4_Chip_Revision_v3.2_Upgrade_Chip_Revision_v1.3_Demand_Collection_and_EOL_Plan_Description.html), [esp-hal ESP32-P4](https://docs.espressif.com/projects/rust/esp-hal/1.2.0/esp32p4/esp_hal/index.html), [CNX: DNESP32P4M](https://www.cnx-software.com/2025/06/16/alientek-dnesp32p4m-an-esp32-p4-board-without-network-connectivity/), [NXP MIMXRT700-EVK](https://www.nxp.com/design/design-center/development-boards-and-designs/MIMXRT700-EVK), [STM32U5G9J-DK2](https://st.com/en/evaluation-tools/stm32u5g9j-dk2.html), [CNX: PicoCalc](https://www.cnx-software.com/2025/03/14/picocalc-kit-raspberry-pi-pico-handheld-terminal-backlit-stm32-qwerty-keyboard/).

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
