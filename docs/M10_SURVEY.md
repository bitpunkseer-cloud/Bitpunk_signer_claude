# M10 전수조사 — 보안 저장 (PIN·잠금·시드 보관함)

레퍼런스 코드를 직접 읽고 정리했다(M7·M8과 같은 저장소). STM32N6은 ST의 공개 HAL 드라이버(`stm32n6xx-hal-driver`: BSEC·SAES/CRYP·RTC/TAMP·MCE 헤더와 소스)를 읽었고, 웹 문서(ST 위키, 제조사 문서)는 이 환경에서 직접 열리지 않아 검색 요약만 참고했다(아래 출처에 표시, **H 트랙에서 실기기로 확인할 항목**은 ◇로 표시).
목적: 시드를 기기에 저장할 때 **도난·분실·플래시 탈취·롤백·피싱·강요**를 견디는 가장 안전한 구조를 고르고, 보안 칩을 쓸지 정하기 위함. 코드는 참고만 하고 복사하지 않는다.

| 약어 | 프로젝트 | 읽은 곳 |
|---|---|---|
| CC | Coldcard Mk4/Q | `docs/pin-entry.md`, `docs/security-model.md`, `shared/pincodes.py`·`login.py`·`trick_pins.py`·`countdowns.py`, `stm32/bootloader/pins.c` |
| PP | Passport Prime (KeyOS) | `api/security/src/lib.rs`, `os/security/src/atsama5d2.rs`, `os/gui-app-lock-screen` |
| KS | Keystone 3 | `src/ui/gui_model/gui_model.h`, `src/driver/drv_atecc608b.h` |
| OK | OneKey Pro | `core/embed/trezorhal/se_thd89.h` |
| SP | Specter DIY | `src/keystore/flash.py`·`ram.py`·`memorycard.py`·`javacard/` |
| KX | Krux | `src/krux/kef.py`·`encryption.py`, `pages/tc_code_verification.py`·`flash_tools.py`, `krux_settings.py` |
| JD | Jade | 블라인드 오라클 PIN 서버(네트워크 필요) |
| SS | SeedSigner | 상태 없는 기기(저장 없음) |

## 1. 레퍼런스 비교

| | 시드가 있는 곳 | 보안 칩 | PIN | 오입력 한도 → 결과 | 피싱 방지 | 강요 대응 |
|---|---|---|---|---|---|---|
| CC | SE1(ATECC608) 안에 **암호화**해서. 복호 키는 **MCU·SE1·SE2 셋에 나눔**("셋 모두 뚫려야 유출") | SE1 ATECC608 + SE2 DS28C36B | 숫자 앞부분 2–6자리 + 뒷부분 2–6자리 | **13회 → 벽돌**(설정과 무관), 틀릴 때마다 대기 시간 | 앞부분 → **단어 2개**(608 칩 키 늘이기로 계산 = 칩이 속도 제한, 기기마다 다름). 단어 화면에서 지정 키 = 즉시 지우기(Kill Key) | **Trick PIN**(SE2에 저장): 시드 지우기, 빈 기기 흉내, 미끼 지갑(BIP-85 1001~1003·2001~2003), 벽돌, 로그인 카운트다운, 틀린 척, Delta 모드. 로그인 지연은 전원이 꺼지면 처음부터(최대 28일) |
| PP | SE 안에 `시드 ⊕ PIN 해시 ⊕ otp_key`. `otp_key`(72 B)는 **배터리로 유지되는 SECURAM**(탬퍼 시 지워짐) | ATECC608 | 숫자 | **10회 → 시드 지움**(`MAX_LOGIN_ATTEMPTS = 10`) | 앞부분 → 보안 단어 2개 | — |
| KS | SE | ATECC608B 등 | 영숫자 비밀번호 | 로그인 10회(`MAX_LOGIN_PASSWORD_ERROR_COUNT`) | — | — |
| OK | SE(THD89) | THD89 | 숫자(Trezor 방식) | 한도 후 지움 | — | 지우기 코드(Wipe code) |
| SP | MCU 내부 플래시(MCU 비밀값으로 암호화), SD·JavaCard 선택 가능 | 선택(JavaCard) | 숫자, `HMAC(비밀값, PIN)` 비교 | **10회 → 지움** | **한 자리 칠 때마다 단어 1개**(`HMAC(tagged_hash("auth", 비밀값), 지금까지의 PIN)`) | — |
| KX | 저장은 선택: 플래시·SD에 **암호화 니모닉(KEF)** — PBKDF2-HMAC-SHA256 + AES(ECB·CBC·CTR·GCM 버전) | 없음 | 없음(상태 없음 + 선택적 암호화 저장) | — | **Tamper Check Code**: 사용자 코드 → `PBKDF2(SHA256(코드), 칩 ID, 100,000)` 확인 후 `SHA256(코드 해시 ‖ 칩 ID ‖ 플래시 전체)`를 색·무늬로 보여 줌 → 펌웨어가 바뀌면 무늬가 바뀜 | — |
| JD | 서버가 PIN을 대신 검사(블라인드 오라클) | 가상 SE | 숫자 | 서버가 셈 | — | — |
| SS | 저장 안 함 | — | — | — | — | — |

정리:
- **보안 칩이 있는 기기(CC·PP·KS·OK)는 오입력 횟수를 칩이 센다.** 펌웨어나 플래시를 되돌려도 횟수가 되돌아가지 않는다. 한도는 10~13회, 넘으면 지우거나 벽돌.
- 보안 칩이 없는 기기(SP)는 횟수를 MCU 플래시에 둔다 — 플래시를 되돌릴 수 있는 공격자에게는 약하다. KX는 아예 잠금을 두지 않고 암호화 강도(KDF)에만 기댄다.
- 피싱 방지 단어는 CC·PP 방식(앞부분 → 단어 2개, 기기 비밀로 계산)과 SP 방식(한 자리마다 단어 1개)이 있다. 핵심은 **가짜 펌웨어·다른 기기는 같은 단어를 만들 수 없어야** 한다는 것(기기 고유 비밀이 필요).
- 시드를 여러 곳에 나눠 두는 구조(CC: MCU+SE1+SE2, PP: SE+SECURAM+PIN)가 한 부품의 결함으로 시드가 새는 것을 막는다.

## 2. STM32N6 보안 기능 (HAL 드라이버에서 확인)

| 기능 | 내용 | 쓸 곳 |
|---|---|---|
| **칩 안 플래시 없음** | 펌웨어·데이터는 외부 XSPI 플래시(DK: 1 Gbit 옥토 플래시 ◇). 플래시는 떼어 읽을 수 있다 | 저장하는 모든 것은 **암호화 + 인증** |
| **SAES + DHUK** | 키 선택: 일반 키 / **DHUK**(칩 고유 키에서 유도한 256비트, 소프트웨어가 읽을 수 없음) / BHK / DHUK⊕BHK / AHK / DHUK⊕AHK. 키 모드: 일반 / **감싸기(wrapped)** / 공유. DHUK 값은 HDPL 단계·보안 영역·**에포크 카운터** 선택에 따라 달라짐. BSEC로 DHUK 사용을 리셋까지 막을 수 있음(`HKLOCK`) | 저장 키를 **이 칩에서만 풀리게 감싼다** → 플래시를 떼어 가도 소용없음 |
| **BSEC OTP** | 퓨즈 **376워드**(워드마다 영구 잠금), 섀도 레지스터, 상위 퓨즈 숨김, 수명 주기 상태(open / closed / 탬퍼로 무효), **에포크 카운터 2개**(SAES에 연결 ◇ 올리는 방법·횟수), HDPL 0–3, HDPL별 디버그 잠금, 스크래치 4개 + 한 번 쓰기 스크래치 8개 | 서명 부팅 키 해시·롤백 방지(M12), 디버그 잠금, DHUK 무효화(◇) |
| **부팅 ROM 서명 부팅** | closed/locked 상태에서 FSBL 서명 검사 필수, OEM 키 해시와 롤백 카운터가 OTP에 ◇ | 펌웨어 바꿔치기 방지 — 설계는 M10, 퓨즈 굽기는 M12 |
| **TAMP** | 백업 레지스터 **32개**(탬퍼 시 지우기 설정 가능), **단조 카운터**, 내부 탬퍼 원인들. DK는 **VBAT가 3.3 V 전원에 연결**(커뮤니티 보고 ◇) → 전원을 끄면 백업 영역도 지워짐 | 전원이 켜져 있는 동안의 비밀·탬퍼 반응. 전원이 꺼져도 남기려면 코인 전지 개조 필요 |
| **MCE** | 외부 메모리 실시간 암호화(AES-128 블록·스트림) ◇ | 펌웨어 기밀성(선택). 저장소는 따로 AEAD로 암호화 |
| 기타 | PKA, TRNG, HASH, CCB(PKA 키 감싸기) | TRNG는 솔트·논스, 시드는 여전히 주사위·동전만 |

## 3. 오입력 횟수를 "되돌릴 수 없게" 셀 곳

이 결정이 M10의 핵심이다. 횟수를 외부 플래시에만 두면, 공격자가 플래시 내용을 미리 복사해 두었다가 몇 번 틀릴 때마다 되돌려 **무제한으로** 시도할 수 있다.

| 위치 | 되돌리기 공격 | 전원 꺼짐 | 평가 |
|---|---|---|---|
| 외부 플래시 | **가능**(복사·되쓰기) | 남음 | 단독으로는 안 됨 |
| TAMP 백업 레지스터·단조 카운터 | 불가(칩 안) | **DK에서는 지워짐**(VBAT = 3.3 V) | 코인 전지 개조 시 쓸 만함. 전지를 빼면 비밀도 지워지게 설계 가능(PP의 SECURAM과 같은 구조) |
| OTP 퓨즈(시도마다 1비트) | 불가 | 남음 | 되돌릴 수 없지만 **평생 횟수가 정해짐**(성공해도 되돌릴 수 없음) — 실용성 낮음 |
| **보안 칩(SE)** | 불가 | 남음 | **가장 좋음.** CC·PP·KS·OK가 모두 이 방식 |

## 4. 보안 칩 후보 (DK에 붙일 수 있는 것)

| | NXP SE050 | Microchip ATECC608B | Infineon OPTIGA Trust M |
|---|---|---|---|
| 개발용 보드 | **OM-SE050ARD-E/F: 아두이노 실드** → DK 아두이노 헤더에 그대로 | 브레이크아웃 보드 | Shield2Go |
| 인터페이스 | I2C(주소 0x48), T=1 over I2C, APDU | I2C | I2C |
| 공개 문서 | **APDU 명세(AN12413)·하드웨어 개요(AN12395) 공개**, 정오표 공개 | 전체 데이터시트는 NDA(요약본·CryptoAuthLib 공개) | 데이터시트·호스트 라이브러리 공개 |
| 쓸 기능 | 인증 객체(UserID)에 **최대 시도 횟수**(넘으면 영구 잠김), 정책으로 보호한 AES·HMAC 키, **단조 카운터**, SCP03(호스트와 암호화 채널) | 슬롯·카운터·KDF, 지갑에서 실적 많음(CC·PP·KS) | 단조 카운터, 보호 업데이트 |
| 인증 | CC EAL 6+ | — | CC EAL 6+ |
| 메모 | CardKB(0x5F)와 같은 I2C 버스에 함께 둘 수 있음. 정오표에 I2C 잠김·SCP03 카운터 문제(대응 필요) | 설정 영역을 잠그면 되돌릴 수 없음 | — |

권장: **SE050**(공개 명세로 독자 구현 가능, DK에 바로 꽂힘, 시도 한도·카운터·키 정책을 칩이 강제).

## 5. 암호 요소

| 요소 | 표준 | 이유 | 검증 |
|---|---|---|---|
| **Argon2id** | RFC 9106 | 메모리를 많이 쓰는 KDF — PIN 맞히기를 GPU·ASIC으로도 비싸게 | RFC 9106 시험 벡터 + `argon2` 크레이트 교차 검사(시험에서만) |
| BLAKE2b | RFC 7693 | Argon2의 해시 | RFC 7693 벡터 |
| **ChaCha20-Poly1305** | RFC 8439 | 소프트웨어로 상수 시간 구현이 쉬움(시뮬레이터·기기 같은 코드) | RFC 8439 벡터 + `chacha20poly1305` 교차 검사 |
| HKDF-SHA256 | RFC 5869 | 여러 비밀을 하나의 키로 묶기 | RFC 5869 벡터 |
| (있음) SHA-256·SHA-512·HMAC·PBKDF2 | — | `bp-crypto`에 이미 있음 | — |

## 출처

- 레퍼런스 코드: 위 표의 파일들(로컬 사본)
- ST HAL: `STMicroelectronics/stm32n6xx-hal-driver` — `stm32n6xx_hal_bsec.h/.c`(퓨즈 376워드, 에포크 카운터 2개, HDPL, DHUK 잠금, 스크래치), `stm32n6xx_hal_cryp.h`(SAES 키 선택·감싸기), `stm32n6xx_hal_rtc_ex.h`(백업 레지스터 32개, 단조 카운터, 탬퍼 지우기)
- [Security features on STM32N6 MCUs (ST wiki)](https://wiki.st.com/stm32mcu/wiki/Security:Security_features_on_STM32N6_MCUs), [STM32N6 boot ROM explained](https://community.st.com/stm32-mcus-60/stm32n6-boot-rom-explained-145756), [How to start with OEMuRoT on STM32N6](https://wiki.st.com/stm32mcu/wiki/Security:How_to_start_with_OEMuRoT_on_STM32N6_MCUs), [UM3451 SESIP guidance](https://www.st.com/resource/en/user_manual/um3451-stm32n6xx-security-guidance-for-sesip-level-3-certification-stmicroelectronics.pdf), [RM0486 MCE (미러)](https://stm32.dirba.io/rm0486-stm32n6x5-x7/51-memory-cipher-engine-mce/), [VBAT on STM32N6 (community)](https://community.st.com/stm32-mcus-products-25/vbat-minimum-on-stm32n6-155713), [UM3300](https://www.st.com.cn/resource/en/user_manual/um3300-discovery-kit-with-stm32n657x0-mcu-stmicroelectronics.pdf)
- [Coldcard PINs](https://coldcard.com/docs/pins/), [Trick PINs](https://coldcard.com/docs/trick-pins), [Mk4 security model](https://blog.coinkite.com/understanding-mk4-security-model/)
- [SE050 APDU spec AN12413](https://cn.nxp.com/docs/en/application-note/AN12413.pdf), [OM-SE050ARD hardware overview AN12395](https://www.mouser.com/datasheet/2/302/AN12395-OM-SE050ARD_hardware_overview-1620473.pdf), [SE050 errata](https://cn.nxp.com/docs/en/errata/SE050_Erratasheet.pdf), [SE050 auth attempts (NXP community)](https://community.nxp.com/t5/Smart-Cards-and-Secure-Element/What-happens-when-the-maximum-number-of-allowed-authentication/td-p/2090760)
