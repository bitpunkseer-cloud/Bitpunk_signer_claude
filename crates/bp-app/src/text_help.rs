//! Screen help strings (M9-9, C11): one topic per kind of screen, opened
//! with `?` (F1 on a host keyboard). Each topic is a title and up to four
//! short paragraphs; the help box wraps them.

/// Topics in `help::Topic` order.
pub const TOPICS: usize = 22;

pub struct HelpStrings {
    /// "Help" (the key bar label)
    pub key_label: &'static str,
    /// Bottom line of the help box.
    pub close: &'static str,
    pub topics: [(&'static str, [&'static str; 4]); TOPICS],
}

pub static EN_HELP: HelpStrings = HelpStrings {
    key_label: "Help",
    close: "Any key closes this help.",
    topics: [
        (
            "Menus",
            [
                "A number opens its row at once; arrows move, Enter opens, Esc goes back.",
                "Fn+Q opens the QR scanner from any menu.",
                "The log under the main menu lists what happened since power on: no amounts, no addresses.",
                "Nothing is stored: power off wipes seeds and settings.",
            ],
        ),
        (
            "Making a seed",
            [
                "Roll a real die (or flip a real coin) and type each result. Never make numbers up.",
                "The board fills up to the minimum count; the checks look for bias, patterns and repeats.",
                "Enter works only once every check passes. Del undoes the last value.",
                "",
            ],
        ),
        (
            "Backing up the words",
            [
                "Write every word in order on paper or metal. The first 4 letters tell a word apart.",
                "The backup check asks for every word; one mistake and no seed is made.",
                "The screen saver hides the words after the set time. Keep cameras and people away.",
                "",
            ],
        ),
        (
            "Typing words",
            [
                "Type a word's first letters: four letters always complete it.",
                "Up/Down pick a suggestion, Enter accepts, Del deletes.",
                "A checksum error means a word is wrong: pick it and fix it.",
                "",
            ],
        ),
        (
            "Seeds",
            [
                "Loaded seeds stay in memory until power off or discard.",
                "The fingerprint (8 characters) names a seed: compare it with your wallet app.",
                "Discarding a seed asks you to type WIPE.",
                "",
            ],
        ),
        (
            "Passphrase",
            [
                "Each passphrase opens a different wallet. Case and spaces count.",
                "Compare the new fingerprint with your wallet before applying it.",
                "If you forget the passphrase, that wallet is lost.",
                "",
            ],
        ),
        (
            "Addresses and xpub",
            [
                "An xpub lets a wallet app watch this seed; it cannot spend.",
                "Pick the format your wallet asks for.",
                "Addresses come in groups of four: check every group, not just the ends.",
                "Tab switches receive and change addresses; Left/Right page.",
            ],
        ),
        (
            "QR codes",
            [
                "Hold your wallet's camera over the code. Animated codes repeat: let it see every frame.",
                "Left/Right density, Up/Down brightness, Tab speed, Space pause, I invert.",
                "S saves it as a file when a card is in.",
                "",
            ],
        ),
        (
            "Scanning",
            [
                "Show the QR to the camera, 15-30 cm away, flat and well lit.",
                "The device tells what it is from its content: PSBT, seed, wallet, address or message.",
                "Nothing from a QR is trusted until the device has checked it.",
                "",
            ],
        ),
        (
            "Checking a transaction",
            [
                "Every input and output is checked against this seed; [ OK ] marks only what was proven.",
                "Compare each recipient address group by group with the address you meant to pay.",
                "Fees show in sats, sat/vB and as a share of the outputs.",
                "Signing needs every screen; the default answer is Cancel.",
            ],
        ),
        (
            "Verifying an address",
            [
                "The device searches this seed's addresses for the one scanned.",
                "Found: it is yours, with its path. Not found: it may still be yours further on; search on.",
                "",
                "",
            ],
        ),
        (
            "Signing a message",
            [
                "Read every page: the signature covers exactly this text.",
                "The address shows which key signs.",
                "Message signing is off until it is turned on in Settings.",
                "",
            ],
        ),
        (
            "Verifying a signature",
            [
                "Valid means the address's key signed exactly this message.",
                "It does not say who owns the address: \"Is this address mine?\" checks that.",
                "",
                "",
            ],
        ),
        (
            "Multisig wallets",
            [
                "A wallet must be registered before its spends are signed.",
                "Check each cosigner's fingerprint and xpub on that cosigner's own device.",
                "The wallet code (XXXX-XXXX) names the wallet: write it on your backup and type it next session.",
                "",
            ],
        ),
        (
            "microSD",
            [
                "The card is powered only during each operation: remove it any time.",
                "Files are judged by their content, not their name. Signed files go next to the original.",
                "Formatting asks you to type FORMAT.",
                "",
            ],
        ),
        (
            "Settings",
            [
                "Left/Right change a value. Settings last until power off.",
                "The settings QR exports them; importing can only make them stricter.",
                "The fee warning and fee limit guard against fee mistakes.",
                "",
            ],
        ),
        (
            "BIP-85 child keys",
            [
                "A child key comes from this seed and an index: the same index always gives the same result.",
                "Back up the parent seed and the index. Anyone with the result can use it.",
                "",
                "",
            ],
        ),
        (
            "Private keys",
            [
                "A WIF or xprv loads a key that already exists. New seeds come only from dice or coins.",
                "A single key has four addresses and signs for them: no xpub, multisig or BIP-85.",
                "",
                "",
            ],
        ),
        (
            "Vault and PIN",
            [
                "The vault keeps seeds, wallets and settings between power-ons, encrypted.",
                "Type the first part of the PIN: check the two words, then type the rest.",
                "Ten wrong PINs erase it for good: keep your word backups.",
                "Lock screen: Esc goes on without the vault; Tab shows the tamper check words.",
            ],
        ),
        (
            "SLIP-39 shares",
            [
                "A SLIP-39 wallet is split into shares: enough of them open it.",
                "Type the shares one by one, in any order. Each is checked as it comes.",
                "New shares come from the secret: the same choices make the same shares.",
                "BIP-39 seed words are split with Seed XOR instead.",
            ],
        ),
        (
            "Seed XOR",
            [
                "A seed split into 2 to 4 parts; each part is a seed of its own.",
                "All parts are needed: their XOR is the seed. Fewer tell nothing.",
                "The Coldcard formula makes the same parts again, here or on a Coldcard.",
                "To load: type the parts one after another, in any order.",
            ],
        ),
        (
            "Metal plates",
            [
                "Tinyseed: each word's number (1-2048) in binary, 12 dots.",
                "Stackbit 1248: each digit of the number as dots worth 1, 2, 4, 8.",
                "Entering a plate: arrows move, Space sets a dot, Enter checks.",
                "The last word is not filled in: a wrong dot shows as a checksum error.",
            ],
        ),
    ],
};

pub static KO_HELP: HelpStrings = HelpStrings {
    key_label: "도움말",
    close: "아무 키나 누르면 닫힙니다.",
    topics: [
        (
            "메뉴",
            [
                "숫자를 누르면 그 줄이 바로 열립니다. 화살표로 이동, Enter로 열기, Esc로 뒤로.",
                "Fn+Q는 어느 메뉴에서나 QR 스캐너를 엽니다.",
                "주 메뉴 아래 기록은 켠 뒤 한 일입니다(금액·주소 없음).",
                "아무것도 저장하지 않습니다. 전원을 끄면 시드와 설정이 지워집니다.",
            ],
        ),
        (
            "시드 만들기",
            [
                "실제 주사위(또는 동전)를 던지고 결과를 하나씩 입력하세요. 숫자를 지어내지 마세요.",
                "기록판은 최소 횟수까지 채워지고, 검사는 치우침·패턴·반복을 찾습니다.",
                "모든 검사를 통과해야 Enter가 됩니다. Del은 마지막 값을 지웁니다.",
                "",
            ],
        ),
        (
            "단어 백업",
            [
                "모든 단어를 순서대로 종이나 금속에 적으세요. 단어는 앞 4글자로 구분됩니다.",
                "백업 검사는 모든 단어를 묻습니다. 하나라도 틀리면 시드를 만들지 않습니다.",
                "설정한 시간이 지나면 화면 보호가 단어를 가립니다. 카메라와 사람을 멀리하세요.",
                "",
            ],
        ),
        (
            "단어 입력",
            [
                "단어의 앞 글자를 입력하세요. 4글자면 항상 완성됩니다.",
                "위/아래로 후보 고르기, Enter로 확정, Del로 지우기.",
                "체크섬 오류는 단어 하나가 틀렸다는 뜻입니다. 그 단어를 골라 고치세요.",
                "",
            ],
        ),
        (
            "시드",
            [
                "불러온 시드는 전원을 끄거나 지울 때까지 메모리에 남습니다.",
                "지문(8글자)이 시드의 이름입니다. 지갑 앱의 지문과 대조하세요.",
                "시드를 지우려면 WIPE를 입력해야 합니다.",
                "",
            ],
        ),
        (
            "패스프레이즈",
            [
                "패스프레이즈마다 다른 지갑이 열립니다. 대소문자와 공백도 구분합니다.",
                "적용하기 전에 새 지문을 지갑 앱과 대조하세요.",
                "패스프레이즈를 잊으면 그 지갑은 잃습니다.",
                "",
            ],
        ),
        (
            "주소와 xpub",
            [
                "xpub은 지갑 앱이 이 시드를 지켜보게 할 뿐, 돈을 보낼 수는 없습니다.",
                "지갑이 요구하는 형식을 고르세요.",
                "주소는 4자씩 묶어 보입니다. 앞뒤만 보지 말고 모든 묶음을 확인하세요.",
                "Tab으로 받기/거스름 주소 전환, 왼쪽/오른쪽으로 페이지.",
            ],
        ),
        (
            "QR 코드",
            [
                "지갑의 카메라를 코드 위에 대세요. 움직이는 코드는 반복되니 모든 프레임을 읽게 두세요.",
                "왼쪽/오른쪽 밀도, 위/아래 밝기, Tab 속도, Space 멈춤, I 반전.",
                "카드가 있으면 S로 파일로 저장합니다.",
                "",
            ],
        ),
        (
            "스캔",
            [
                "QR을 카메라에서 15~30cm 떨어뜨려 평평하고 밝게 보여 주세요.",
                "기기가 내용을 보고 종류를 정합니다: PSBT, 시드, 지갑, 주소, 메시지.",
                "QR로 받은 것은 기기가 확인하기 전까지 믿지 않습니다.",
                "",
            ],
        ),
        (
            "거래 검토",
            [
                "모든 입력과 출력을 이 시드로 확인합니다. [ OK ]는 증명된 것에만 붙습니다.",
                "받는 사람 주소를 보내려던 주소와 묶음마다 대조하세요.",
                "수수료는 sats, sat/vB, 출력 대비 비율로 보입니다.",
                "모든 화면을 거쳐야 서명할 수 있고, 기본 선택은 취소입니다.",
            ],
        ),
        (
            "주소 확인",
            [
                "스캔한 주소를 이 시드의 주소 중에서 찾습니다.",
                "찾으면 내 주소이고 경로를 보입니다. 못 찾으면 더 뒤에 있을 수 있으니 계속 찾으세요.",
                "",
                "",
            ],
        ),
        (
            "메시지 서명",
            [
                "모든 페이지를 읽으세요. 서명은 정확히 이 글에 대한 것입니다.",
                "주소는 어떤 키로 서명하는지 보여 줍니다.",
                "메시지 서명은 설정에서 켜기 전까지 꺼져 있습니다.",
                "",
            ],
        ),
        (
            "서명 확인",
            [
                "유효하다는 것은 그 주소의 키가 정확히 이 메시지에 서명했다는 뜻입니다.",
                "주소의 주인이 누구인지는 말해 주지 않습니다. \"내 주소인가요?\"로 확인하세요.",
                "",
                "",
            ],
        ),
        (
            "멀티시그 지갑",
            [
                "지갑을 등록해야 그 지갑의 거래에 서명할 수 있습니다.",
                "공동서명자마다 지문과 xpub을 그 공동서명자의 기기에서 대조하세요.",
                "지갑 코드(XXXX-XXXX)가 지갑의 이름입니다. 백업에 적고 다음에 입력하세요.",
                "",
            ],
        ),
        (
            "microSD",
            [
                "카드는 작업하는 동안에만 켜집니다. 언제든 빼도 됩니다.",
                "파일 종류는 이름이 아니라 내용으로 판별합니다. 서명한 파일은 원본 옆에 저장합니다.",
                "포맷하려면 FORMAT을 입력해야 합니다.",
                "",
            ],
        ),
        (
            "설정",
            [
                "왼쪽/오른쪽으로 값을 바꿉니다. 설정은 전원을 끌 때까지만 유지됩니다.",
                "설정 QR로 내보낼 수 있고, 가져오기는 더 엄격하게만 바꿉니다.",
                "수수료 경고와 한도가 수수료 실수를 막습니다.",
                "",
            ],
        ),
        (
            "BIP-85 자식 키",
            [
                "자식 키는 이 시드와 번호로 만듭니다. 같은 번호는 언제나 같은 결과입니다.",
                "부모 시드와 번호를 백업하세요. 결과를 가진 사람은 누구나 쓸 수 있습니다.",
                "",
                "",
            ],
        ),
        (
            "개인키",
            [
                "WIF나 xprv로 이미 있는 키를 불러옵니다. 새 시드는 주사위나 동전으로만 만듭니다.",
                "단일 키는 주소 4개로 서명합니다. xpub·멀티시그·BIP-85는 없습니다.",
                "",
                "",
            ],
        ),
        (
            "보관함과 PIN",
            [
                "보관함은 시드·지갑·설정을 암호화해 전원을 꺼도 남깁니다.",
                "PIN 앞부분을 치고 단어 2개를 확인한 뒤 나머지를 치세요.",
                "PIN을 10번 틀리면 보관함이 영구히 지워집니다. 단어 백업이 유일한 복구 수단입니다.",
                "잠금 화면에서 Esc: 보관함 없이 사용, Tab: 탬퍼 점검 단어.",
            ],
        ),
        (
            "SLIP-39 조각",
            [
                "SLIP-39 지갑은 조각으로 나뉩니다. 정한 수만큼 모이면 열립니다.",
                "조각을 하나씩, 순서 없이 입력하세요. 조각마다 바로 검사합니다.",
                "새 조각은 비밀에서 만듭니다. 같은 선택이면 같은 조각이 나옵니다.",
                "BIP-39 시드 단어는 Seed XOR로 나누세요.",
            ],
        ),
        (
            "Seed XOR",
            [
                "시드를 2~4개 조각으로 나눕니다. 조각마다 그 자체로 시드입니다.",
                "조각이 모두 있어야 합니다. 조각의 XOR이 시드이고, 모자라면 아무것도 모릅니다.",
                "Coldcard 공식은 이 기기나 Coldcard에서 같은 조각을 다시 만듭니다.",
                "불러오기: 조각을 하나씩, 순서 없이 입력하세요.",
            ],
        ),
        (
            "금속판",
            [
                "Tinyseed: 단어 번호(1~2048)를 이진수 점 12개로.",
                "Stackbit 1248: 번호의 자리마다 1, 2, 4, 8의 점으로.",
                "옮겨 적기: 화살표로 이동, Space로 점, Enter로 검사.",
                "마지막 단어를 채워 주지 않습니다. 틀린 점은 체크섬 오류로 드러납니다.",
            ],
        ),
    ],
};
