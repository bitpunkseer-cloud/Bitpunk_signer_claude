//! Wallet and cosigner formats: Coldcard setup file, Sparrow's descriptor
//! file, Specter/Krux JSON, UR crypto-output / crypto-account /
//! crypto-hdkey, key-expression text and the Coldcard xpub JSON. Every
//! format must give the same wallet record as the plain descriptor.

use bp_bitcoin::bip32::{KeyVersion, Xpriv, XKEY_LEN};
use bp_bitcoin::multisig::descriptor::{self, Error as DError, Form};
use bp_bitcoin::multisig::formats::{
    self, parse_bpw, parse_cosigner, parse_cosigner_ur, parse_output_ur, parse_wallet, write_bpw, Error,
    Format, BPW_HEADER,
};
use bp_bitcoin::multisig::{Cosigner, MsScript, Wallet};
use bp_bitcoin::Network;
use bp_qr::ur::cbor::Writer;

fn master(i: u8) -> Xpriv {
    Xpriv::master(&[i; 32]).unwrap()
}

fn cosigner(i: u8, script: MsScript, net: Network) -> Cosigner {
    let m = master(i);
    let path = script.account_path(net, 0);
    Cosigner {
        fingerprint: m.fingerprint(),
        origin: path,
        xpub: m.derive_path(&path).unwrap().to_xpub(),
        version: KeyVersion::X,
    }
}

fn wallet(script: MsScript, m: u8, n: u8, net: Network) -> Wallet {
    let keys: Vec<Cosigner> = (1..=n).map(|i| cosigner(i, script, net)).collect();
    Wallet::new(net != Network::Mainnet, script, m, &keys).unwrap()
}

fn xkey(c: &Cosigner, v: KeyVersion, net: Network) -> String {
    let mut x = [0u8; XKEY_LEN];
    let n = c.xpub.encode(v.public(net), &mut x);
    String::from_utf8(x[..n].to_vec()).unwrap()
}

fn fp_hex(fp: &[u8; 4], upper: bool) -> String {
    let s: String = fp.iter().map(|b| format!("{b:02x}")).collect();
    if upper {
        s.to_uppercase()
    } else {
        s
    }
}

fn desc(w: &Wallet, form: Form) -> String {
    let mut o = [0u8; descriptor::MAX_DESCRIPTOR];
    let n = descriptor::write(w, form, &mut o).unwrap();
    String::from_utf8(o[..n].to_vec()).unwrap()
}

fn coldcard_file(w: &Wallet, net: Network, v: KeyVersion, format: &str) -> String {
    let mut s = String::from("# Coldcard Multisig setup file (exported from Sparrow)\n#\n");
    s += &format!("Name: Family vault\nPolicy: {} of {}\n", w.m, w.n());
    s += &format!("Derivation: {}\nFormat: {format}\n\n", w.keys()[0].origin);
    for k in w.keys() {
        s += &format!("{}: {}\n", fp_hex(&k.fingerprint, true), xkey(k, v, net));
    }
    s
}

#[test]
fn coldcard_setup_file() {
    for (script, fmt, v, net) in [
        (MsScript::Wsh, "P2WSH", KeyVersion::X, Network::Mainnet),
        (MsScript::Wsh, "p2wsh", KeyVersion::MultiZ, Network::Mainnet),
        (
            MsScript::ShWsh,
            "P2SH-P2WSH",
            KeyVersion::MultiY,
            Network::Mainnet,
        ),
        (MsScript::ShWsh, "P2WSH-P2SH", KeyVersion::X, Network::Testnet),
        (MsScript::Wsh, "P2WSH", KeyVersion::MultiZ, Network::Signet),
    ] {
        let w = wallet(script, 2, 3, net);
        let text = coldcard_file(&w, net, v, fmt);
        let got = parse_wallet(text.as_bytes()).unwrap();
        assert_eq!(got.format, Format::Coldcard);
        assert_eq!(got.wallet.id(), w.id(), "{text}");
        assert_eq!(got.wallet.name(), "Family vault");
        assert!(got.wallet.keys().iter().all(|k| k.version == v));
    }
}

#[test]
fn coldcard_per_key_derivation_and_errors() {
    let net = Network::Mainnet;
    let mut keys: Vec<Cosigner> = (1..=3).map(|i| cosigner(i, MsScript::Wsh, net)).collect();
    // the third cosigner on account 1'
    let m3 = master(3);
    let p3 = MsScript::Wsh.account_path(net, 1);
    keys[2] = Cosigner {
        fingerprint: m3.fingerprint(),
        origin: p3,
        xpub: m3.derive_path(&p3).unwrap().to_xpub(),
        version: KeyVersion::X,
    };
    let w = Wallet::new(false, MsScript::Wsh, 2, &keys).unwrap();
    let mut text = String::from("Name: mixed accounts\nPolicy: 2 of 3\nFormat: P2WSH\n");
    for k in &keys {
        text += &format!(
            "Derivation: {}\n{}: {}\n",
            k.origin,
            fp_hex(&k.fingerprint, false),
            xkey(k, KeyVersion::X, net)
        );
    }
    assert_eq!(parse_wallet(text.as_bytes()).unwrap().wallet.id(), w.id());

    let good = coldcard_file(&w, net, KeyVersion::X, "P2WSH");
    let err = |t: &str| parse_wallet(t.as_bytes()).unwrap_err();
    assert_eq!(
        err(&good.replace("Format: P2WSH", "Format: P2SH")),
        Error::ScriptFormat
    );
    assert_eq!(err(&good.replace("Format: P2WSH\n", "")), Error::ScriptFormat);
    assert_eq!(err(&good.replace("2 of 3", "2 of 4")), Error::KeyCount);
    assert_eq!(err(&good.replace("2 of 3", "4 of 3")), Error::Policy);
    assert_eq!(err(&good.replace("2 of 3", "two of three")), Error::Policy);
    let no_deriv: String = good
        .lines()
        .filter(|l| !l.starts_with("Derivation"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(err(&no_deriv), Error::Derivation);
    // a broken key, a private key, mixed networks
    let first_key = xkey(&w.keys()[0], KeyVersion::X, net);
    assert_eq!(err(&good.replace(&first_key, &first_key[..100])), Error::Key);
    let prv = {
        let a = master(1).derive_path(&w.keys()[0].origin).unwrap();
        let mut o = [0u8; XKEY_LEN];
        let n = a.encode(KeyVersion::X.private(net), &mut o);
        String::from_utf8(o[..n].to_vec()).unwrap()
    };
    assert_eq!(err(&good.replace(&first_key, &prv)), Error::PrivateKey);
    let tkey = xkey(&w.keys()[0], KeyVersion::X, Network::Testnet);
    assert_eq!(err(&good.replace(&first_key, &tkey)), Error::MixedNetwork);
    // unknown fields are ignored, as on Coldcard
    let extra = good.replace("Name:", "Comments: hello\nName:");
    assert_eq!(
        parse_wallet(extra.as_bytes()).unwrap().wallet.id(),
        parse_wallet(good.as_bytes()).unwrap().wallet.id()
    );
}

#[test]
fn descriptor_files() {
    let net = Network::Testnet;
    let w = wallet(MsScript::Wsh, 2, 3, net);
    // Sparrow's "Output Descriptor" export: three lines with comments
    let sparrow = format!(
        "# Receive and change descriptor (BIP389):\n{}\n\n# Receive descriptor (Bitcoin Core: importdescriptors):\n{}\n\n# Change descriptor (Bitcoin Core: importdescriptors):\n{}\n",
        desc(&w, Form::Multipath),
        desc(&w, Form::Branch(0)),
        desc(&w, Form::Branch(1))
    );
    let got = parse_wallet(sparrow.as_bytes()).unwrap();
    assert_eq!((got.format, got.wallet), (Format::Descriptor, w));
    // receive + change pair
    let pair = format!("{}\n{}", desc(&w, Form::Branch(0)), desc(&w, Form::Branch(1)));
    assert_eq!(parse_wallet(pair.as_bytes()).unwrap().wallet.id(), w.id());
    // change only
    assert_eq!(
        parse_wallet(desc(&w, Form::Branch(1)).as_bytes()).unwrap_err(),
        Error::ChangeOnly
    );
    // two different wallets
    let other = wallet(MsScript::Wsh, 1, 3, net);
    let mixed = format!("{}\n{}", desc(&w, Form::Branch(0)), desc(&other, Form::Branch(1)));
    assert_eq!(parse_wallet(mixed.as_bytes()).unwrap_err(), Error::LinesDiffer);
    // descriptor errors come through
    let multi = desc(&w, Form::Multipath).replace("sortedmulti", "multi");
    let multi = multi.split('#').next().unwrap();
    assert_eq!(
        parse_wallet(multi.as_bytes()).unwrap_err(),
        Error::Descriptor(DError::Unsorted)
    );
    assert_eq!(parse_wallet(b"hello world").unwrap_err(), Error::Unknown);
}

#[test]
fn json_wallets() {
    let net = Network::Mainnet;
    let w = wallet(MsScript::ShWsh, 2, 3, net);
    let d = desc(&w, Form::Branch(0));
    let specter = format!(
        "{{\"label\": \"Vault \\\"A\\\"\", \"blockheight\": 812345, \"descriptor\": \"{}\", \"devices\": [{{\"type\": \"specter\", \"label\": \"x\"}}]}}",
        d.replace('/', "\\/")
    );
    let got = parse_wallet(specter.as_bytes()).unwrap();
    assert_eq!(got.format, Format::Json);
    assert_eq!(got.wallet.id(), w.id());
    assert_eq!(got.wallet.name(), "Vault \"A\"");
    let krux = format!(
        "{{\"name\":\"k\",\"descriptor\":\"{}\"}}",
        desc(&w, Form::Multipath)
    );
    assert_eq!(parse_wallet(krux.as_bytes()).unwrap().wallet.name(), "k");
    assert_eq!(parse_wallet(b"{\"label\": \"x\"}").unwrap_err(), Error::Unknown);
    // an escape we do not resolve
    let bad = format!("{{\"descriptor\": \"{}\\u0041\"}}", d);
    assert_eq!(parse_wallet(bad.as_bytes()).unwrap_err(), Error::Unknown);
}

/// `#6.303({3: key, 4: chain, [5: coininfo], 6: origin, [7: children], 8: parent})`
fn write_hdkey(w: &mut Writer, c: &Cosigner, test: bool, children: Option<u64>, tagged: bool) {
    if tagged {
        w.tag(303).unwrap();
    }
    let mut n = 4;
    if test {
        n += 1;
    }
    if children.is_some() {
        n += 1;
    }
    w.map(n).unwrap();
    w.uint(3).unwrap();
    w.bytes(&c.xpub.key.serialize()).unwrap();
    w.uint(4).unwrap();
    w.bytes(&c.xpub.chain_code).unwrap();
    if test {
        w.uint(5).unwrap();
        w.tag(305).unwrap();
        w.map(1).unwrap();
        w.uint(2).unwrap();
        w.uint(1).unwrap();
    }
    w.uint(6).unwrap();
    w.tag(304).unwrap();
    w.map(3).unwrap();
    w.uint(1).unwrap();
    let steps = c.origin.steps();
    w.array(steps.len() as u64 * 2).unwrap();
    for &s in steps {
        w.uint((s & 0x7fff_ffff) as u64).unwrap();
        w.bool(s & 0x8000_0000 != 0).unwrap();
    }
    w.uint(2).unwrap();
    w.uint(u32::from_be_bytes(c.fingerprint) as u64).unwrap();
    w.uint(3).unwrap();
    w.uint(steps.len() as u64).unwrap();
    if let Some(b) = children {
        w.uint(7).unwrap();
        w.tag(304).unwrap();
        w.map(1).unwrap();
        w.uint(1).unwrap();
        w.array(4).unwrap();
        w.uint(b).unwrap();
        w.bool(false).unwrap();
        w.array(0).unwrap();
        w.bool(false).unwrap();
    }
    w.uint(8).unwrap();
    w.uint(u32::from_be_bytes(c.xpub.parent_fingerprint) as u64)
        .unwrap();
}

fn output_ur(w: &Wallet, sorted: bool, children: Option<u64>) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut wr = Writer::new(&mut buf);
    if w.script == MsScript::ShWsh {
        wr.tag(400).unwrap();
    }
    wr.tag(401).unwrap();
    wr.tag(if sorted { 407 } else { 406 }).unwrap();
    wr.map(2).unwrap();
    wr.uint(1).unwrap();
    wr.uint(w.m as u64).unwrap();
    wr.uint(2).unwrap();
    wr.array(w.n() as u64).unwrap();
    for k in w.keys() {
        write_hdkey(&mut wr, k, w.test, children, true);
    }
    let n = wr.len();
    buf.truncate(n);
    buf
}

#[test]
fn ur_crypto_output() {
    for (script, net) in [
        (MsScript::Wsh, Network::Mainnet),
        (MsScript::ShWsh, Network::Testnet),
    ] {
        let w = wallet(script, 2, 3, net);
        for children in [None, Some(0)] {
            let got = parse_output_ur(&output_ur(&w, true, children)).unwrap();
            assert_eq!(got.format, Format::UrOutput);
            assert_eq!(got.wallet, w);
        }
        assert_eq!(
            parse_output_ur(&output_ur(&w, true, Some(1))).unwrap_err(),
            Error::ChangeOnly
        );
        assert_eq!(
            parse_output_ur(&output_ur(&w, false, Some(0))).unwrap_err(),
            Error::Descriptor(DError::Unsorted)
        );
        let mut trailing = output_ur(&w, true, None);
        trailing.push(0);
        assert_eq!(parse_output_ur(&trailing).unwrap_err(), Error::Cbor);
        let cut = output_ur(&w, true, None);
        assert_eq!(parse_output_ur(&cut[..cut.len() - 3]).unwrap_err(), Error::Cbor);
    }
}

#[test]
fn cosigner_text_and_json() {
    let net = Network::Mainnet;
    let c = cosigner(5, MsScript::Wsh, net);
    let fp = fp_hex(&c.fingerprint, false);
    for (text, v) in [
        (
            format!("[{fp}/48h/0h/0h/2h]{}", xkey(&c, KeyVersion::X, net)),
            KeyVersion::X,
        ),
        (
            format!("[{fp}/48'/0'/0'/2']{}", xkey(&c, KeyVersion::MultiZ, net)),
            KeyVersion::MultiZ,
        ),
        (
            format!(
                "[{}/48h/0h/0h/2h]{}/<0;1>/*\n",
                fp.to_uppercase(),
                xkey(&c, KeyVersion::X, net)
            ),
            KeyVersion::X,
        ),
    ] {
        let (got, test) = parse_cosigner(text.as_bytes(), MsScript::Wsh).unwrap();
        assert!(!test);
        assert_eq!(
            (got.fingerprint, got.origin, got.xpub, got.version),
            (c.fingerprint, c.origin, c.xpub, v)
        );
    }
    assert_eq!(
        parse_cosigner(xkey(&c, KeyVersion::X, net).as_bytes(), MsScript::Wsh).unwrap_err(),
        Error::MissingOrigin
    );
    assert_eq!(
        parse_cosigner(b"[zz]xpub", MsScript::Wsh).unwrap_err(),
        Error::Key
    );

    // Coldcard "Export XPUB" multisig JSON
    let sh = cosigner(5, MsScript::ShWsh, net);
    let json = format!(
        "{{\"p2sh_deriv\": \"m/45'\", \"p2sh\": \"{}\", \"p2sh_p2wsh_deriv\": \"m/48'/0'/0'/1'\", \"p2sh_p2wsh\": \"{}\", \"p2wsh_deriv\": \"m/48'/0'/0'/2'\", \"p2wsh\": \"{}\", \"xfp\": \"{}\", \"account\": 0}}",
        xkey(&c, KeyVersion::X, net),
        xkey(&sh, KeyVersion::MultiY, net),
        xkey(&c, KeyVersion::MultiZ, net),
        fp.to_uppercase()
    );
    let (a, _) = parse_cosigner(json.as_bytes(), MsScript::Wsh).unwrap();
    assert_eq!(
        (a.origin, a.xpub, a.version),
        (c.origin, c.xpub, KeyVersion::MultiZ)
    );
    let (b, _) = parse_cosigner(json.as_bytes(), MsScript::ShWsh).unwrap();
    assert_eq!(
        (b.origin, b.xpub, b.version),
        (sh.origin, sh.xpub, KeyVersion::MultiY)
    );
}

#[test]
fn cosigner_ur() {
    let net = Network::Testnet;
    let wsh = cosigner(7, MsScript::Wsh, net);
    let shwsh = cosigner(7, MsScript::ShWsh, net);
    // crypto-account as SeedSigner writes it: one output per script type
    let mut buf = vec![0u8; 4096];
    let mut w = Writer::new(&mut buf);
    w.map(2).unwrap();
    w.uint(1).unwrap();
    w.uint(u32::from_be_bytes(wsh.fingerprint) as u64).unwrap();
    w.uint(2).unwrap();
    w.array(3).unwrap();
    w.tag(404).unwrap(); // wpkh: skipped
    write_hdkey(&mut w, &wsh, true, None, true);
    w.tag(400).unwrap();
    w.tag(401).unwrap();
    write_hdkey(&mut w, &shwsh, true, None, true);
    w.tag(401).unwrap();
    write_hdkey(&mut w, &wsh, true, None, true);
    let n = w.len();
    let acct = &buf[..n];
    let (a, test) = parse_cosigner_ur("crypto-account", acct, MsScript::Wsh).unwrap();
    assert!(test);
    assert_eq!(
        (a.fingerprint, a.origin, a.xpub),
        (wsh.fingerprint, wsh.origin, wsh.xpub)
    );
    let (b, _) = parse_cosigner_ur("crypto-account", acct, MsScript::ShWsh).unwrap();
    assert_eq!(b.xpub, shwsh.xpub);

    // crypto-hdkey: the map without its tag
    let mut hb = vec![0u8; 1024];
    let mut h = Writer::new(&mut hb);
    write_hdkey(&mut h, &wsh, true, None, false);
    let hn = h.len();
    let (k, _) = parse_cosigner_ur("crypto-hdkey", &hb[..hn], MsScript::Wsh).unwrap();
    assert_eq!(k.xpub, wsh.xpub);
    assert_eq!(
        parse_cosigner_ur("crypto-psbt", &hb[..hn], MsScript::Wsh).unwrap_err(),
        Error::Unknown
    );
}

#[test]
fn private_key_in_ur_is_refused() {
    let c = cosigner(1, MsScript::Wsh, Network::Mainnet);
    let mut hb = vec![0u8; 1024];
    let mut h = Writer::new(&mut hb);
    h.map(2).unwrap();
    h.uint(2).unwrap();
    h.bool(true).unwrap();
    h.uint(3).unwrap();
    let mut k = [0u8; 33];
    k[1..].copy_from_slice(&[7u8; 32]);
    h.bytes(&k).unwrap();
    let n = h.len();
    assert_eq!(
        parse_cosigner_ur("crypto-hdkey", &hb[..n], MsScript::Wsh).unwrap_err(),
        formats::Error::PrivateKey
    );
    let _ = c;
}

/// What Bitpunk exports for a coordinator reads back through every cosigner
/// parser to the same key.
#[test]
fn cosigner_exports_round_trip() {
    use bp_bitcoin::multisig::formats::{write_coldcard_xpub_json, write_key_text};
    use bp_bitcoin::urtypes::{crypto_account_tags, AccountKey, TAG_SH, TAG_WSH};
    for net in [Network::Mainnet, Network::Testnet] {
        let test = net != Network::Mainnet;
        let wsh = cosigner(3, MsScript::Wsh, net);
        let sh = cosigner(3, MsScript::ShWsh, net);
        let mut buf = [0u8; 1024];
        // key text
        let n = write_key_text(&wsh, test, &mut buf).unwrap();
        let (k, t) = parse_cosigner(&buf[..n], MsScript::Wsh).unwrap();
        assert_eq!(
            (k.fingerprint, k.origin, k.xpub, t),
            (wsh.fingerprint, wsh.origin, wsh.xpub, test)
        );
        // Coldcard JSON (both scripts)
        let n = write_coldcard_xpub_json(&wsh, &sh, 0, test, &mut buf).unwrap();
        let (a, _) = parse_cosigner(&buf[..n], MsScript::Wsh).unwrap();
        let (b, _) = parse_cosigner(&buf[..n], MsScript::ShWsh).unwrap();
        assert_eq!(
            (a.xpub, a.origin, a.version),
            (wsh.xpub, wsh.origin, KeyVersion::MultiZ)
        );
        assert_eq!(
            (b.xpub, b.origin, b.version),
            (sh.xpub, sh.origin, KeyVersion::MultiY)
        );
        // UR crypto-account
        for (c, script, tags) in [
            (&wsh, MsScript::Wsh, &[TAG_WSH][..]),
            (&sh, MsScript::ShWsh, &[TAG_SH, TAG_WSH][..]),
        ] {
            let key = AccountKey {
                xpub: &c.xpub,
                master_fingerprint: c.fingerprint,
                path: &c.origin,
                script: bp_bitcoin::address::ScriptType::NativeSegwit,
                network: net,
            };
            let n = crypto_account_tags(&key, tags, &mut buf).unwrap();
            let (k, t) = parse_cosigner_ur("crypto-account", &buf[..n], script).unwrap();
            assert_eq!(
                (k.fingerprint, k.origin, k.xpub, t),
                (c.fingerprint, c.origin, c.xpub, test)
            );
            // the other script type is not in this account
            let other = if script == MsScript::Wsh {
                MsScript::ShWsh
            } else {
                MsScript::Wsh
            };
            assert_eq!(
                parse_cosigner_ur("crypto-account", &buf[..n], other).unwrap_err(),
                Error::ScriptFormat
            );
        }
    }
}

/// The Bitpunk wallet file: round trip, and every malformed field refused.
#[test]
fn bpw_files() {
    use bp_bitcoin::multisig::register::{Code, CodeKey};
    let net = Network::Testnet;
    let w = wallet(MsScript::Wsh, 2, 3, net);
    let ck = CodeKey::new(&master(0));
    let tag = ck.tag(&w);
    let code = ck.code(&w).display();
    let code = std::str::from_utf8(&code).unwrap();
    let mut out = [0u8; 8192];
    let n = write_bpw(&w, "Family vault", code, &tag, &mut out).unwrap();
    let text = std::str::from_utf8(&out[..n]).unwrap().to_string();
    assert!(text.starts_with(BPW_HEADER));
    let b = parse_bpw(text.as_bytes()).unwrap();
    assert_eq!((b.name, b.code, b.tag), ("Family vault", code, tag));
    // the descriptor reads back as the same wallet
    let back = parse_wallet(b.descriptor).unwrap().wallet;
    assert_eq!(back.id(), w.id());
    assert_eq!(ck.tag(&back), tag);
    assert_eq!(Code::from_tag(&b.tag).display(), ck.code(&w).display());
    // CRLF and a byte order mark are fine
    let crlf = format!("\u{feff}{}", text.replace('\n', "\r\n"));
    assert_eq!(parse_bpw(crlf.as_bytes()).unwrap().tag, tag);
    // malformed files
    let lines: Vec<&str> = text.lines().collect();
    let bad = [
        text.replace(BPW_HEADER, "# Bitpunk wallet v2"),
        text.replace("name: ", "nom: "),
        text.replace(&lines[3][5..9], "zzzz"),
        text.replace(lines[3], &lines[3][..lines[3].len() - 2]),
        lines[..4].join("\n"),
        format!("{text}extra line\n"),
        text.replace("Family vault", "Fam\u{1}ly"),
        text.replace(lines[4], "pkh(xpub)"),
    ];
    for t in bad {
        assert!(parse_bpw(t.as_bytes()).is_err(), "{t}");
    }
    // a small buffer
    assert!(write_bpw(&w, "x", code, &tag, &mut out[..100]).is_none());
}
