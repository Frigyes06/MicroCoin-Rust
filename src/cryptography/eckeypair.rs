use openssl::bn::BigNumContext;
use openssl::ec::*;
use openssl::nid::Nid;
use openssl::pkey::PKey;

pub enum eckeytypes {
    Secp256K1 = 714,
    Secp384R1 = 715,
    Secp521R1 = 716,
    Sect283K1 = 729,
}

pub fn createnewkeypair() -> EcKey<openssl::pkey::Private> {
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let keytype = eckeytypes::Secp256K1 as u16;
    println!("{}", keytype);
    let key: EcKey<openssl::pkey::Private> = EcKey::generate(&group).unwrap();
    let mut ctx: BigNumContext = openssl::bn::BigNumContext::new().unwrap();

    println!("private eckey = {:?}", key.private_key());

    let bytes = key.public_key().to_bytes(&group,
        openssl::ec::PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    println!("public key = {:?}", bytes);

    let public_key: EcPoint = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
    let ec_key: EcKey<openssl::pkey::Public> = EcKey::from_public_key(&group, &public_key).unwrap();

    assert!(ec_key.check_key().is_ok());
    return key;
}

pub fn exportprivatekey(key: EcKey<openssl::pkey::Private>) -> String{
    let privatekey=&**key.private_key().to_hex_str().unwrap();          //magic, don't touch it.
    drop(key);
    return String::from(privatekey);
}