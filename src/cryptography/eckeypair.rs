use openssl::bn::BigNumContext;
use openssl::ec::*;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use display_bytes::{display_bytes};

pub enum eckeytypes {           //enum for keypair types
    SECP256K1 = 714,
    SECP384R1 = 715,
    SECP521R1 = 716,
    SECT283K1 = 729,
}

pub fn createnewkeypair() -> EcKey<openssl::pkey::Private> {                            //function for creating new keypairs
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let keytype = eckeytypes::SECP256K1 as u16;                                    //key type for future implementation 
    let key: EcKey<openssl::pkey::Private> = EcKey::generate(&group).unwrap();          //generates keypair
    let mut ctx: BigNumContext = openssl::bn::BigNumContext::new().unwrap();            //BigNumContext

    let bytes = key.public_key().to_bytes(&group,
        openssl::ec::PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    let public_key: EcPoint = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
    let ec_key: EcKey<openssl::pkey::Public> = EcKey::from_public_key(&group, &public_key).unwrap();

    assert!(ec_key.check_key().is_ok());
    return key;
}

pub fn exportprivatekey(key: &EcKey<openssl::pkey::Private>) -> String{
    let privatekey=&**key.private_key().to_hex_str().unwrap();          //magic, don't touch it. (I copied most from the documentations. I don't know exactly what &** does)
    drop(key);
    return String::from(privatekey);
}

pub fn exportpubkey(key: &EcKey<openssl::pkey::Private>) -> (){                 //Not finished
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx: BigNumContext = openssl::bn::BigNumContext::new().unwrap(); 
    let bytes = key.public_key().to_bytes(&group,openssl::ec::PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    println!("{}", display_bytes(&bytes));
}