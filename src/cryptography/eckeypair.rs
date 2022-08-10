use openssl::{bn::*, ec::*, nid::Nid, pkey::PKey, sha::Sha256 };
use hex::FromHex;
use bincode::{serialize,Options};
use serde_derive::{Serialize, Deserialize};

pub enum ECKeyTypes {           //enum for keypair types
    SECP256K1 = 714,
    SECP384R1 = 715,
    SECP521R1 = 716,
    SECT283K1 = 729,
}

#[derive(Serialize, Deserialize, Debug)]
struct PubkeyStruct {
    prefix: u8,
    curvetype: u16,
    xlen: [u8;2],
    x_coord: [u8;32],
    ylen: [u8;2],
    y_coord: [u8;32],
    checksum: [u8;4],
}

#[derive(Serialize, Deserialize, Debug)]
struct ShaHashStruct {
    curvetype: u16,
    spearator1: char,
    x_coord: [u8;32],
    spearator2: char,
    y_coord: [u8;32],
}

pub fn createnewkeypair() -> EcKey<openssl::pkey::Private> {                            //function for creating new keypairs
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let keytype: u16 = ECKeyTypes::SECP256K1 as u16;                                    //key type for future implementation 
    let key: EcKey<openssl::pkey::Private> = EcKey::generate(&group).unwrap();          //generates keypair
    let mut ctx: BigNumContext = openssl::bn::BigNumContext::new().unwrap();            //BigNumContext

    let bytes: Vec<u8> = key.public_key().to_bytes(&group,
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

pub fn exportpubkey(key: &EcKey<openssl::pkey::Private>) -> String{
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx: BigNumContext = BigNumContext::new().unwrap();
    let public_key: &EcPointRef = key.public_key();
    let mut x: BigNum = BigNum::new().unwrap();
    let mut y: BigNum = BigNum::new().unwrap();
    public_key
        .affine_coordinates_gfp(group.as_ref(), &mut x, &mut y, &mut ctx)   //Extracts coordinates from public key
        .expect("extract coords");

    println!("{}, {}", x.to_hex_str().unwrap(), y.to_hex_str().unwrap());

    let mut sha256: Sha256 = Sha256::new();

    let data = ShaHashStruct{                                                           //sha hash of Curvetype + X + Y
        curvetype: ECKeyTypes::SECP256K1 as u16,
        spearator1: ':',
        x_coord: x.to_vec().try_into().unwrap(),
        spearator2: ':',
        y_coord: y.to_vec().try_into().unwrap(),
    };

    sha256.update(&bincode::options().with_fixint_encoding().serialize(&data).unwrap()[..]);
    let sha_hash = sha256.finish();

    println!("{:X?}", sha_hash);
    
    let pubkey = PubkeyStruct{
        prefix: 1,
        curvetype: ECKeyTypes::SECP256K1 as u16,
        xlen: [32,0],
        x_coord: x.to_vec().try_into().unwrap(),
        ylen: [32,0],
        y_coord: y.to_vec().try_into().unwrap(),
        checksum: sha_hash[..4].try_into().unwrap(), 
    };

    let pubkeyb = bincode::options().with_fixint_encoding().serialize(&pubkey).unwrap();

    let encoded: String = bs58::encode(pubkeyb).into_string();
    return encoded;
    //println!("{:01X?}", encoded);
    //println!("{:X?}", pubkey);
}