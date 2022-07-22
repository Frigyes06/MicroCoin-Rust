use openssl::{bn::*, ec::*, nid::Nid, pkey::PKey, sha::Sha256 };
use hex::encode;
use hex::FromHex;

pub enum eckeytypes {           //enum for keypair types
    SECP256K1 = 714,
    SECP384R1 = 715,
    SECP521R1 = 716,
    SECT283K1 = 729,
}

pub fn createnewkeypair() -> EcKey<openssl::pkey::Private> {                            //function for creating new keypairs
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let keytype: u16 = eckeytypes::SECP256K1 as u16;                                    //key type for future implementation 
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

pub fn exportpubkey(key: &EcKey<openssl::pkey::Private>) -> (){
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

    let prefix: u8 = 1;
    let curvetype: u16 = eckeytypes::SECP256K1 as u16;
    let xlen = &x.to_vec().len().to_le_bytes();
    let x_coord = &x.to_vec();
    let ylen = &y.to_vec().len().to_le_bytes();
    let y_coord = &y.to_vec();

    let data: String = format!("02CA{}{}",x.to_hex_str().unwrap(), y.to_hex_str().unwrap());       //sha hash of Curvetype + X + Y
    println!("{}", data);
    sha256.update(&<[u8; 66]>::from_hex(&data).unwrap());
    let sha_hash = &sha256.finish();

    println!("{:X?}", sha_hash);
    
    let pubkey = [prefix.to_le_bytes()[0], curvetype.to_le_bytes()[0],curvetype.to_le_bytes()[1],xlen[0], xlen[1], x_coord[0],x_coord[1],x_coord[2],x_coord[3],x_coord[4],x_coord[5],x_coord[6],x_coord[7],x_coord[8],x_coord[9],x_coord[10],x_coord[11],x_coord[12],x_coord[13],x_coord[14],x_coord[15],x_coord[16],x_coord[17],x_coord[18],x_coord[19],x_coord[20],x_coord[21],x_coord[22],x_coord[23],x_coord[24],x_coord[25],x_coord[26],x_coord[27],x_coord[28],x_coord[29],x_coord[30],x_coord[31],ylen[0],ylen[1], y_coord[0],y_coord[1],y_coord[2],y_coord[3],y_coord[4],y_coord[5],y_coord[6],y_coord[7],y_coord[8],y_coord[9],y_coord[10],y_coord[11],y_coord[12],y_coord[13],y_coord[14],y_coord[15],y_coord[16],y_coord[17],y_coord[18],y_coord[19],y_coord[20],y_coord[21],y_coord[22],y_coord[23],y_coord[24],y_coord[25],y_coord[26],y_coord[27],y_coord[28],y_coord[29],y_coord[30],y_coord[31],sha_hash[0],sha_hash[1],sha_hash[2],sha_hash[3]];
    //TODO: rewrite the pubkey constructor in a more professional way ^^^^

    let encoded: String = bs58::encode(pubkey).into_string();       //TODO: Base58 encoding. Using bignum works for now, but it should be replaced with something more elegant
    println!("{:01X?}", encoded);
    println!("{:X?}", pubkey);
}