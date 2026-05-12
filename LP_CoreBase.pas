unit LP_CoreBase;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Hash,
  System.NetEncoding,
  System.JSON,
  System.IOUtils;

const
  LP_BASE_URL    = 'https://appgateway.leapmotor-international.de';
  LP_SERVER_HOST = 'appgateway.leapmotor-international.de';
  LP_APP_VERSION = '1.12.3';
  LP_SOURCE      = 'leapmotor';
  LP_CHANNEL     = '1';
  LP_LANGUAGE    = 'en-GB';
  LP_DEVICE_TYPE = '1';
  LP_P12_ENC_ALG = '1';
  NID_3DES = 131;
  NID_RC2  = 166;

  type
  TLPLogEvent = reference to procedure(const AMsg: string);
var
  LPLogProc : TLPLogEvent;

type
  ELPConnectError = class(Exception);
  ELPAuthError    = class(ELPConnectError);

  TLPConnectBase = class
  private
    FAccCertFile     : string;
    FAccKeyFile      : string;

    procedure DeleteTempCerts;
    procedure ParseLoginResponse(const AJSON: string);


  protected
    FBaseURL         : string;
    FDeviceID        : string;
    FLanguage        : string;
    FUserID          : string;
    FToken           : string;
    FSignIkm         : string;
    FSignSalt        : string;
    FSignInfo        : string;
    FRefreshToken    : string;
    FAccP12Base64    : string;
    FAccUid          : string;
    FAppCertFile     : string;
    FAppKeyFile      : string;
    FCurrentCertFile : string;
    FCurrentKeyFile  : string;

    { Override platform }
    function  LibLoad(const AName: string): Pointer; virtual; abstract;
    function  LibSym(ALib: Pointer; const AName: string): Pointer; virtual; abstract;
    procedure LibFree(ALib: Pointer); virtual; abstract;
    function  PostForm(const APath    : string;
                       const AHeaders : TStrings;
                       const ABody    : string): string; virtual; abstract;

    { Usati da PostForm nelle sottoclassi }
    function  PEMtoPFX(const ACertFile, AKeyFile: string;
                        const APassword: AnsiString): TBytes; virtual;
    procedure SetClientCert(const ACert, AKey: string);
    procedure LoadAccountCertFromP12; virtual;
    function DeriveP12Password(const AAccountID, AUid: string): string;
  private
    function  SM4EncryptBlock(const ABlock: TBytes): TBytes;
    function  P12MemoryEncode(const AData: TBytes): TBytes;
    //function  DeriveP12Password(const AAccountID, AUid: string): string;
    function  DeriveSignKey: TBytes;
    function  HMACSHA256Hex(const AKey: TBytes; const AData: string): string;
    function  SHA256Hex(const AData: string): string;
    function  GenerateNonce: string;
    function  TimestampMs: string;
    function  BuildLoginHeaders(const AUsername, APassword: string): TStringList;
    function  BuildSignedHeaders(const AVin: string = '';
                                 const AExtraFields: TStringList = nil): TStringList;
    function  AuthHeaders: TStringList;

  public
    constructor Create(const AAppCertFile, AAppKeyFile : string;
                       const ABaseURL                  : string = LP_BASE_URL;
                       const ALanguage                 : string = LP_LANGUAGE);
    destructor Destroy; override;

    procedure Login(const AUsername, APassword: string);
    function  GetVehicleList: TJSONObject;
    function  GetVehicleStatus(const AVIN, ACarType: string): TJSONObject;
    function  GetVehicleRawStatus(const AVIN, ACarType: string): TJSONObject;
    function  GetMileageEnergyDetail(const AVIN: string): TJSONObject;
    // utility
    function XorObfuscate(const AData: TBytes): TBytes;
    procedure SaveCredentials(const AEmail, APassword: string;
                                          const AFilePath: string);
    procedure LoadCredentials(out AEmail, APassword: string;
                                          const AFilePath: string);

    property UserID   : string read FUserID;
    property Token    : string read FToken;
    property DeviceID : string read FDeviceID;
  end;

function URLEncodeValue(const S: string): string;

implementation

uses
  System.DateUtils,
  System.Math;

const
  SM4_SBOX: array[0..255] of Byte = (
    $D6,$90,$E9,$FE,$CC,$E1,$3D,$B7,$16,$B6,$14,$C2,$28,$FB,$2C,$05,
    $2B,$67,$9A,$76,$2A,$BE,$04,$C3,$AA,$44,$13,$26,$49,$86,$06,$99,
    $9C,$42,$50,$F4,$91,$EF,$98,$7A,$33,$54,$0B,$43,$ED,$CF,$AC,$62,
    $E4,$B3,$1C,$A9,$C9,$08,$E8,$95,$80,$DF,$94,$FA,$75,$8F,$3F,$A6,
    $47,$07,$A7,$FC,$F3,$73,$17,$BA,$83,$59,$3C,$19,$E6,$85,$4F,$A8,
    $68,$6B,$81,$B2,$71,$64,$DA,$8B,$F8,$EB,$0F,$4B,$70,$56,$9D,$35,
    $1E,$24,$0E,$5E,$63,$58,$D1,$A2,$25,$22,$7C,$3B,$01,$21,$78,$87,
    $D4,$00,$46,$57,$9F,$D3,$27,$52,$4C,$36,$02,$E7,$A0,$C4,$C8,$9E,
    $EA,$BF,$8A,$D2,$40,$C7,$38,$B5,$A3,$F7,$F2,$CE,$F9,$61,$15,$A1,
    $E0,$AE,$5D,$A4,$9B,$34,$1A,$55,$AD,$93,$32,$30,$F5,$8C,$B1,$E3,
    $1D,$F6,$E2,$2E,$82,$66,$CA,$60,$C0,$29,$23,$AB,$0D,$53,$4E,$6F,
    $D5,$DB,$37,$45,$DE,$FD,$8E,$2F,$03,$FF,$6A,$72,$6D,$6C,$5B,$51,
    $8D,$1B,$AF,$92,$BB,$DD,$BC,$7F,$11,$D9,$5C,$41,$1F,$10,$5A,$D8,
    $0A,$C1,$31,$88,$A5,$CD,$7B,$BD,$2D,$74,$D0,$12,$B8,$E5,$B4,$B0,
    $89,$69,$97,$4A,$0C,$96,$77,$7E,$65,$B9,$F1,$09,$C5,$6E,$C6,$84,
    $18,$F0,$7D,$EC,$3A,$DC,$4D,$20,$79,$EE,$5F,$3E,$D7,$CB,$39,$48
  );
  SM4_ROUND_KEYS: array[0..31] of Cardinal = (
    $818FA553,$EBA3318D,$5FC3C93A,$BD1DADD9,
    $BB61CAB9,$000FD7EA,$DC6E0166,$DA937279,
    $607EE786,$B548754C,$107330E4,$EA17C186,
    $0F56F74B,$B21E443C,$E1210FE2,$009995C8,
    $E7529A48,$6EF474F6,$2AB06DF6,$43B11BE8,
    $359D4A14,$C29E2CDE,$30CF6A3E,$79D1C806,
    $7C502387,$AAAB9BC6,$F0FE744B,$1CAFC872,
    $95A9D075,$88070D58,$22800475,$8391938B
  );

function URLEncodeValue(const S: string): string;
const
  SafeChars = ['A'..'Z', 'a'..'z', '0'..'9', '-', '_', '.', '~'];
var
  B : TBytes;
  J : Integer;
begin
  Result := '';
  B := TEncoding.UTF8.GetBytes(S);
  for J := 0 to Length(B) - 1 do
    if CharInSet(Char(B[J]), SafeChars) then
      Result := Result + Char(B[J])
    else
      Result := Result + '%' + IntToHex(B[J], 2);
end;

{ TLPConnectBase }

constructor TLPConnectBase.Create(const AAppCertFile, AAppKeyFile : string;
                                   const ABaseURL                  : string;
                                   const ALanguage                 : string);
begin
  inherited Create;
  Randomize;
  FAppCertFile     := AAppCertFile;
  FAppKeyFile      := AAppKeyFile;
  FCurrentCertFile := AAppCertFile;
  FCurrentKeyFile  := AAppKeyFile;
  FBaseURL         := ABaseURL;
  FLanguage        := ALanguage;
  FDeviceID := LowerCase(
    THashMD5.GetHashString(DateTimeToStr(Now) + IntToStr(Random(999999))));
end;

destructor TLPConnectBase.Destroy;
begin
  DeleteTempCerts;
  inherited;
end;

procedure TLPConnectBase.SetClientCert(const ACert, AKey: string);
begin
  FCurrentCertFile := ACert;
  FCurrentKeyFile  := AKey;
end;

procedure TLPConnectBase.DeleteTempCerts;
begin
  if FAccCertFile <> '' then begin TFile.Delete(FAccCertFile); FAccCertFile := ''; end;
  if FAccKeyFile  <> '' then begin TFile.Delete(FAccKeyFile);  FAccKeyFile  := ''; end;
end;

function TLPConnectBase.GenerateNonce: string;
begin
  Result := IntToStr(100000 + Random(9900000));
end;

function TLPConnectBase.TimestampMs: string;
begin
  Result := IntToStr(
    DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now), False) * 1000);
end;

function TLPConnectBase.SHA256Hex(const AData: string): string;
begin
  Result := LowerCase(THashSHA2.GetHashString(AData, SHA256));
end;

function TLPConnectBase.HMACSHA256Hex(const AKey: TBytes; const AData: string): string;
var
  D : TBytes;
  I : Integer;
begin
  D := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), AKey, SHA256);
  Result := '';
  for I := 0 to Length(D) - 1 do
    Result := Result + IntToHex(D[I], 2);
  Result := LowerCase(Result);
end;

function TLPConnectBase.SM4EncryptBlock(const ABlock: TBytes): TBytes;
var
  X0, X1, X2, X3, T, B, NewX, RK : Cardinal;
begin
  X0 := (Cardinal(ABlock[0])  shl 24) or (Cardinal(ABlock[1])  shl 16)
     or (Cardinal(ABlock[2])  shl  8) or  Cardinal(ABlock[3]);
  X1 := (Cardinal(ABlock[4])  shl 24) or (Cardinal(ABlock[5])  shl 16)
     or (Cardinal(ABlock[6])  shl  8) or  Cardinal(ABlock[7]);
  X2 := (Cardinal(ABlock[8])  shl 24) or (Cardinal(ABlock[9])  shl 16)
     or (Cardinal(ABlock[10]) shl  8) or  Cardinal(ABlock[11]);
  X3 := (Cardinal(ABlock[12]) shl 24) or (Cardinal(ABlock[13]) shl 16)
     or (Cardinal(ABlock[14]) shl  8) or  Cardinal(ABlock[15]);
  for RK in SM4_ROUND_KEYS do
  begin
    T := X1 xor X2 xor X3 xor RK;
    B := (Cardinal(SM4_SBOX[(T shr 24) and $FF]) shl 24)
      or (Cardinal(SM4_SBOX[(T shr 16) and $FF]) shl 16)
      or (Cardinal(SM4_SBOX[(T shr  8) and $FF]) shl  8)
      or  Cardinal(SM4_SBOX[ T         and $FF]);
    NewX := X0 xor B xor ((B shl 2) or (B shr 30)) xor ((B shl 10) or (B shr 22))
               xor ((B shl 18) or (B shr 14)) xor ((B shl 24) or (B shr 8));
    X0 := X1; X1 := X2; X2 := X3; X3 := NewX;
  end;
  SetLength(Result, 16);
  Result[0]  := (X3 shr 24) and $FF;  Result[1]  := (X3 shr 16) and $FF;
  Result[2]  := (X3 shr  8) and $FF;  Result[3]  :=  X3         and $FF;
  Result[4]  := (X2 shr 24) and $FF;  Result[5]  := (X2 shr 16) and $FF;
  Result[6]  := (X2 shr  8) and $FF;  Result[7]  :=  X2         and $FF;
  Result[8]  := (X1 shr 24) and $FF;  Result[9]  := (X1 shr 16) and $FF;
  Result[10] := (X1 shr  8) and $FF;  Result[11] :=  X1         and $FF;
  Result[12] := (X0 shr 24) and $FF;  Result[13] := (X0 shr 16) and $FF;
  Result[14] := (X0 shr  8) and $FF;  Result[15] :=  X0         and $FF;
end;

function TLPConnectBase.P12MemoryEncode(const AData: TBytes): TBytes;
var
  PadLen, I, Offset  : Integer;
  Padded, Block, Enc : TBytes;
begin
  PadLen := 16 - (Length(AData) mod 16);
  SetLength(Padded, Length(AData) + PadLen);
  if Length(AData) > 0 then Move(AData[0], Padded[0], Length(AData));
  for I := Length(AData) to Length(Padded) - 1 do Padded[I] := Byte(PadLen);
  SetLength(Result, Length(Padded));
  Offset := 0;
  while Offset < Length(Padded) do
  begin
    SetLength(Block, 16);
    Move(Padded[Offset], Block[0], 16);
    Enc := SM4EncryptBlock(Block);
    Move(Enc[0], Result[Offset], 16);
    Inc(Offset, 16);
  end;
end;

function TLPConnectBase.DeriveP12Password(const AAccountID, AUid: string): string;
var
  CN, CNEven, UIDOdd, AppInput : string;
  I : Integer;
  Digest, Encoded, First12 : TBytes;
  B64 : string;
begin
  CN := LowerCase(THashMD5.GetHashString(AAccountID));
  CNEven := '';
  for I := 1 to Length(CN) do if (I mod 2) = 1 then CNEven := CNEven + CN[I];
  UIDOdd := '';
  for I := 1 to Length(AUid) do if (I mod 2) = 0 then UIDOdd := UIDOdd + AUid[I];
  AppInput := CN + CNEven + UIDOdd;
  Digest   := THashSHA2.GetHashBytes(AppInput, SHA256);
  Encoded  := P12MemoryEncode(Digest);
  SetLength(First12, 12);
  Move(Encoded[0], First12[0], 12);
  B64 := TNetEncoding.Base64.EncodeBytesToString(First12);
  B64 := StringReplace(B64, '=',  '', [rfReplaceAll]);
  B64 := StringReplace(B64, #13, '', [rfReplaceAll]);
  B64 := StringReplace(B64, #10, '', [rfReplaceAll]);
  Result := Copy(B64, 1, 15);
end;

function TLPConnectBase.DeriveSignKey: TBytes;
var
  SaltBytes, IkmBytes, InfoBytes, PRK, ExpandInput : TBytes;
begin
  SaltBytes   := TEncoding.UTF8.GetBytes(FSignSalt);
  IkmBytes    := TEncoding.UTF8.GetBytes(FSignIkm);
  InfoBytes   := TEncoding.UTF8.GetBytes(FSignInfo);
  PRK         := THashSHA2.GetHMACAsBytes(IkmBytes, SaltBytes, SHA256);
  ExpandInput := InfoBytes + TBytes.Create($01);
  Result      := THashSHA2.GetHMACAsBytes(ExpandInput, PRK, SHA256);
end;

function TLPConnectBase.BuildLoginHeaders(const AUsername, APassword: string): TStringList;
var
  Nonce, Ts, Sign, SignInput: string;
begin
  Nonce := GenerateNonce;
  Ts    := TimestampMs;
  SignInput :=
    FLanguage + LP_DEVICE_TYPE + FDeviceID +
    '1' + AUsername + '0' + '1' + Nonce +
    APassword + '20260204' + LP_SOURCE + Ts + LP_APP_VERSION;
  Sign := SHA256Hex(SignInput);
  Result := TStringList.Create;
  Result.Add('acceptLanguage: ' + FLanguage);
  Result.Add('channel: '        + LP_CHANNEL);
  Result.Add('deviceType: '     + LP_DEVICE_TYPE);
  Result.Add('X-P12_ENC_ALG: ' + LP_P12_ENC_ALG);
  Result.Add('source: '         + LP_SOURCE);
  Result.Add('version: '        + LP_APP_VERSION);
  Result.Add('nonce: '          + Nonce);
  Result.Add('deviceId: '       + FDeviceID);
  Result.Add('timestamp: '      + Ts);
  Result.Add('sign: '           + Sign);
end;

function TLPConnectBase.BuildSignedHeaders(const AVin: string;
                                            const AExtraFields: TStringList): TStringList;
var
  Nonce, Ts, SignInput, Sign : string;
  SignKey : TBytes;
  Fields  : TStringList;
  I       : Integer;
begin
  Nonce   := GenerateNonce;
  Ts      := TimestampMs;
  SignKey := DeriveSignKey;
  Fields  := TStringList.Create;
  try
    Fields.Add('acceptLanguage=' + FLanguage);
    Fields.Add('channel='        + LP_CHANNEL);
    Fields.Add('deviceId='       + FDeviceID);
    Fields.Add('deviceType='     + LP_DEVICE_TYPE);
    Fields.Add('nonce='          + Nonce);
    Fields.Add('source='         + LP_SOURCE);
    Fields.Add('timestamp='      + Ts);
    Fields.Add('version='        + LP_APP_VERSION);
    if AVin <> '' then Fields.Add('vin=' + AVin);
    if Assigned(AExtraFields) then Fields.AddStrings(AExtraFields);
    Fields.Sort;
    SignInput := '';
    for I := 0 to Fields.Count - 1 do
      SignInput := SignInput + Fields.ValueFromIndex[I];
  finally
    Fields.Free;
  end;
  Sign := HMACSHA256Hex(SignKey, SignInput);
  Result := TStringList.Create;
  Result.Add('acceptLanguage: ' + FLanguage);
  Result.Add('channel: '        + LP_CHANNEL);
  Result.Add('deviceType: '     + LP_DEVICE_TYPE);
  Result.Add('X-P12_ENC_ALG: ' + LP_P12_ENC_ALG);
  Result.Add('source: '         + LP_SOURCE);
  Result.Add('version: '        + LP_APP_VERSION);
  Result.Add('nonce: '          + Nonce);
  Result.Add('deviceId: '       + FDeviceID);
  Result.Add('timestamp: '      + Ts);
  Result.Add('sign: '           + Sign);
end;

function TLPConnectBase.AuthHeaders: TStringList;
begin
  if (FUserID = '') or (FToken = '') then
    raise ELPAuthError.Create('Non autenticato: chiama Login() prima.');
  Result := TStringList.Create;
  Result.Add('userId: ' + FUserID);
  Result.Add('token: '  + FToken);
end;

function TLPConnectBase.PEMtoPFX(const ACertFile, AKeyFile: string;
                                   const APassword: AnsiString): TBytes;
type
  TBIO = Pointer; TX509 = Pointer; TEVP_PKEY = Pointer; TPKCS12p = Pointer;
  TfBIO_new_mem_buf      = function(buf: Pointer; len: Integer): TBIO; cdecl;
  TfBIO_free             = procedure(bio: TBIO); cdecl;
  TfPEM_read_bio_X509    = function(bp: TBIO; x, cb, u: Pointer): TX509; cdecl;
  TfPEM_read_bio_PrivKey = function(bp: TBIO; x, cb, u: Pointer): TEVP_PKEY; cdecl;
  TfPKCS12_create        = function(pass, name: PAnsiChar; pkey: TEVP_PKEY; cert: TX509;
                                     ca: Pointer; nid_key, nid_cert, iter,
                                     mac_iter, keytype: Integer): TPKCS12p; cdecl;
  Tfi2d_PKCS12           = function(a: TPKCS12p; pp: PPointer): Integer; cdecl;
  TfPKCS12_free          = procedure(p12: TPKCS12p); cdecl;
  TfX509_free            = procedure(x: TX509); cdecl;
  TfEVP_PKEY_free        = procedure(k: TEVP_PKEY); cdecl;
  TfERR_get_error  = function: LongWord; cdecl;
  TfERR_error_string = function(e: LongWord; buf: PAnsiChar): PAnsiChar; cdecl;
var
  hLib : Pointer;
  fBIO_new_mem_buf      : TfBIO_new_mem_buf;
  fBIO_free             : TfBIO_free;
  fPEM_read_bio_X509    : TfPEM_read_bio_X509;
  fPEM_read_bio_PrivKey : TfPEM_read_bio_PrivKey;
  fPKCS12_create        : TfPKCS12_create;
  fi2d_PKCS12           : Tfi2d_PKCS12;
  fPKCS12_free          : TfPKCS12_free;
  fX509_free            : TfX509_free;
  fEVP_PKEY_free        : TfEVP_PKEY_free;
  CertPEM, KeyPEM : TBytes;
  BioCert, BioKey : TBIO;
  Cert : TX509; PKey : TEVP_PKEY; P12 : TPKCS12p;
  DERLen : Integer; DERPtr : PByte;
  fERR_get_error   : TfERR_get_error;
  fERR_error_string: TfERR_error_string;
  ErrCode : LongWord;
  ErrBuf  : array[0..255] of AnsiChar;

  procedure Load(var FP; const N: string);
  begin
    Pointer(FP) := LibSym(hLib, N);
    if Pointer(FP) = nil then
      raise ELPConnectError.CreateFmt('PEMtoPFX: funzione mancante: %s', [N]);
  end;

begin
  hLib := LibLoad('libcrypto-1_1.dll');
  if hLib = nil then hLib := LibLoad('libcrypto-3.dll');
  if hLib = nil then hLib := LibLoad('libcrypto.so');
  if hLib = nil then raise ELPConnectError.Create('libcrypto non trovata');



  BioCert := nil; BioKey := nil; Cert := nil; PKey := nil; P12 := nil;
  try
    Load(fBIO_new_mem_buf,      'BIO_new_mem_buf');
    Load(fBIO_free,             'BIO_free');
    Load(fPEM_read_bio_X509,    'PEM_read_bio_X509');
    Load(fPEM_read_bio_PrivKey, 'PEM_read_bio_PrivateKey');
    Load(fPKCS12_create,        'PKCS12_create');
    Load(fi2d_PKCS12,           'i2d_PKCS12');
    Load(fPKCS12_free,          'PKCS12_free');
    Load(fX509_free,            'X509_free');
    Load(fEVP_PKEY_free,        'EVP_PKEY_free');

    CertPEM := TFile.ReadAllBytes(ACertFile);
    BioCert := fBIO_new_mem_buf(@CertPEM[0], Length(CertPEM));
    if BioCert = nil then raise ELPConnectError.Create('BIO cert fallito');
    Cert := fPEM_read_bio_X509(BioCert, nil, nil, nil);
    if Cert = nil then raise ELPConnectError.Create('PEM cert non leggibile');

    KeyPEM := TFile.ReadAllBytes(AKeyFile);
    BioKey := fBIO_new_mem_buf(@KeyPEM[0], Length(KeyPEM));
    if BioKey = nil then raise ELPConnectError.Create('BIO key fallito');
    PKey := fPEM_read_bio_PrivKey(BioKey, nil, nil, nil);
    if PKey = nil then raise ELPConnectError.Create('PEM key non leggibile');

    Load(fERR_get_error,   'ERR_get_error');
    Load(fERR_error_string,'ERR_error_string');

    P12 := fPKCS12_create(PAnsiChar(APassword), 'client', PKey, Cert, nil,
                           0, 0, 0, 0, 0);

    if P12 = nil then
    begin
      ErrCode := fERR_get_error;
      fERR_error_string(ErrCode, @ErrBuf[0]);
      raise ELPConnectError.CreateFmt('PKCS12_create fallito: %s (code=%d)',
        [string(AnsiString(ErrBuf)), ErrCode]);
    end;

    DERLen := fi2d_PKCS12(P12, nil);
    if DERLen <= 0 then raise ELPConnectError.Create('i2d_PKCS12 fallito');
    SetLength(Result, DERLen);
    DERPtr := @Result[0];
    fi2d_PKCS12(P12, @DERPtr);
  finally
    if P12     <> nil then fPKCS12_free(P12);
    if Cert    <> nil then fX509_free(Cert);
    if PKey    <> nil then fEVP_PKEY_free(PKey);
    if BioCert <> nil then fBIO_free(BioCert);
    if BioKey  <> nil then fBIO_free(BioKey);
    LibFree(hLib);
  end;
end;

procedure TLPConnectBase.LoadAccountCertFromP12;
type
  TPKCS12 = Pointer; TX509 = Pointer; TEVP_PKEY = Pointer;
  TBIO = Pointer; TBIO_METH = Pointer;
  Tf_d2i_PKCS12            = function(a: Pointer; pp: PPointer; len: LongInt): TPKCS12; cdecl;
  Tf_PKCS12_parse          = function(p12: TPKCS12; pass: PAnsiChar;
                                       pkey: PPointer; cert: PPointer; ca: Pointer): Integer; cdecl;
  Tf_PKCS12_free           = procedure(p12: TPKCS12); cdecl;
  Tf_X509_free             = procedure(x: TX509); cdecl;
  Tf_EVP_PKEY_free         = procedure(k: TEVP_PKEY); cdecl;
  Tf_BIO_new               = function(t: TBIO_METH): TBIO; cdecl;
  Tf_BIO_s_mem             = function: TBIO_METH; cdecl;
  Tf_BIO_free              = procedure(b: TBIO); cdecl;
  Tf_BIO_read              = function(b: TBIO; buf: Pointer; len: Integer): Integer; cdecl;
  Tf_PEM_write_bio_X509    = function(b: TBIO; x: TX509): Integer; cdecl;
  Tf_PEM_write_bio_PrivKey = function(b: TBIO; k: TEVP_PKEY; enc, kstr: Pointer;
                                       klen: Integer; cb, u: Pointer): Integer; cdecl;
var
  hLib : Pointer;
  f_d2i_PKCS12            : Tf_d2i_PKCS12;
  f_PKCS12_parse          : Tf_PKCS12_parse;
  f_PKCS12_free           : Tf_PKCS12_free;
  f_X509_free             : Tf_X509_free;
  f_EVP_PKEY_free         : Tf_EVP_PKEY_free;
  f_BIO_new               : Tf_BIO_new;
  f_BIO_s_mem             : Tf_BIO_s_mem;
  f_BIO_free              : Tf_BIO_free;
  f_BIO_read              : Tf_BIO_read;
  f_PEM_write_bio_X509    : Tf_PEM_write_bio_X509;
  f_PEM_write_bio_PrivKey : Tf_PEM_write_bio_PrivKey;
  P12Bytes : TBytes; Password : string; PassA : AnsiString;
  P12Data : TPKCS12; Cert : TX509; PKey : TEVP_PKEY; Bio : TBIO;
  RawBuf  : array[0..65535] of Byte;
  PemBytes : TBytes; TmpCert, TmpKey : string; FS : TFileStream; P12Ptr : PByte;

  procedure LoadFn(var FP; const N: string);
  begin
    Pointer(FP) := LibSym(hLib, N);
    if Pointer(FP) = nil then
      raise ELPConnectError.CreateFmt('OpenSSL: funzione non trovata: %s', [N]);
  end;

  function BioToBytes(ABio: TBIO): TBytes;
  var N: Integer;
  begin
    N := f_BIO_read(ABio, @RawBuf[0], SizeOf(RawBuf));
    if N <= 0 then raise ELPConnectError.Create('BIO_read fallito');
    SetLength(Result, N);
    Move(RawBuf[0], Result[0], N);
  end;

begin
  if FAccP12Base64 = '' then raise ELPAuthError.Create('base64Cert non disponibile');
  hLib := LibLoad('libcrypto-1_1.dll');
  if hLib = nil then hLib := LibLoad('libcrypto-3.dll');
  if hLib = nil then hLib := LibLoad('libeay32.dll');
  if hLib = nil then hLib := LibLoad('libcrypto.so');
  if hLib = nil then raise ELPConnectError.Create('libcrypto non trovata');
  try
    LoadFn(f_d2i_PKCS12,            'd2i_PKCS12');
    LoadFn(f_PKCS12_parse,          'PKCS12_parse');
    LoadFn(f_PKCS12_free,           'PKCS12_free');
    LoadFn(f_X509_free,             'X509_free');
    LoadFn(f_EVP_PKEY_free,         'EVP_PKEY_free');
    LoadFn(f_BIO_new,               'BIO_new');
    LoadFn(f_BIO_s_mem,             'BIO_s_mem');
    LoadFn(f_BIO_free,              'BIO_free');
    LoadFn(f_BIO_read,              'BIO_read');
    LoadFn(f_PEM_write_bio_X509,    'PEM_write_bio_X509');
    LoadFn(f_PEM_write_bio_PrivKey, 'PEM_write_bio_PrivateKey');

    P12Bytes := TNetEncoding.Base64.DecodeStringToBytes(FAccP12Base64);
    Password := DeriveP12Password(FUserID, FAccUid);
    PassA    := AnsiString(Password);
    P12Ptr   := @P12Bytes[0];
    P12Data  := f_d2i_PKCS12(nil, @P12Ptr, Length(P12Bytes));
    if P12Data = nil then raise ELPConnectError.Create('d2i_PKCS12 fallito');
    try
      Cert := nil; PKey := nil;
      if f_PKCS12_parse(P12Data, PAnsiChar(PassA), @PKey, @Cert, nil) <> 1 then
        raise ELPAuthError.Create('PKCS12_parse fallito: password errata?');
      try
        Bio := f_BIO_new(f_BIO_s_mem);
        try f_PEM_write_bio_X509(Bio, Cert); PemBytes := BioToBytes(Bio); finally f_BIO_free(Bio); end;
        TmpCert := TPath.GetTempFileName;
        FS := TFileStream.Create(TmpCert, fmCreate);
        try FS.WriteBuffer(PemBytes[0], Length(PemBytes)); finally FS.Free; end;

        Bio := f_BIO_new(f_BIO_s_mem);
        try f_PEM_write_bio_PrivKey(Bio, PKey, nil, nil, 0, nil, nil); PemBytes := BioToBytes(Bio); finally f_BIO_free(Bio); end;
        TmpKey := TPath.GetTempFileName;
        FS := TFileStream.Create(TmpKey, fmCreate);
        try FS.WriteBuffer(PemBytes[0], Length(PemBytes)); finally FS.Free; end;

        DeleteTempCerts;
        FAccCertFile := TmpCert;
        FAccKeyFile  := TmpKey;
      finally
        if Cert <> nil then f_X509_free(Cert);
        if PKey <> nil then f_EVP_PKEY_free(PKey);
      end;
    finally
      f_PKCS12_free(P12Data);
    end;
  finally
    LibFree(hLib);
  end;
end;

procedure TLPConnectBase.ParseLoginResponse(const AJSON: string);
var
  Root, Data  : TJSONObject;
  Parts       : TArray<string>;
  B64         : string;
  Payload     : TBytes;
  PayloadJSON : TJSONObject;
  UserParts   : TArray<string>;
begin
  Root := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
  if not Assigned(Root) then raise ELPConnectError.Create('Login: risposta non JSON');
  try
    if Root.GetValue<Integer>('code') <> 0 then
      raise ELPAuthError.Create('Login fallito: ' + Root.GetValue<string>('message'));
    Data          := Root.GetValue<TJSONObject>('data');
    FUserID       := Data.GetValue<string>('id');
    FToken        := Data.GetValue<string>('token');
    FSignIkm      := Data.GetValue<string>('signIkm');
    FSignSalt     := Data.GetValue<string>('signSalt');
    FSignInfo     := Data.GetValue<string>('signInfo');
    FRefreshToken := Data.GetValue<string>('refreshToken');
    FAccUid       := Data.GetValue<string>('uid');
    FAccP12Base64 := Data.GetValue<string>('base64Cert');
    try
      Parts := FToken.Split(['.']);
      if Length(Parts) >= 2 then
      begin
        B64 := Parts[1];
        while (Length(B64) mod 4) <> 0 do B64 := B64 + '=';
        B64 := StringReplace(B64, '-', '+', [rfReplaceAll]);
        B64 := StringReplace(B64, '_', '/', [rfReplaceAll]);
        Payload := TNetEncoding.Base64.DecodeStringToBytes(B64);
        PayloadJSON := TJSONObject.ParseJSONValue(
          TEncoding.UTF8.GetString(Payload)) as TJSONObject;
        if Assigned(PayloadJSON) then
        try
          UserParts := PayloadJSON.GetValue<string>('user_name').Split([',']);
          if (Length(UserParts) >= 4) and (UserParts[2] <> '') then
            FDeviceID := UserParts[2];
        finally
          PayloadJSON.Free;
        end;
      end;
    except end;
  finally
    Root.Free;
  end;
  LoadAccountCertFromP12;
end;

procedure TLPConnectBase.Login(const AUsername, APassword: string);
var
  Headers        : TStringList;
  Body, Response : string;
begin
  Headers := BuildLoginHeaders(AUsername, APassword);
  try
    Body :=
      'isRecoverAcct=0' +
      '&password='         + URLEncodeValue(APassword) +
      '&policyId=20260204' +
      '&loginMethod=1'     +
      '&email='            + URLEncodeValue(AUsername);
    Response := PostForm('/carownerservice/oversea/acct/v1/login', Headers, Body);
  finally
    Headers.Free;
  end;
  ParseLoginResponse(Response);
end;

function TLPConnectBase.GetVehicleList: TJSONObject;
var Hdrs, Auth : TStringList; Response : string;
begin
  SetClientCert(FAccCertFile, FAccKeyFile);
  Hdrs := BuildSignedHeaders; Auth := AuthHeaders;
  try
    Hdrs.AddStrings(Auth);
    Response := PostForm('/carownerservice/oversea/vehicle/v1/list', Hdrs, '');
  finally Hdrs.Free; Auth.Free; end;
  Result := TJSONObject.ParseJSONValue(Response) as TJSONObject;
end;

function TLPConnectBase.GetVehicleStatus(const AVIN, ACarType: string): TJSONObject;
begin
  Result := GetVehicleRawStatus(AVIN, ACarType);
end;

function TLPConnectBase.GetVehicleRawStatus(const AVIN, ACarType: string): TJSONObject;
var Hdrs, Auth : TStringList; Response : string;
begin
  Hdrs := BuildSignedHeaders(AVIN); Auth := AuthHeaders;
  try
    Hdrs.AddStrings(Auth);
    Response := PostForm(
      '/carownerservice/oversea/vehicle/v1/status/get/' + LowerCase(ACarType),
      Hdrs, 'vin=' + TNetEncoding.URL.Encode(AVIN));
  finally Hdrs.Free; Auth.Free; end;
  Result := TJSONObject.ParseJSONValue(Response) as TJSONObject;
end;

function TLPConnectBase.GetMileageEnergyDetail(const AVIN: string): TJSONObject;
var Hdrs, Auth : TStringList; Response : string;
begin
  Hdrs := BuildSignedHeaders(AVIN); Auth := AuthHeaders;
  try
    Hdrs.AddStrings(Auth);
    Response := PostForm(
      '/carownerservice/oversea/drivingRecord/v1/mileage/energy/detail',
      Hdrs, 'vin=' + TNetEncoding.URL.Encode(AVIN));
  finally Hdrs.Free; Auth.Free; end;
  Result := TJSONObject.ParseJSONValue(Response) as TJSONObject;
end;



// Utility

function TLPConnectBase.XorObfuscate(const AData: TBytes): TBytes;
const
  KEY : array[0..15] of Byte = (
    $4C,$50,$43,$6F,$6E,$6E,$65,$63,$74,$32,$30,$32,$35,$50,$4D,$53);
    // 'LPConnect2025PMS'
var
  I : Integer;
begin
  SetLength(Result, Length(AData));
  for I := 0 to Length(AData) - 1 do
    Result[I] := AData[I] xor KEY[I mod 16];
end;

procedure TLPConnectBase.SaveCredentials(const AEmail, APassword: string;
                                          const AFilePath: string);
var
  Path   : string;
  Enc    : TBytes;
  B64    : string;
  Lines  : TStringList;
begin
  if AFilePath = '' then Path := TPath.Combine(TPath.GetHomePath, 'lp_cred.dat')
                    else Path := AFilePath;

  Enc := XorObfuscate(TEncoding.UTF8.GetBytes(APassword));
  B64 := TNetEncoding.Base64.EncodeBytesToString(Enc);
  B64 := StringReplace(B64, #13, '', [rfReplaceAll]);
  B64 := StringReplace(B64, #10, '', [rfReplaceAll]);

  Lines := TStringList.Create;
  try
    Lines.Add('e=' + AEmail);
    Lines.Add('p=' + B64);
    Lines.SaveToFile(Path, TEncoding.UTF8);
  finally
    Lines.Free;
  end;
end;

procedure TLPConnectBase.LoadCredentials(out AEmail, APassword: string;
                                          const AFilePath: string);
var
  Path   : string;
  Lines  : TStringList;
  I      : Integer;
  Key, Val, B64 : string;
  Enc    : TBytes;
begin
  AEmail := ''; APassword := ''; B64 := '';
  if AFilePath = '' then Path := TPath.Combine(TPath.GetHomePath, 'lp_cred.dat')
                    else Path := AFilePath;
  if not TFile.Exists(Path) then Exit;

  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(Path, TEncoding.UTF8);
    for I := 0 to Lines.Count - 1 do
    begin
      Key := Copy(Lines[I], 1, 1);
      Val := Copy(Lines[I], 3, MaxInt);
      if Key = 'e' then AEmail := Val;
      if Key = 'p' then B64    := Val;
    end;
  finally
    Lines.Free;
  end;

  if B64 = '' then Exit;
  try
    Enc       := TNetEncoding.Base64.DecodeStringToBytes(B64);
    APassword := TEncoding.UTF8.GetString(XorObfuscate(Enc));
  except
    APassword := '';
  end;
end;


end.
