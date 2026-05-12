unit LP_CoreAndroid;

{
  LP_CoreAndroid.pas
  Implementazione Android di TLPConnectBase.

  HTTP+mTLS : Java HttpsURLConnection via JNI
  PEM→PFX   : Java puro — nessuna dipendenza da libcrypto.so
  Dipendenze : RAD Studio 10.4, target Android 32/64-bit
}

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding, System.IOUtils,
  Androidapi.JNI,
  LP_CoreBase;

type
  TLPConnect = class(TLPConnectBase)
  private
    FAndroidCert    : Pointer;
    FAndroidPrivKey : Pointer;
    FAndroidAccKSObj : Pointer;
    FAndroidAccPass  : string;
    destructor Destroy; override;
  protected
    function  LibLoad(const AName: string): Pointer; override;
    function  LibSym(ALib: Pointer; const AName: string): Pointer; override;
    procedure LibFree(ALib: Pointer); override;
    function  PEMtoPFX(const ACertFile, AKeyFile: string;
                        const APassword: AnsiString): TBytes; override;
    function  PostForm(const APath    : string;
                       const AHeaders : TStrings;
                       const ABody    : string): string; override;
    procedure LoadAccountCertFromP12; override;
  end;

implementation

uses
  System.Math,
  Posix.Dlfcn,
  Androidapi.JNI.JavaTypes,
  Androidapi.JNIBridge,
  Androidapi.Helpers;

procedure LPLog(const AMsg: string);
begin
  exit;
  if Assigned(LPLogProc) then
    TThread.Synchronize(nil, procedure
    begin
      LPLogProc('[LP] ' + AMsg);
    end);
end;

type
  TJNIValue = packed record
    case Integer of
      0: (z: Boolean);
      1: (b: ShortInt);
      2: (c: Word);
      3: (s: SmallInt);
      4: (i: Integer);
      5: (j: Int64);
      6: (f: Single);
      7: (d: Double);
      8: (l: JNIObject);
  end;

type
  // ── java.io.ByteArrayInputStream ──────────────────────────────
  JByteArrayInputStream = interface;
  JByteArrayInputStreamClass = interface(JObjectClass)
    ['{B2F3C4D5-E6F7-4A8B-9C0D-E1F2A3B4C5D6}']
    function init(buf: TJavaArray<Byte>): JByteArrayInputStream; cdecl;
  end;
  [JavaSignature('java/io/ByteArrayInputStream')]
  JByteArrayInputStream = interface(JInputStream)
    ['{A1B2C3D4-E5F6-4A7B-8C9D-E0F1A2B3C4D5}']
  end;
  TJByteArrayInputStream = class(
    TJavaGenericImport<JByteArrayInputStreamClass, JByteArrayInputStream>) end;

  // ── java.io.ByteArrayOutputStream ─────────────────────────────
  JByteArrayOutputStream = interface;
  JByteArrayOutputStreamClass = interface(JObjectClass)
    ['{A7B8C9D0-1111-2222-3333-444444444401}']
    function init: JByteArrayOutputStream; cdecl;
  end;
  [JavaSignature('java/io/ByteArrayOutputStream')]
  JByteArrayOutputStream = interface(JOutputStream)
    ['{B8C9D0E1-1111-2222-3333-444444444401}']
    function toByteArray: TJavaArray<Byte>; cdecl;
  end;
  TJByteArrayOutputStream = class(
    TJavaGenericImport<JByteArrayOutputStreamClass, JByteArrayOutputStream>) end;



  // ── java.net.URLConnection ────────────────────────────────────
  JURLConnection = interface;
  JURLConnectionClass = interface(JObjectClass)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
  end;
  [JavaSignature('java/net/URLConnection')]
  JURLConnection = interface(JObject)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    procedure setRequestMethod(method: JString); cdecl;
    procedure setRequestProperty(key, value: JString); cdecl;
    procedure setDoOutput(dooutput: Boolean); cdecl;
    procedure setConnectTimeout(timeout: Integer); cdecl;
    procedure setReadTimeout(timeout: Integer); cdecl;
    function  getOutputStream: JOutputStream; cdecl;
    function  getInputStream: JInputStream; cdecl;
    procedure connect; cdecl;
  end;
  TJURLConnection = class(
    TJavaGenericImport<JURLConnectionClass, JURLConnection>) end;

  // ── java.net.URL ──────────────────────────────────────────────
  JURL = interface;
  JURLClass = interface(JObjectClass)
    ['{F1E2D3C4-B5A6-4978-8B9C-ADBEEF012345}']
    function init(spec: JString): JURL; cdecl;
  end;
  [JavaSignature('java/net/URL')]
  JURL = interface(JObject)
    ['{A2B3C4D5-E6F7-4890-9ABC-DEF012345678}']
    function openConnection: JURLConnection; cdecl;
  end;
  TJURL = class(TJavaGenericImport<JURLClass, JURL>) end;

  // ── java.net.HttpURLConnection ────────────────────────────────
  JHttpURLConnection = interface;
  JHttpURLConnectionClass = interface(JURLConnectionClass)
    ['{C3D4E5F6-A7B8-9012-CDEF-123456789012}']
  end;
  [JavaSignature('java/net/HttpURLConnection')]
  JHttpURLConnection = interface(JURLConnection)
    ['{D4E5F6A7-B8C9-0123-DEF0-234567890123}']
  end;
  TJHttpURLConnection = class(
    TJavaGenericImport<JHttpURLConnectionClass, JHttpURLConnection>) end;

  // ── java.security.cert.Certificate ───────────────────────────
  JCertificate = interface;
  JCertificateClass = interface(JObjectClass)
    ['{A1B2C3D4-2222-3333-4444-555555555501}']
  end;
  [JavaSignature('java/security/cert/Certificate')]
  JCertificate = interface(JObject)
    ['{B2C3D4E5-2222-3333-4444-555555555501}']
  end;
  TJCertificate = class(
    TJavaGenericImport<JCertificateClass, JCertificate>) end;

  // ── java.security.Key ─────────────────────────────────────────
  JKey = interface;
  JKeyClass = interface(JObjectClass)
    ['{A1B2C3D4-3333-4444-5555-666666666601}']
  end;
  [JavaSignature('java/security/Key')]
  JKey = interface(JObject)
    ['{B2C3D4E5-3333-4444-5555-666666666601}']
  end;
  TJKey = class(TJavaGenericImport<JKeyClass, JKey>) end;

  // ── java.security.PrivateKey ──────────────────────────────────
  JPrivateKey = interface;
  JPrivateKeyClass = interface(JKeyClass)
    ['{A1B2C3D4-5555-6666-7777-888888888801}']
  end;
  [JavaSignature('java/security/PrivateKey')]
  JPrivateKey = interface(JKey)
    ['{B2C3D4E5-5555-6666-7777-888888888801}']
  end;
  TJPrivateKey = class(TJavaGenericImport<JPrivateKeyClass, JPrivateKey>) end;

  // ── java.security.KeyStore ────────────────────────────────────
  JKeyStore = interface;
  JKeyStoreClass = interface(JObjectClass)
    ['{11223344-5566-7788-99AA-BBCCDDEEFF00}']
    function getInstance(type_: JString): JKeyStore; cdecl;
  end;
  [JavaSignature('java/security/KeyStore')]
  JKeyStore = interface(JObject)
    ['{FFEEDDCC-BBAA-9988-7766-554433221100}']
    procedure load(stream: JInputStream; password: TJavaArray<Char>); cdecl;
    procedure setKeyEntry(alias: JString; key: JKey;
                           password: TJavaArray<Char>;
                           chain: TJavaObjectArray<JObject>); cdecl;
    procedure store(stream: JOutputStream;
                    password: TJavaArray<Char>); cdecl;
  end;
  TJKeyStore = class(TJavaGenericImport<JKeyStoreClass, JKeyStore>) end;

  // ── java.security.cert.CertificateFactory ─────────────────────
  JCertificateFactory = interface;
  JCertificateFactoryClass = interface(JObjectClass)
    ['{A1B2C3D4-1111-2222-3333-444444444402}']
    function getInstance(type_: JString): JCertificateFactory; cdecl;
  end;
  [JavaSignature('java/security/cert/CertificateFactory')]
  JCertificateFactory = interface(JObject)
    ['{B2C3D4E5-1111-2222-3333-444444444402}']
    function generateCertificate(inStream: JInputStream): JCertificate; cdecl;
  end;
  TJCertificateFactory = class(
    TJavaGenericImport<JCertificateFactoryClass, JCertificateFactory>) end;

  // ── java.security.spec.KeySpec ────────────────────────────────
  JKeySpec = interface;
  JKeySpecClass = interface(JObjectClass)
    ['{A1B2C3D4-4444-5555-6666-777777777701}']
  end;
  [JavaSignature('java/security/spec/KeySpec')]
  JKeySpec = interface(JObject)
    ['{B2C3D4E5-4444-5555-6666-777777777701}']
  end;
  TJKeySpec = class(TJavaGenericImport<JKeySpecClass, JKeySpec>) end;

  // ── java.security.spec.PKCS8EncodedKeySpec ────────────────────
  JPKCS8EncodedKeySpec = interface;
  JPKCS8EncodedKeySpecClass = interface(JObjectClass)
    ['{C3D4E5F6-1111-2222-3333-444444444402}']
    function init(encodedKey: TJavaArray<Byte>): JPKCS8EncodedKeySpec; cdecl;
  end;
  [JavaSignature('java/security/spec/PKCS8EncodedKeySpec')]
  JPKCS8EncodedKeySpec = interface(JObject)
    ['{D4E5F6A7-1111-2222-3333-444444444402}']
  end;
  TJPKCSEncodedKeySpec = class(
    TJavaGenericImport<JPKCS8EncodedKeySpecClass, JPKCS8EncodedKeySpec>) end;

  // ── java.security.KeyFactory ──────────────────────────────────
  JKeyFactory = interface;
  JKeyFactoryClass = interface(JObjectClass)
    ['{E5F6A7B8-1111-2222-3333-444444444402}']
    function getInstance(algorithm: JString): JKeyFactory; cdecl;
  end;
  [JavaSignature('java/security/KeyFactory')]
  JKeyFactory = interface(JObject)
    ['{F6A7B8C9-1111-2222-3333-444444444402}']
    function generatePrivate(keySpec: JKeySpec): JPrivateKey; cdecl;
  end;
  TJKeyFactory = class(
    TJavaGenericImport<JKeyFactoryClass, JKeyFactory>) end;

  // ── javax.net.ssl.KeyManager ──────────────────────────────────
  JKeyManager = interface(IJavaInstance)
    ['{B8C9D0E1-F2A3-4B4C-5D6E-F7A8B9C0D1E2}']
  end;

  // ── javax.net.ssl.X509KeyManager ──────────────────────────────
  [JavaSignature('javax/net/ssl/X509KeyManager')]
  JX509KeyManager = interface(JKeyManager)
    ['{A1B2C3D4-6666-7777-8888-999999999901}']
    function  getPrivateKey(alias: JString): JObject; cdecl;
    function  getCertificateChain(alias: JString): TJavaObjectArray<JObject>; cdecl;
    function  getClientAliases(keyType: JString;
                                issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
    function  getServerAliases(keyType: JString;
                                issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
    function  chooseClientAlias(keyTypes: TJavaObjectArray<JString>;
                                 issuers: TJavaObjectArray<JObject>;
                                 socket: JObject): JString; cdecl;
    function  chooseServerAlias(keyType: JString;
                                 issuers: TJavaObjectArray<JObject>;
                                 socket: JObject): JString; cdecl;
  end;

  // ── javax.net.ssl.TrustManager ────────────────────────────────
  JTrustManager = interface(IJavaInstance)
    ['{F2A3B4C5-D6E7-4F8A-9B0C-D1E2F3A4B5C6}']
  end;

  // ── javax.net.ssl.X509TrustManager ───────────────────────────
  [JavaSignature('javax/net/ssl/X509TrustManager')]
  JX509TrustManager = interface(JTrustManager)
    ['{A2B3C4D5-E6F7-4A8B-9C0D-E1F2A3B4C5D6}']
    procedure checkClientTrusted(chain: TJavaObjectArray<JObject>;
                                  authType: JString); cdecl;
    procedure checkServerTrusted(chain: TJavaObjectArray<JObject>;
                                  authType: JString); cdecl;
    function  getAcceptedIssuers: TJavaObjectArray<JObject>; cdecl;
  end;

  // ── javax.net.ssl.SSLSession ──────────────────────────────────
  JSSLSession = interface(IJavaInstance)
    ['{F8A9B0C1-D2E3-4F4A-5B6C-D7E8F9A0B1C2}']
  end;

  // ── javax.net.ssl.HostnameVerifier ────────────────────────────
  [JavaSignature('javax/net/ssl/HostnameVerifier')]
  JHostnameVerifier = interface(IJavaInstance)
    ['{A9B0C1D2-E3F4-4A5B-6C7D-E8F9A0B1C2D3}']
    function verify(hostname: JString; session: JSSLSession): Boolean; cdecl;
  end;

  // ── javax.net.ssl.SSLSocketFactory ───────────────────────────
  JSSLSocketFactory = interface;
  JSSLSocketFactoryClass = interface(JObjectClass)
    ['{A3B4C5D6-E7F8-4A9B-0C1D-E2F3A4B5C6D7}']
  end;
  [JavaSignature('javax/net/ssl/SSLSocketFactory')]
  JSSLSocketFactory = interface(JObject)
    ['{B4C5D6E7-F8A9-4B0C-1D2E-F3A4B5C6D7E8}']
  end;
  TJSSLSocketFactory = class(
    TJavaGenericImport<JSSLSocketFactoryClass, JSSLSocketFactory>) end;

  // ── javax.net.ssl.SSLContext ──────────────────────────────────
  JSSLContext = interface;
  JSSLContextClass = interface(JObjectClass)
    ['{C5D6E7F8-A9B0-4C1D-2E3F-A4B5C6D7E8F9}']
    function getInstance(protocol: JString): JSSLContext; cdecl;
  end;
   [JavaSignature('javax/net/ssl/SSLContext')]
  JSSLContext = interface(JObject)
    ['{D6E7F8A9-B0C1-4D2E-3F4A-B5C6D7E8F9A0}']
    procedure init(km: JObject; tm: JObject; random: JObject); cdecl;
    function  getSocketFactory: JSSLSocketFactory; cdecl;
  end;
  TJSSLContext = class(TJavaGenericImport<JSSLContextClass, JSSLContext>) end;

  // ── javax.net.ssl.HttpsURLConnection ─────────────────────────
  JHttpsURLConnection = interface;
  JHttpsURLConnectionClass = interface(JHttpURLConnectionClass)
    ['{B0C1D2E3-F4A5-4B6C-7D8E-F9A0B1C2D3E4}']
  end;
  [JavaSignature('javax/net/ssl/HttpsURLConnection')]
  JHttpsURLConnection = interface(JHttpURLConnection)
    ['{C1D2E3F4-A5B6-4C7D-8E9F-A0B1C2D3E4F5}']
    procedure setSSLSocketFactory(sf: JSSLSocketFactory); cdecl;
    procedure setHostnameVerifier(v: JHostnameVerifier); cdecl;
    function  getResponseCode: Integer; cdecl;
    function  getResponseMessage: JString; cdecl;
    function  getErrorStream: JInputStream; cdecl;
  end;
  TJHttpsURLConnection = class(
    TJavaGenericImport<JHttpsURLConnectionClass, JHttpsURLConnection>) end;

   // ── javax.net.ssl.KeyManagerFactory ──────────────────────────
  JKeyManagerFactory = interface;
  JKeyManagerFactoryClass = interface(JObjectClass)
    ['{C9D0E1F2-A3B4-4C5D-6E7F-A8B9C0D1E2F3}']
    function getInstance(algorithm: JString): JKeyManagerFactory; cdecl;
  end;
  [JavaSignature('javax/net/ssl/KeyManagerFactory')]
  JKeyManagerFactory = interface(JObject)
    ['{D0E1F2A3-B4C5-4D6E-7F8A-B9C0D1E2F3A4}']
    function getKeyManagers: TJavaObjectArray<JKeyManager>; cdecl;
  end;
  TJKeyManagerFactory = class(
    TJavaGenericImport<JKeyManagerFactoryClass, JKeyManagerFactory>) end;



  // ── TrustAll ──────────────────────────────────────────────────
  TTrustAllManager = class(TJavaLocal, JX509TrustManager)
  public
    procedure checkClientTrusted(chain: TJavaObjectArray<JObject>;
                                  authType: JString); cdecl;
    procedure checkServerTrusted(chain: TJavaObjectArray<JObject>;
                                  authType: JString); cdecl;
    function  getAcceptedIssuers: TJavaObjectArray<JObject>; cdecl;
  end;

  TTrustAllHostnames = class(TJavaLocal, JHostnameVerifier)
  public
    function verify(hostname: JString; session: JSSLSession): Boolean; cdecl;
  end;

  // ── KeyManager custom (bypassa KeyManagerFactory) ─────────────
  TLPKeyManager = class(TJavaLocal, JX509KeyManager)
  private
    FCertPtr : Pointer;
    FKeyPtr  : Pointer;
  public
    constructor Create(const ACertPtr, AKeyPtr: Pointer);
    function  getPrivateKey(alias: JString): JObject; cdecl;
    function  getCertificateChain(alias: JString): TJavaObjectArray<JObject>; cdecl;
    function  getClientAliases(keyType: JString;
                                issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
    function  getServerAliases(keyType: JString;
                                issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
    function  chooseClientAlias(keyTypes: TJavaObjectArray<JString>;
                                 issuers: TJavaObjectArray<JObject>;
                                 socket: JObject): JString; cdecl;
    function  chooseServerAlias(keyType: JString;
                                 issuers: TJavaObjectArray<JObject>;
                                 socket: JObject): JString; cdecl;
  end;

{ TTrustAllManager }

procedure TTrustAllManager.checkClientTrusted(chain: TJavaObjectArray<JObject>;
  authType: JString); cdecl;
begin end;

procedure TTrustAllManager.checkServerTrusted(chain: TJavaObjectArray<JObject>;
  authType: JString); cdecl;
begin end;

function TTrustAllManager.getAcceptedIssuers: TJavaObjectArray<JObject>; cdecl;
begin
  Result := TJavaObjectArray<JObject>.Create(0);
end;

{ TTrustAllHostnames }

function TTrustAllHostnames.verify(hostname: JString;
  session: JSSLSession): Boolean; cdecl;
begin
  Result := True;
end;

{ TLPKeyManager }

constructor TLPKeyManager.Create(const ACertPtr, AKeyPtr: Pointer);
begin
  inherited Create;
  FCertPtr := ACertPtr;
  FKeyPtr  := AKeyPtr;
end;

function TLPKeyManager.getPrivateKey(alias: JString): JObject; cdecl;
begin
  Result := TJObject.Wrap(JNIObject(FKeyPtr));
end;

function TLPKeyManager.getCertificateChain(alias: JString): TJavaObjectArray<JObject>; cdecl;
begin
  Result    := TJavaObjectArray<JObject>.Create(1);
  Result[0] := TJObject.Wrap(JNIObject(FCertPtr));
end;

function TLPKeyManager.getClientAliases(keyType: JString;
  issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
begin
  Result    := TJavaObjectArray<JString>.Create(1);
  Result[0] := StringToJString('client');
end;

function TLPKeyManager.getServerAliases(keyType: JString;
  issuers: TJavaObjectArray<JObject>): TJavaObjectArray<JString>; cdecl;
begin
  Result := nil;
end;

function TLPKeyManager.chooseClientAlias(keyTypes: TJavaObjectArray<JString>;
  issuers: TJavaObjectArray<JObject>; socket: JObject): JString; cdecl;
begin
  Result := StringToJString('client');
end;

function TLPKeyManager.chooseServerAlias(keyType: JString;
  issuers: TJavaObjectArray<JObject>; socket: JObject): JString; cdecl;
begin
  Result := nil;
end;

{ TLPConnect }

function TLPConnect.LibLoad(const AName: string): Pointer;
begin
  Result := Pointer(dlopen(PAnsiChar(AnsiString(AName)), RTLD_LAZY));
end;

function TLPConnect.LibSym(ALib: Pointer; const AName: string): Pointer;
begin
  Result := dlsym(NativeUInt(ALib), PAnsiChar(AnsiString(AName)));
end;

procedure TLPConnect.LibFree(ALib: Pointer);
begin
  dlclose(NativeUInt(ALib));
end;

function TLPConnect.PEMtoPFX(const ACertFile, AKeyFile: string;
                               const APassword: AnsiString): TBytes;

  function PEMToDER(const AFile: string): TBytes;
  var
    Raw    : string;
    StartP : Integer;
    EndP   : Integer;
    Block  : string;
    B64    : string;
    Lines  : TArray<string>;
    Line   : string;
  begin
    LPLog('PEMToDER: inizio per ' + AFile);
    if not TFile.Exists(AFile) then
      raise ELPConnectError.Create('PEMToDER: file non trovato: ' + AFile);
    Raw := TFile.ReadAllText(AFile, TEncoding.UTF8);
    LPLog('PEMToDER: letti ' + IntToStr(Length(Raw)) + ' chars');
    StartP := Pos('-----BEGIN', Raw);
    if StartP = 0 then
      raise ELPConnectError.Create('PEMToDER: nessun marker BEGIN in ' + AFile);
    EndP := Pos('-----', Raw, StartP + 10);
    EndP := Pos('-----', Raw, EndP + 5);
    if EndP = 0 then
      raise ELPConnectError.Create('PEMToDER: nessun marker END in ' + AFile);
    Block := Copy(Raw, StartP, EndP - StartP + 5);
    Lines := Block.Split([#10]);
    B64   := '';
    for Line in Lines do
    begin
      if Trim(Line).StartsWith('-----') then Continue;
      if Trim(Line) = '' then Continue;
      B64 := B64 + Trim(StringReplace(Line, #13, '', [rfReplaceAll]));
    end;
    if B64 = '' then
      raise ELPConnectError.Create('PEMToDER: base64 vuoto in ' + AFile);
    LPLog('PEMToDER: DER bytes=' + IntToStr(Length(
      TNetEncoding.Base64.DecodeStringToBytes(B64))));
    Result := TNetEncoding.Base64.DecodeStringToBytes(B64);
  end;

  function BytesToJava(const ABytes: TBytes): TJavaArray<Byte>;
  var I: Integer;
  begin
    Result := TJavaArray<Byte>.Create(Length(ABytes));
    for I := 0 to Length(ABytes) - 1 do
      Result[I] := ShortInt(ABytes[I]);
  end;

var
  PassStr   : string;
  PassChars : TJavaArray<Char>;
  CertDER   : TBytes;
  KeyDER    : TBytes;
  CertArr   : TJavaArray<Byte>;
  KeyArr    : TJavaArray<Byte>;
  BisCert   : JByteArrayInputStream;
  CF        : JCertificateFactory;
  Cert      : JCertificate;
  KeySpec   : JPKCS8EncodedKeySpec;
  KF        : JKeyFactory;
  PrivKey   : JPrivateKey;
  KS        : JKeyStore;
  BOS       : JByteArrayOutputStream;
  OutArr    : TJavaArray<Byte>;
  I         : Integer;
  Env       : PJNIEnv;
  KSObj     : JNIObject;
  KSClass   : JNIClass;
  MID       : JNIMethodID;
  CertClass : JNIClass;
  CertArrJ  : JNIObject;
  AliasObj  : JNIObject;
  KeyObj    : JNIObject;
  BOSObj    : JNIObject;
  PassLen   : Integer;
  PassArrJ  : JNIObject;
  PassPtr   : Pointer;
  Args4     : array[0..3] of TJNIValue;
  Args2     : array[0..1] of TJNIValue;
begin
  LPLog('PEMtoPFX: inizio CertFile=' + ACertFile);

  PassStr   := string(APassword);
  PassChars := TJavaArray<Char>.Create(Length(PassStr));
  try
    for I := 0 to Length(PassStr) - 1 do PassChars[I] := PassStr[I + 1];

    // ── Certificato ───────────────────────────────────────────
    LPLog('PEMtoPFX: [1] cert DER...');
    CertDER := PEMToDER(ACertFile);
    CertArr := BytesToJava(CertDER);
    try
      BisCert := TJByteArrayInputStream.JavaClass.init(CertArr);
      CF      := TJCertificateFactory.JavaClass.getInstance(
                   StringToJString('X.509'));
      Cert    := CF.generateCertificate(
                   TJInputStream.Wrap((BisCert as ILocalObject).GetObjectID));
      LPLog('PEMtoPFX: [1] cert OK');
    finally
      CertArr.Free;
    end;

    // ── Chiave privata ────────────────────────────────────────
    LPLog('PEMtoPFX: [2] key DER...');
    KeyDER := PEMToDER(AKeyFile);
    KeyArr := BytesToJava(KeyDER);
    try
      KeySpec := TJPKCSEncodedKeySpec.JavaClass.init(KeyArr);
      KF      := TJKeyFactory.JavaClass.getInstance(StringToJString('RSA'));
      PrivKey := KF.generatePrivate(
                   TJKeySpec.Wrap((KeySpec as ILocalObject).GetObjectID));
      if TJNIResolver.GetJNIEnv^.ExceptionCheck(TJNIResolver.GetJNIEnv) = 1 then
      begin
        TJNIResolver.GetJNIEnv^.ExceptionClear(TJNIResolver.GetJNIEnv);
        LPLog('PEMtoPFX: RSA fallito, provo EC...');
        KF      := TJKeyFactory.JavaClass.getInstance(StringToJString('EC'));
        PrivKey := KF.generatePrivate(
                     TJKeySpec.Wrap((KeySpec as ILocalObject).GetObjectID));
        if TJNIResolver.GetJNIEnv^.ExceptionCheck(TJNIResolver.GetJNIEnv) = 1 then
        begin
          TJNIResolver.GetJNIEnv^.ExceptionClear(TJNIResolver.GetJNIEnv);
          raise ELPConnectError.Create('generatePrivate fallito RSA e EC');
        end;
        LPLog('PEMtoPFX: chiave EC OK');
      end else
        LPLog('PEMtoPFX: chiave RSA OK');
    finally
      KeyArr.Free;
    end;

    // Salva per uso in PostForm (bypassa KeyManagerFactory)
    FAndroidCert    := Pointer((Cert as ILocalObject).GetObjectID);
    FAndroidPrivKey := Pointer((PrivKey as ILocalObject).GetObjectID);

    // ── KeyStore PKCS12 ───────────────────────────────────────
    LPLog('PEMtoPFX: [3] KeyStore...');
    KS := TJKeyStore.JavaClass.getInstance(StringToJString('PKCS12'));
    KS.load(nil, nil);

    // setKeyEntry via JNI diretto
    LPLog('PEMtoPFX: [4] setKeyEntry JNI...');
    Env      := TJNIResolver.GetJNIEnv;
    KSObj    := (KS as ILocalObject).GetObjectID;
    KSClass  := Env^.GetObjectClass(Env, KSObj);
    MID      := Env^.GetMethodID(Env, KSClass, 'setKeyEntry',
      '(Ljava/lang/String;Ljava/security/Key;[C[Ljava/security/cert/Certificate;)V');
    if MID = nil then
      raise ELPConnectError.Create('setKeyEntry MID non trovato');

    CertClass := Env^.FindClass(Env, 'java/security/cert/Certificate');
    CertArrJ  := Env^.NewObjectArray(Env, 1, CertClass, nil);
    Env^.SetObjectArrayElement(Env, CertArrJ, 0,
      (Cert as ILocalObject).GetObjectID);

    AliasObj := (StringToJString('client') as ILocalObject).GetObjectID;
    KeyObj   := (PrivKey as ILocalObject).GetObjectID;

    PassLen  := PassChars.Length;
    PassArrJ := Env^.NewCharArray(Env, PassLen);
    PassPtr  := Env^.GetCharArrayElements(Env, PassArrJ, nil);
    for I := 0 to PassLen - 1 do
      PWideChar(PByte(PassPtr) + I * 2)^ := PassChars[I];
    Env^.ReleaseCharArrayElements(Env, PassArrJ, PassPtr, 0);

    Args4[0].l := AliasObj;
    Args4[1].l := KeyObj;
    Args4[2].l := PassArrJ;
    Args4[3].l := CertArrJ;
    Env^.CallVoidMethodA(Env, KSObj, MID, @Args4[0]);

    if Env^.ExceptionCheck(Env) = 1 then
    begin
      Env^.ExceptionClear(Env);
      raise ELPConnectError.Create('setKeyEntry eccezione Java');
    end;
    LPLog('PEMtoPFX: [4] setKeyEntry OK');

    // store via JNI diretto
    LPLog('PEMtoPFX: [5] store JNI...');
    BOS    := TJByteArrayOutputStream.JavaClass.init;
    BOSObj := (BOS as ILocalObject).GetObjectID;

    Env     := TJNIResolver.GetJNIEnv;
    KSObj   := (KS as ILocalObject).GetObjectID;
    KSClass := Env^.GetObjectClass(Env, KSObj);
    MID     := Env^.GetMethodID(Env, KSClass, 'store',
      '(Ljava/io/OutputStream;[C)V');
    if MID = nil then
      raise ELPConnectError.Create('store MID non trovato');

    PassLen  := PassChars.Length;
    PassArrJ := Env^.NewCharArray(Env, PassLen);
    PassPtr  := Env^.GetCharArrayElements(Env, PassArrJ, nil);
    for I := 0 to PassLen - 1 do
      PWideChar(PByte(PassPtr) + I * 2)^ := PassChars[I];
    Env^.ReleaseCharArrayElements(Env, PassArrJ, PassPtr, 0);

    Args2[0].l := BOSObj;
    Args2[1].l := PassArrJ;
    Env^.CallVoidMethodA(Env, KSObj, MID, @Args2[0]);

    if Env^.ExceptionCheck(Env) = 1 then
    begin
      Env^.ExceptionClear(Env);
      raise ELPConnectError.Create('store eccezione Java');
    end;

    OutArr := BOS.toByteArray;
    SetLength(Result, OutArr.Length);
    for I := 0 to OutArr.Length - 1 do Result[I] := Byte(OutArr[I]);
    LPLog('PEMtoPFX: completato, PFX bytes=' + IntToStr(Length(Result)));

  finally
    PassChars.Free;
  end;
end;

function TLPConnect.PostForm(const APath: string; const AHeaders: TStrings;
  const ABody: string): string;
const
  PFX_PASS : AnsiString = 'lp_tmp_pfx_pwd';
var
  PfxBytes  : TBytes;
  PfxArr    : TJavaArray<Byte>;
  PassChars : TJavaArray<Char>;
  PassStr   : string;
  I, N      : Integer;
  SslCtx    : JSSLContext;
  URL_      : JURL;
  ConnObj   : JObject;
  Conn      : JHttpsURLConnection;
  OS        : JOutputStream;
  IS_       : JInputStream;
  BufArr    : TJavaArray<Byte>;
  RespStream: TBytesStream;
  BodyBytes : TBytes;
  BodyArr   : TJavaArray<Byte>;
  ColonIdx  : Integer;
  Env2      : PJNIEnv;
  SslObj    : JNIObject;
  SslClass  : JNIClass;
  MIDSsl    : JNIMethodID;
  ArgsSsl   : array[0..2] of TJNIValue;
  TrustMgr  : TTrustAllManager;
  TrustObj  : JNIObject;
  TrustClass: JNIClass;
  TrustArr  : JNIObject;
  ArgsGetKS  : array[0..0] of TJNIValue;
  ArgsGetKMF : array[0..0] of TJNIValue;
  ArgsLoad   : array[0..1] of TJNIValue;
  ArgsKMF3   : array[0..1] of TJNIValue;
  ArgsBIS2   : array[0..0] of TJNIValue;
begin
LPLog('PostForm: inizio PATH=' + APath);

  PassStr   := string(PFX_PASS);
  PassChars := TJavaArray<Char>.Create(Length(PassStr));
  PfxArr    := TJavaArray<Byte>.Create(0);
  try
    for I := 0 to Length(PassStr) - 1 do PassChars[I] := PassStr[I + 1];

    LPLog('PostForm: [2] SSL setup...');
    try
      Env2 := TJNIResolver.GetJNIEnv;

      var KSObj3   : JNIObject;
      var PassArr3 : JNIObject;

      if FAndroidAccKSObj <> nil then
      begin
        // ── Chiamate autenticate: usa KeyStore account ────────
        LPLog('PostForm: [2] usando AccKS');
        KSObj3 := JNIObject(FAndroidAccKSObj);

        var AccLen  : Integer := Length(FAndroidAccPass);
        PassArr3    := Env2^.NewCharArray(Env2, AccLen);
        var AccPtr  : Pointer := Env2^.GetCharArrayElements(Env2, PassArr3, nil);
        for var JA := 0 to AccLen - 1 do
          PWideChar(PByte(AccPtr) + JA * 2)^ := FAndroidAccPass[JA + 1];
        Env2^.ReleaseCharArrayElements(Env2, PassArr3, AccPtr, 0);
      end
      else
      begin
        // ── Login: usa PEMtoPFX con app cert ─────────────────
        LPLog('PostForm: [1] PEMtoPFX...');
        try
          PfxBytes := PEMtoPFX(FCurrentCertFile, FCurrentKeyFile, PFX_PASS);
        except on E: Exception do
          raise ELPConnectError.Create('PostForm: PEMtoPFX fallito: ' + E.Message);
        end;
        LPLog('PostForm: [1] PEMtoPFX OK, bytes=' + IntToStr(Length(PfxBytes)));

        var PassLen3  : Integer := PassChars.Length;
        PassArr3 := Env2^.NewCharArray(Env2, PassLen3);
        var PassPtr3  : Pointer := Env2^.GetCharArrayElements(Env2, PassArr3, nil);
        for var J3 := 0 to PassLen3 - 1 do
          PWideChar(PByte(PassPtr3) + J3 * 2)^ := PassChars[J3];
        Env2^.ReleaseCharArrayElements(Env2, PassArr3, PassPtr3, 0);

        // KeyStore.getInstance
        var KSClass2  : JNIClass    := Env2^.FindClass(Env2, 'java/security/KeyStore');
        var MIDGetKS  : JNIMethodID := Env2^.GetStaticMethodID(Env2, KSClass2,
          'getInstance', '(Ljava/lang/String;)Ljava/security/KeyStore;');
        var PKCS12Str : JNIObject   := (StringToJString('PKCS12') as ILocalObject).GetObjectID;
        ArgsGetKS[0].l := PKCS12Str;
        KSObj3 := Env2^.CallStaticObjectMethodA(Env2, KSClass2, MIDGetKS, @ArgsGetKS[0]);
        if Env2^.ExceptionCheck(Env2) = 1 then
        begin
          Env2^.ExceptionClear(Env2);
          raise ELPConnectError.Create('KS.getInstance eccezione');
        end;
        LPLog('PostForm: [2a] KS getInstance OK');

        // BIS dal PFX
        var BISClass  : JNIClass    := Env2^.FindClass(Env2, 'java/io/ByteArrayInputStream');
        var MIDNewBIS : JNIMethodID := Env2^.GetMethodID(Env2, BISClass, '<init>', '([B)V');
        var PfxJArr   : JNIObject   := Env2^.NewByteArray(Env2, Length(PfxBytes));
        var PfxPtr    : Pointer     := Env2^.GetByteArrayElements(Env2, PfxJArr, nil);
        Move(PfxBytes[0], PfxPtr^, Length(PfxBytes));
        Env2^.ReleaseByteArrayElements(Env2, PfxJArr, PfxPtr, 0);
        ArgsBIS2[0].l := PfxJArr;
        var BISObj    : JNIObject   := Env2^.NewObjectA(Env2, BISClass, MIDNewBIS, @ArgsBIS2[0]);

        // KeyStore.load
        var KSClass2b : JNIClass    := Env2^.GetObjectClass(Env2, KSObj3);
        var MIDLoad   : JNIMethodID := Env2^.GetMethodID(Env2, KSClass2b, 'load',
          '(Ljava/io/InputStream;[C)V');
        ArgsLoad[0].l := BISObj;
        ArgsLoad[1].l := PassArr3;
        Env2^.CallVoidMethodA(Env2, KSObj3, MIDLoad, @ArgsLoad[0]);
        if Env2^.ExceptionCheck(Env2) = 1 then
        begin
          Env2^.ExceptionClear(Env2);
          raise ELPConnectError.Create('KS.load eccezione');
        end;
        LPLog('PostForm: [2b] KS load OK');
      end;

      // ── KMF (comune) ─────────────────────────────────────────
      var KMFClass3  : JNIClass    := Env2^.FindClass(Env2, 'javax/net/ssl/KeyManagerFactory');
      var MIDGetKMF  : JNIMethodID := Env2^.GetStaticMethodID(Env2, KMFClass3,
        'getInstance', '(Ljava/lang/String;)Ljavax/net/ssl/KeyManagerFactory;');
      var X509Str    : JNIObject   := (StringToJString('X509') as ILocalObject).GetObjectID;
      ArgsGetKMF[0].l := X509Str;
      var KMFObj3    : JNIObject   := Env2^.CallStaticObjectMethodA(Env2, KMFClass3,
        MIDGetKMF, @ArgsGetKMF[0]);
      if Env2^.ExceptionCheck(Env2) = 1 then
      begin
        Env2^.ExceptionClear(Env2);
        raise ELPConnectError.Create('KMF.getInstance eccezione');
      end;
      LPLog('PostForm: [2c] KMF getInstance OK');

      var KMFClass3b : JNIClass    := Env2^.GetObjectClass(Env2, KMFObj3);
      var MIDInitKMF : JNIMethodID := Env2^.GetMethodID(Env2, KMFClass3b, 'init',
        '(Ljava/security/KeyStore;[C)V');
      ArgsKMF3[0].l := KSObj3;
      ArgsKMF3[1].l := PassArr3;
      Env2^.CallVoidMethodA(Env2, KMFObj3, MIDInitKMF, @ArgsKMF3[0]);
      if Env2^.ExceptionCheck(Env2) = 1 then
      begin
        Env2^.ExceptionClear(Env2);
        raise ELPConnectError.Create('KMF.init eccezione');
      end;
      LPLog('PostForm: [2d] KMF init OK');

      var MIDGetKMs  : JNIMethodID := Env2^.GetMethodID(Env2, KMFClass3b,
        'getKeyManagers', '()[Ljavax/net/ssl/KeyManager;');
      var KMsArr3    : JNIObject   := Env2^.CallObjectMethod(Env2, KMFObj3, MIDGetKMs);
      if Env2^.ExceptionCheck(Env2) = 1 then
      begin
        Env2^.ExceptionClear(Env2);
        raise ELPConnectError.Create('getKeyManagers eccezione');
      end;
      LPLog('PostForm: [2e] KMs OK');

      // ── SSLContext ────────────────────────────────────────────
      SslCtx   := TJSSLContext.JavaClass.getInstance(StringToJString('TLS'));
      SslObj   := (SslCtx as ILocalObject).GetObjectID;
      SslClass := Env2^.GetObjectClass(Env2, SslObj);
      MIDSsl   := Env2^.GetMethodID(Env2, SslClass, 'init',
        '([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V');
      if MIDSsl = nil then
        raise ELPConnectError.Create('SSLContext init MID non trovato');

      TrustMgr   := TTrustAllManager.Create;
      TrustObj   := (TrustMgr as ILocalObject).GetObjectID;
      TrustClass := Env2^.FindClass(Env2, 'javax/net/ssl/TrustManager');
      TrustArr   := Env2^.NewObjectArray(Env2, 1, TrustClass, nil);
      Env2^.SetObjectArrayElement(Env2, TrustArr, 0, TrustObj);

      ArgsSsl[0].l := KMsArr3;
      ArgsSsl[1].l := TrustArr;
      ArgsSsl[2].l := nil;
      Env2^.CallVoidMethodA(Env2, SslObj, MIDSsl, @ArgsSsl[0]);
      if Env2^.ExceptionCheck(Env2) = 1 then
      begin
        Env2^.ExceptionClear(Env2);
        raise ELPConnectError.Create('SSLContext.init eccezione');
      end;
      LPLog('PostForm: [2f] SSLContext OK');

    except on E: Exception do
      raise ELPConnectError.Create('PostForm: SSL setup fallito: ' + E.Message);
    end;
    LPLog('PostForm: [2] SSL setup OK');

    // ── URL + HttpsURLConnection ───────────────────────────────
    LPLog('PostForm: [3] openConnection...');
    try
      URL_  := TJURL.JavaClass.init(StringToJString(FBaseURL + APath));
      Conn  := TJHttpsURLConnection.Wrap(
                 (URL_.openConnection as ILocalObject).GetObjectID);
    except on E: Exception do
      raise ELPConnectError.Create('PostForm: openConnection fallito: ' + E.Message);
    end;
    LPLog('PostForm: [3] openConnection OK');

    // ── Headers ────────────────────────────────────────────────
    LPLog('PostForm: [4] headers...');
    Conn.setSSLSocketFactory(SslCtx.getSocketFactory);
    Conn.setHostnameVerifier(TTrustAllHostnames.Create);
    Conn.setRequestMethod(StringToJString('POST'));
    Conn.setDoOutput(ABody <> '');
    Conn.setConnectTimeout(30000);
    Conn.setReadTimeout(30000);
    Conn.setRequestProperty(
      StringToJString('Connection'),
      StringToJString('close'));
    Conn.setRequestProperty(
      StringToJString('Content-Type'),
      StringToJString('application/x-www-form-urlencoded; charset=UTF-8'));
    for I := 0 to AHeaders.Count - 1 do
    begin
      ColonIdx := Pos(': ', AHeaders[I]);
      if ColonIdx > 0 then
        Conn.setRequestProperty(
          StringToJString(Copy(AHeaders[I], 1, ColonIdx - 1)),
          StringToJString(Copy(AHeaders[I], ColonIdx + 2, MaxInt)));
    end;
    LPLog('PostForm: [4] headers OK (' + IntToStr(AHeaders.Count) + ')');

    // ── Body ───────────────────────────────────────────────────
    if ABody <> '' then
    begin
      LPLog('PostForm: [5] send body...');
      try
        BodyBytes := TEncoding.UTF8.GetBytes(ABody);
        BodyArr   := TJavaArray<Byte>.Create(Length(BodyBytes));
        try
          for I := 0 to Length(BodyBytes) - 1 do
            BodyArr[I] := ShortInt(BodyBytes[I]);
          OS := Conn.getOutputStream;
          OS.write(BodyArr);
          // flush
          var OSObj   : JNIObject   := (OS as ILocalObject).GetObjectID;
          var OSClass : JNIClass    := Env2^.GetObjectClass(Env2, OSObj);
          var MIDFlush: JNIMethodID := Env2^.GetMethodID(Env2, OSClass, 'flush', '()V');
          if MIDFlush <> nil then
            Env2^.CallVoidMethod(Env2, OSObj, MIDFlush);
          // close
          var MIDClose: JNIMethodID := Env2^.GetMethodID(Env2, OSClass, 'close', '()V');
          if MIDClose <> nil then
            Env2^.CallVoidMethod(Env2, OSObj, MIDClose);
        finally
          BodyArr.Free;
        end;
      except on E: Exception do
        raise ELPConnectError.Create('PostForm: send body fallito: ' + E.Message);
      end;
      LPLog('PostForm: [5] body OK');
    end;

    // ── Risposta ───────────────────────────────────────────────
    LPLog('PostForm: [6] response...');
    try
      Env2 := TJNIResolver.GetJNIEnv;
      var ConnObj2  : JNIObject   := (Conn as ILocalObject).GetObjectID;
      var ConnClass : JNIClass    := Env2^.GetObjectClass(Env2, ConnObj2);
      var MIDCode   : JNIMethodID := Env2^.GetMethodID(Env2, ConnClass,
        'getResponseCode', '()I');
      if MIDCode = nil then
        raise ELPConnectError.Create('getResponseCode MID non trovato');
      var RespCode : Integer := Env2^.CallIntMethod(Env2, ConnObj2, MIDCode);
      LPLog('PostForm: [6] HTTP code=' + IntToStr(RespCode));

      if Env2^.ExceptionCheck(Env2) = 1 then
      begin
        var ExcObj  : JNIObject := Env2^.ExceptionOccurred(Env2);
        Env2^.ExceptionClear(Env2);
        var ExcClass : JNIClass    := Env2^.GetObjectClass(Env2, ExcObj);
        var MIDMsg   : JNIMethodID := Env2^.GetMethodID(Env2, ExcClass,
          'getMessage', '()Ljava/lang/String;');
        var MsgObj   : JNIObject   := Env2^.CallObjectMethod(Env2, ExcObj, MIDMsg);
        var ExcMsg   : string      := JStringToString(TJString.Wrap(MsgObj));
        raise ELPConnectError.Create('getResponseCode eccezione: ' + ExcMsg);
      end;

      if RespCode >= 400 then
      begin
        var MIDErr : JNIMethodID := Env2^.GetMethodID(Env2, ConnClass,
          'getErrorStream', '()Ljava/io/InputStream;');
        IS_ := TJInputStream.Wrap(Env2^.CallObjectMethod(Env2, ConnObj2, MIDErr));
      end
      else
      begin
        var MIDIn : JNIMethodID := Env2^.GetMethodID(Env2, ConnClass,
          'getInputStream', '()Ljava/io/InputStream;');
        IS_ := TJInputStream.Wrap(Env2^.CallObjectMethod(Env2, ConnObj2, MIDIn));
      end;

      if IS_ = nil then
        raise ELPConnectError.Create('stream nil, code=' + IntToStr(RespCode));

      BufArr     := TJavaArray<Byte>.Create(8192);
      RespStream := TBytesStream.Create;
      try
        repeat
          N := IS_.read(BufArr, 0, 8192);
          if N > 0 then
          begin
            SetLength(BodyBytes, N);
            for I := 0 to N - 1 do BodyBytes[I] := Byte(BufArr[I]);
            RespStream.WriteBuffer(BodyBytes[0], N);
          end;
        until N <= 0;
        Result := TEncoding.UTF8.GetString(RespStream.Bytes, 0, RespStream.Size);
      finally
        BufArr.Free;
        RespStream.Free;
      end;
    except on E: Exception do
      raise ELPConnectError.Create('PostForm: response fallito: ' + E.Message);
    end;
    LPLog('PostForm: [6] risposta len=' + IntToStr(Length(Result)));
    LPLog('PostForm: risposta=' + Copy(Result, 1, 200));

  finally
    PassChars.Free;
    PfxArr.Free;
  end;
end;

procedure TLPConnect.LoadAccountCertFromP12;
var
  Env       : PJNIEnv;
  P12Bytes  : TBytes;
  Password  : string;
  PassChars : TJavaArray<Char>;
  PfxArr    : TJavaArray<Byte>;
  I         : Integer;
  ArgsBIS3  : array[0..0] of TJNIValue;
  ArgsLoad3 : array[0..1] of TJNIValue;
  PassLen3  : Integer;
  PassArr3  : JNIObject;
  PassPtr3  : Pointer;
  PfxJArr   : JNIObject;
  PfxPtr    : Pointer;
  BISClass  : JNIClass;
  MIDNewBIS : JNIMethodID;
  BISObj    : JNIObject;
  KSClass3  : JNIClass;
  MIDGetKS3 : JNIMethodID;
  PKCS12Str : JNIObject;
  KSObj4    : JNIObject;
  MIDLoad3  : JNIMethodID;
  KSClass3b : JNIClass;
  ArgsGetKS3: array[0..0] of TJNIValue;
begin
  if FAccP12Base64 = '' then
    raise ELPAuthError.Create('base64Cert non disponibile');

  P12Bytes := TNetEncoding.Base64.DecodeStringToBytes(FAccP12Base64);
  Password := DeriveP12Password(FUserID, FAccUid);
  PassChars := TJavaArray<Char>.Create(Length(Password));
  try
    for I := 0 to Length(Password) - 1 do PassChars[I] := Password[I + 1];

    Env := TJNIResolver.GetJNIEnv;

    // BIS dal P12
    BISClass  := Env^.FindClass(Env, 'java/io/ByteArrayInputStream');
    MIDNewBIS := Env^.GetMethodID(Env, BISClass, '<init>', '([B)V');
    PfxJArr   := Env^.NewByteArray(Env, Length(P12Bytes));
    PfxPtr    := Env^.GetByteArrayElements(Env, PfxJArr, nil);
    Move(P12Bytes[0], PfxPtr^, Length(P12Bytes));
    Env^.ReleaseByteArrayElements(Env, PfxJArr, PfxPtr, 0);
    ArgsBIS3[0].l := PfxJArr;
    BISObj    := Env^.NewObjectA(Env, BISClass, MIDNewBIS, @ArgsBIS3[0]);

    // Password char[]
    PassLen3 := PassChars.Length;
    PassArr3 := Env^.NewCharArray(Env, PassLen3);
    PassPtr3 := Env^.GetCharArrayElements(Env, PassArr3, nil);
    for I := 0 to PassLen3 - 1 do
      PWideChar(PByte(PassPtr3) + I * 2)^ := PassChars[I];
    Env^.ReleaseCharArrayElements(Env, PassArr3, PassPtr3, 0);

    // KeyStore.getInstance('PKCS12')
    KSClass3  := Env^.FindClass(Env, 'java/security/KeyStore');
    MIDGetKS3 := Env^.GetStaticMethodID(Env, KSClass3, 'getInstance',
      '(Ljava/lang/String;)Ljava/security/KeyStore;');
    PKCS12Str := (StringToJString('PKCS12') as ILocalObject).GetObjectID;
    ArgsGetKS3[0].l := PKCS12Str;
    KSObj4    := Env^.CallStaticObjectMethodA(Env, KSClass3, MIDGetKS3, @ArgsGetKS3[0]);

    // KeyStore.load
    KSClass3b := Env^.GetObjectClass(Env, KSObj4);
    MIDLoad3  := Env^.GetMethodID(Env, KSClass3b, 'load',
      '(Ljava/io/InputStream;[C)V');
    ArgsLoad3[0].l := BISObj;
    ArgsLoad3[1].l := PassArr3;
    Env^.CallVoidMethodA(Env, KSObj4, MIDLoad3, @ArgsLoad3[0]);

    if Env^.ExceptionCheck(Env) = 1 then
    begin
      Env^.ExceptionClear(Env);
      raise ELPAuthError.Create('LoadAccountCertFromP12: KS.load fallito');
    end;

    // Salva il KeyStore per uso futuro in PostForm
    FAndroidAccKSObj := Pointer(Env^.NewGlobalRef(Env, KSObj4));
    FAndroidAccPass  := Password;

  finally
    PassChars.Free;
  end;
end;

destructor TLPConnect.Destroy;
begin
  if FAndroidAccKSObj <> nil then
  begin
    var Env := TJNIResolver.GetJNIEnv;
    Env^.DeleteGlobalRef(Env, JNIObject(FAndroidAccKSObj));
    FAndroidAccKSObj := nil;
  end;
  inherited;
end;

end.
