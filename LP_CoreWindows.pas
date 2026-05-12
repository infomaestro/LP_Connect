unit LP_CoreWindows;

{
  LP_CoreWindows.pas
  Implementazione Windows di TLPConnectBase.
  HTTP+mTLS : WinHTTP + crypt32 (dinamici)
  PEM→PFX   : libcrypto-1_1.dll / libcrypto-3.dll (via LP_CoreBase)
}

interface

uses
  LP_CoreBase,
  System.SysUtils,
  System.Classes,
  Winapi.Windows;

type
  TLPConnect = class(TLPConnectBase)
  protected
    function  LibLoad(const AName: string): Pointer; override;
    function  LibSym(ALib: Pointer; const AName: string): Pointer; override;
    procedure LibFree(ALib: Pointer); override;
    function  PostForm(const APath    : string;
                       const AHeaders : TStrings;
                       const ABody    : string): string; override;
  end;

implementation

uses
  System.NetEncoding;

type
  TCertContext = record
    dwCertEncodingType : DWORD;
    pbCertEncoded      : PByte;
    cbCertEncoded      : DWORD;
    pCertInfo          : Pointer;
    hCertStore         : Pointer;
  end;
  PCertContext = ^TCertContext;

  TCryptDataBlob = record
    cbData : DWORD;
    pbData : PByte;
  end;
  PCryptDataBlob = ^TCryptDataBlob;

  TfWinHttpOpen              = function(pwszAgent: PWideChar; dwAccessType: DWORD;
                                         pwszProxy, pwszProxyBypass: PWideChar;
                                         dwFlags: DWORD): Pointer; stdcall;
  TfWinHttpConnect           = function(hSession: Pointer; pswzServerName: PWideChar;
                                         nServerPort: Word; dwReserved: DWORD): Pointer; stdcall;
  TfWinHttpOpenRequest       = function(hConnect: Pointer;
                                         pwszVerb, pwszObjectName,
                                         pwszVersion, pwszReferrer: PWideChar;
                                         ppwszAcceptTypes: Pointer;
                                         dwFlags: DWORD): Pointer; stdcall;
  TfWinHttpSetOption         = function(hInternet: Pointer; dwOption: DWORD;
                                         lpBuffer: Pointer; dwBufferLength: DWORD): BOOL; stdcall;
  TfWinHttpAddRequestHeaders = function(hRequest: Pointer; pwszHeaders: PWideChar;
                                         dwHeadersLength, dwModifiers: DWORD): BOOL; stdcall;
  TfWinHttpSendRequest       = function(hRequest: Pointer; pwszHeaders: PWideChar;
                                         dwHeadersLength: DWORD; lpOptional: Pointer;
                                         dwOptionalLength, dwTotalLength,
                                         dwContext: DWORD): BOOL; stdcall;
  TfWinHttpReceiveResponse   = function(hRequest: Pointer; lpReserved: Pointer): BOOL; stdcall;
  TfWinHttpReadData          = function(hRequest: Pointer; lpBuffer: Pointer;
                                         dwNumberOfBytesToRead: DWORD;
                                         var lpdwNumberOfBytesRead: DWORD): BOOL; stdcall;
  TfWinHttpCloseHandle       = function(hInternet: Pointer): BOOL; stdcall;

  TfPFXImportCertStore               = function(pPFX: PCryptDataBlob;
                                                  szPassword: PWideChar;
                                                  dwFlags: DWORD): Pointer; stdcall;
  TfCertFindCertificateInStore       = function(hCertStore: Pointer;
                                                  dwCertEncodingType, dwFindFlags,
                                                  dwFindType: DWORD;
                                                  pvFindPara: Pointer;
                                                  pPrevCertContext: PCertContext): PCertContext; stdcall;
  TfCertFreeCertificateContext       = function(pCertContext: PCertContext): BOOL; stdcall;
  TfCertCloseStore                   = function(hCertStore: Pointer;
                                                  dwFlags: DWORD): BOOL; stdcall;
  TfCertOpenStore                    = function(lpszStoreProvider: PAnsiChar;
                                                  dwEncodingType, hCryptProv,
                                                  dwFlags: DWORD;
                                                  pvPara: Pointer): Pointer; stdcall;
  TfCertAddCertificateContextToStore = function(hCertStore: Pointer;
                                                  pCertContext: PCertContext;
                                                  dwAddDisposition: DWORD;
                                                  ppStoreContext: Pointer): BOOL; stdcall;
  TfCertDeleteCertificateFromStore   = function(pCertContext: PCertContext): BOOL; stdcall;

{ TLPConnect }

function TLPConnect.LibLoad(const AName: string): Pointer;
begin
  Result := Pointer(LoadLibraryW(PWideChar(AName)));
end;

function TLPConnect.LibSym(ALib: Pointer; const AName: string): Pointer;
begin
  Result := GetProcAddress(HMODULE(ALib), PChar(AName));
end;

procedure TLPConnect.LibFree(ALib: Pointer);
begin
  FreeLibrary(HMODULE(ALib));
end;

function TLPConnect.PostForm(const APath    : string;
                              const AHeaders : TStrings;
                              const ABody    : string): string;
const
  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY      = 0;
  WINHTTP_FLAG_SECURE                    = $00800000;
  WINHTTP_OPTION_SECURITY_FLAGS          = 31;
  WINHTTP_OPTION_CLIENT_CERT_CONTEXT     = 47;
  WINHTTP_ADDREQ_FLAG_ADD                = $20000000;
  SECURITY_FLAG_IGNORE_UNKNOWN_CA        = $00000100;
  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = $00002000;
  SECURITY_FLAG_IGNORE_CERT_CN_INVALID   = $00001000;
  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  = $00000200;
  CRYPT_EXPORTABLE                       = $00000001;
  CRYPT_USER_KEYSET                      = $00001000;
  X509_ASN_ENCODING                      = $00000001;
  PKCS_7_ASN_ENCODING                    = $00010000;
  CERT_FIND_ANY                          = 0;
  CERT_SYSTEM_STORE_CURRENT_USER         = $00010000;
  CERT_STORE_ADD_REPLACE_EXISTING        = 3;
  CERT_STORE_PROV_SYSTEM                 = 10;
  ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED  = 12044;
  PFX_PASSWORD : AnsiString              = 'lp_tmp_pfx_pwd';
var
  hWinHTTP, hCrypt32 : Pointer;
  fWinHttpOpen              : TfWinHttpOpen;
  fWinHttpConnect           : TfWinHttpConnect;
  fWinHttpOpenRequest       : TfWinHttpOpenRequest;
  fWinHttpSetOption         : TfWinHttpSetOption;
  fWinHttpAddRequestHeaders : TfWinHttpAddRequestHeaders;
  fWinHttpSendRequest       : TfWinHttpSendRequest;
  fWinHttpReceiveResponse   : TfWinHttpReceiveResponse;
  fWinHttpReadData          : TfWinHttpReadData;
  fWinHttpCloseHandle       : TfWinHttpCloseHandle;
  fPFXImportCertStore               : TfPFXImportCertStore;
  fCertFindCertificateInStore       : TfCertFindCertificateInStore;
  fCertFreeCertificateContext       : TfCertFreeCertificateContext;
  fCertCloseStore                   : TfCertCloseStore;
  fCertOpenStore                    : TfCertOpenStore;
  fCertAddCertificateContextToStore : TfCertAddCertificateContextToStore;
  fCertDeleteCertificateFromStore   : TfCertDeleteCertificateFromStore;

  hSession, hConnect, hRequest : Pointer;
  hCertStore, hMyStore         : Pointer;
  pCertCtx, pImported          : PCertContext;
  PfxBytes   : TBytes;
  PfxBlob    : TCryptDataBlob;
  PfxPwd     : WideString;
  dwSecFlags : DWORD;
  BodyBytes  : TBytes;
  I          : Integer;
  dwRead     : DWORD;
  dwErr      : DWORD;
  ReadBuf    : array[0..8191] of Byte;
  RespStream : TBytesStream;

  procedure Load(hLib: Pointer; var FP; const N: string);
  begin
    Pointer(FP) := LibSym(hLib, N);
    if Pointer(FP) = nil then
      raise ELPConnectError.CreateFmt('PostForm: funzione mancante: %s', [N]);
  end;

  procedure AddHeaders(hReq: Pointer);
  var J: Integer;
  begin
    fWinHttpAddRequestHeaders(hReq,
      'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
      DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD);
    for J := 0 to AHeaders.Count - 1 do
      if AHeaders[J] <> '' then
        fWinHttpAddRequestHeaders(hReq, PWideChar(AHeaders[J]),
          DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD);
  end;

  function SendBody(hReq: Pointer): Boolean;
  begin
    if Length(BodyBytes) > 0 then
      Result := fWinHttpSendRequest(hReq, nil, 0,
                  @BodyBytes[0], Length(BodyBytes), Length(BodyBytes), 0)
    else
      Result := fWinHttpSendRequest(hReq, nil, 0, nil, 0, 0, 0);
  end;

begin
  hWinHTTP := LibLoad('winhttp.dll');
  if hWinHTTP = nil then raise ELPConnectError.Create('winhttp.dll non trovata');
  hCrypt32  := LibLoad('crypt32.dll');
  if hCrypt32 = nil then begin LibFree(hWinHTTP); raise ELPConnectError.Create('crypt32.dll non trovata'); end;

  hSession := nil; hConnect  := nil; hRequest  := nil;
  hCertStore := nil; hMyStore := nil;
  pCertCtx := nil; pImported := nil;
  RespStream := nil;
  try
    Load(hWinHTTP, fWinHttpOpen,              'WinHttpOpen');
    Load(hWinHTTP, fWinHttpConnect,           'WinHttpConnect');
    Load(hWinHTTP, fWinHttpOpenRequest,       'WinHttpOpenRequest');
    Load(hWinHTTP, fWinHttpSetOption,         'WinHttpSetOption');
    Load(hWinHTTP, fWinHttpAddRequestHeaders, 'WinHttpAddRequestHeaders');
    Load(hWinHTTP, fWinHttpSendRequest,       'WinHttpSendRequest');
    Load(hWinHTTP, fWinHttpReceiveResponse,   'WinHttpReceiveResponse');
    Load(hWinHTTP, fWinHttpReadData,          'WinHttpReadData');
    Load(hWinHTTP, fWinHttpCloseHandle,       'WinHttpCloseHandle');
    Load(hCrypt32, fPFXImportCertStore,               'PFXImportCertStore');
    Load(hCrypt32, fCertFindCertificateInStore,        'CertFindCertificateInStore');
    Load(hCrypt32, fCertFreeCertificateContext,        'CertFreeCertificateContext');
    Load(hCrypt32, fCertCloseStore,                    'CertCloseStore');
    Load(hCrypt32, fCertOpenStore,                     'CertOpenStore');
    Load(hCrypt32, fCertAddCertificateContextToStore,  'CertAddCertificateContextToStore');
    Load(hCrypt32, fCertDeleteCertificateFromStore,    'CertDeleteCertificateFromStore');

    PfxBytes := PEMtoPFX(FCurrentCertFile, FCurrentKeyFile, PFX_PASSWORD);
    PfxPwd   := WideString(PFX_PASSWORD);
    PfxBlob.cbData := Length(PfxBytes);
    PfxBlob.pbData := @PfxBytes[0];

    hCertStore := fPFXImportCertStore(@PfxBlob, PWideChar(PfxPwd),
                    CRYPT_EXPORTABLE or CRYPT_USER_KEYSET);
    if hCertStore = nil then
      raise ELPConnectError.CreateFmt('PFXImportCertStore fallito (%d)', [GetLastError]);

    pCertCtx := fCertFindCertificateInStore(hCertStore,
      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nil, nil);
    if pCertCtx = nil then
      raise ELPConnectError.CreateFmt('CertFindCertificateInStore fallito (%d)', [GetLastError]);

    hMyStore := fCertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), 0, 0,
                  CERT_SYSTEM_STORE_CURRENT_USER, PWideChar('MY'));
    if hMyStore = nil then
      raise ELPConnectError.CreateFmt('CertOpenStore MY fallito (%d)', [GetLastError]);

    pImported := nil;
    fCertAddCertificateContextToStore(hMyStore, pCertCtx,
      CERT_STORE_ADD_REPLACE_EXISTING, @pImported);
    if pImported = nil then
      raise ELPConnectError.CreateFmt('CertAdd fallito (%d)', [GetLastError]);

    hSession := fWinHttpOpen('LeapConnect/1.0',
                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0);
    if hSession = nil then
      raise ELPConnectError.CreateFmt('WinHttpOpen fallito (%d)', [GetLastError]);

    hConnect := fWinHttpConnect(hSession, LP_SERVER_HOST, 443, 0);
    if hConnect = nil then
      raise ELPConnectError.CreateFmt('WinHttpConnect fallito (%d)', [GetLastError]);

    hRequest := fWinHttpOpenRequest(hConnect, 'POST',
                  PWideChar(APath), nil, nil, nil, WINHTTP_FLAG_SECURE);
    if hRequest = nil then
      raise ELPConnectError.CreateFmt('WinHttpOpenRequest fallito (%d)', [GetLastError]);

    dwSecFlags := SECURITY_FLAG_IGNORE_UNKNOWN_CA
               or SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
               or SECURITY_FLAG_IGNORE_CERT_CN_INVALID
               or SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    fWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                       @dwSecFlags, SizeOf(dwSecFlags));

    AddHeaders(hRequest);
    BodyBytes := TEncoding.UTF8.GetBytes(ABody);

    if not SendBody(hRequest) then
    begin
      dwErr := GetLastError;
      if dwErr = ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED then
      begin
        fWinHttpCloseHandle(hRequest);
        hRequest := nil;
        hRequest := fWinHttpOpenRequest(hConnect, 'POST',
                      PWideChar(APath), nil, nil, nil, WINHTTP_FLAG_SECURE);
        if hRequest = nil then
          raise ELPConnectError.CreateFmt('WinHttpOpenRequest (retry) fallito (%d)', [GetLastError]);
        fWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                           @dwSecFlags, SizeOf(dwSecFlags));
        if not fWinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                                  pImported, SizeOf(TCertContext)) then
          raise ELPConnectError.CreateFmt('WinHttpSetOption CERT fallito (%d)', [GetLastError]);
        AddHeaders(hRequest);
        if not SendBody(hRequest) then
          raise ELPConnectError.CreateFmt('WinHttpSendRequest (retry) fallito (%d)', [GetLastError]);
      end
      else
        raise ELPConnectError.CreateFmt('WinHttpSendRequest fallito (%d)', [dwErr]);
    end;

    if not fWinHttpReceiveResponse(hRequest, nil) then
      raise ELPConnectError.CreateFmt('WinHttpReceiveResponse fallito (%d)', [GetLastError]);

    RespStream := TBytesStream.Create;
    try
      repeat
        dwRead := 0;
        if not fWinHttpReadData(hRequest, @ReadBuf[0], SizeOf(ReadBuf), dwRead) then
          raise ELPConnectError.CreateFmt('WinHttpReadData fallito (%d)', [GetLastError]);
        if dwRead > 0 then RespStream.WriteBuffer(ReadBuf[0], dwRead);
      until dwRead = 0;
      Result := TEncoding.UTF8.GetString(RespStream.Bytes, 0, RespStream.Size);
    finally
      RespStream.Free;
    end;

  finally
    if pImported  <> nil then fCertDeleteCertificateFromStore(pImported);
    if hMyStore   <> nil then fCertCloseStore(hMyStore, 0);
    if pCertCtx   <> nil then fCertFreeCertificateContext(pCertCtx);
    if hCertStore <> nil then fCertCloseStore(hCertStore, 0);
    if hRequest   <> nil then fWinHttpCloseHandle(hRequest);
    if hConnect   <> nil then fWinHttpCloseHandle(hConnect);
    if hSession   <> nil then fWinHttpCloseHandle(hSession);
    LibFree(hCrypt32);
    LibFree(hWinHTTP);
  end;
end;

end.
