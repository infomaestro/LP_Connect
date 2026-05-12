unit LP_WinHTTP;

interface

uses
  System.SysUtils, System.Classes, Winapi.Windows;

function WinHTTPPost(const AURL, ABody: string;
                     const AHeaders: TStringList;
                     const ACertFile, AKeyFile: string): string;

implementation

uses
  System.NetEncoding;

const
  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY    = 0;
  WINHTTP_FLAG_SECURE                  = $00800000;
  WINHTTP_FLAG_BYPASS_PROXY_CACHE      = $00000100;
  SECURITY_FLAG_IGNORE_UNKNOWN_CA      = $00000100;
  SECURITY_FLAG_IGNORE_CERT_CN_INVALID = $00001000;
  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = $00002000;
  WINHTTP_OPTION_SECURITY_FLAGS        = 31;
  WINHTTP_OPTION_CLIENT_CERT_CONTEXT   = 47;
  WINHTTP_ENABLE_SSL_REVOCATION        = $00000001;

type
  HINTERNET = THandle;

function WinHttpOpen(pszAgentW: PWideChar; dwAccessType: DWORD;
  pszProxyW, pszProxyBypassW: PWideChar; dwFlags: DWORD): HINTERNET;
  stdcall; external 'winhttp.dll';
function WinHttpConnect(hSession: HINTERNET; pswzServerName: PWideChar;
  nServerPort: Word; dwReserved: DWORD): HINTERNET;
  stdcall; external 'winhttp.dll';
function WinHttpOpenRequest(hConnect: HINTERNET; pwszVerb: PWideChar;
  pwszObjectName: PWideChar; pwszVersion: PWideChar;
  pwszReferrer: PWideChar; ppwszAcceptTypes: Pointer;
  dwFlags: DWORD): HINTERNET; stdcall; external 'winhttp.dll';
function WinHttpSendRequest(hRequest: HINTERNET;
  pwszHeaders: PWideChar; dwHeadersLength: DWORD;
  lpOptional: Pointer; dwOptionalLength: DWORD;
  dwTotalLength: DWORD; dwContext: DWORD_PTR): BOOL;
  stdcall; external 'winhttp.dll';
function WinHttpReceiveResponse(hRequest: HINTERNET;
  lpReserved: Pointer): BOOL; stdcall; external 'winhttp.dll';
function WinHttpReadData(hRequest: HINTERNET; lpBuffer: Pointer;
  dwNumberOfBytesToRead: DWORD; var lpdwNumberOfBytesRead: DWORD): BOOL;
  stdcall; external 'winhttp.dll';
function WinHttpCloseHandle(hInternet: HINTERNET): BOOL;
  stdcall; external 'winhttp.dll';
function WinHttpSetOption(hInternet: HINTERNET; dwOption: DWORD;
  lpBuffer: Pointer; dwBufferLength: DWORD): BOOL;
  stdcall; external 'winhttp.dll';
function WinHttpAddRequestHeaders(hRequest: HINTERNET;
  pwszHeaders: PWideChar; dwHeadersLength: DWORD;
  dwModifiers: DWORD): BOOL; stdcall; external 'winhttp.dll';

function WinHTTPPost(const AURL, ABody: string;
                     const AHeaders: TStringList;
                     const ACertFile, AKeyFile: string): string;
var
  hSession, hConnect, hRequest: HINTERNET;
  URI                          : string;
  Host, Path                   : string;
  HeaderStr                    : string;
  BodyBytes                    : TBytes;
  Buffer                       : array[0..4095] of AnsiChar;
  BytesRead                    : DWORD;
  ResponseBytes                : TBytesStream;
  SecurityFlags                : DWORD;
  I                            : Integer;
begin
  Result := '';

  // Parse URL
  URI  := AURL;
  Host := URI;
  Path := '/';
  if URI.StartsWith('https://') then
    Delete(URI, 1, 8);
  I := Pos('/', URI);
  if I > 0 then
  begin
    Host := Copy(URI, 1, I - 1);
    Path := Copy(URI, I, MaxInt);
  end
  else
    Host := URI;

  hSession := WinHttpOpen('LPConnect/1.0',
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0);
  if hSession = 0 then
    raise Exception.Create('WinHttpOpen failed: ' + IntToStr(GetLastError));
  try
    hConnect := WinHttpConnect(hSession, PWideChar(WideString(Host)), 443, 0);
    if hConnect = 0 then
      raise Exception.Create('WinHttpConnect failed: ' + IntToStr(GetLastError));
    try
      hRequest := WinHttpOpenRequest(hConnect, 'POST',
        PWideChar(WideString(Path)), nil, nil, nil, WINHTTP_FLAG_SECURE);
      if hRequest = 0 then
        raise Exception.Create('WinHttpOpenRequest failed');
      try
        // Ignora errori certificato server (self-signed)
        SecurityFlags :=
          SECURITY_FLAG_IGNORE_UNKNOWN_CA or
          SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
          @SecurityFlags, SizeOf(SecurityFlags));

        // Headers
        HeaderStr := '';
        if Assigned(AHeaders) then
          for I := 0 to AHeaders.Count - 1 do
            HeaderStr := HeaderStr + AHeaders[I] + #13#10;

        if HeaderStr <> '' then
          WinHttpAddRequestHeaders(hRequest,
            PWideChar(WideString(HeaderStr)),
            DWORD(-1), $20000000);

        // Body
        BodyBytes := TEncoding.UTF8.GetBytes(ABody);

        if not WinHttpSendRequest(hRequest, nil, 0,
          Pointer(BodyBytes), Length(BodyBytes),
          Length(BodyBytes), 0) then
          raise Exception.Create('WinHttpSendRequest failed: ' +
            IntToStr(GetLastError));

        if not WinHttpReceiveResponse(hRequest, nil) then
          raise Exception.Create('WinHttpReceiveResponse failed');

        // Leggi risposta
        ResponseBytes := TBytesStream.Create;
        try
          repeat
            BytesRead := 0;
            if WinHttpReadData(hRequest, @Buffer[0],
              SizeOf(Buffer), BytesRead) then
            begin
              if BytesRead > 0 then
                ResponseBytes.Write(Buffer[0], BytesRead);
            end;
          until BytesRead = 0;
          Result := TEncoding.UTF8.GetString(ResponseBytes.Bytes, 0,
            ResponseBytes.Size);
        finally
          ResponseBytes.Free;
        end;
      finally
        WinHttpCloseHandle(hRequest);
      end;
    finally
      WinHttpCloseHandle(hConnect);
    end;
  finally
    WinHttpCloseHandle(hSession);
  end;
end;

end.
